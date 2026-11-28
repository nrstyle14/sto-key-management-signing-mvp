//go:build integration

// 통합 테스트: Fabric 원문 서명(설계서 10.5, D-26)의 1~9단계와 거부 사례. MySQL(signer 스키마)과 시험용 P-256 서명기를 쓴다.
// 실제 HSM·peer 경로는 test/fabric_e2e_test.go(make it-fabric)가 확인한다.
package signsvc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/policy"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

// p256Signer 는 시험용 P-256 서명기다(HSM 처럼 정규화하지 않은 r, s 를 돌려준다).
type p256Signer struct{ keys map[string]*ecdsa.PrivateKey }

func (p *p256Signer) Generate(context.Context, signer.KeySpec) (signer.PublicKey, error) {
	return nil, errors.New("시험용")
}
func (p *p256Signer) Destroy(context.Context, string) error { return errors.New("시험용") }
func (p *p256Signer) SignDigest(_ context.Context, keyID string, d [32]byte) (*big.Int, *big.Int, error) {
	k, ok := p.keys[keyID]
	if !ok {
		return nil, nil, errors.New("키 없음")
	}
	return ecdsa.Sign(rand.Reader, k, d[:])
}

type fabFixture struct {
	*fixture
	fl      string // Fabric 원장 ID
	key     string
	certPEM []byte
	svc     *Service
}

func selfCert(t *testing.T, k *ecdsa.PrivateKey, cn string) []byte {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func setupFabric(t *testing.T) *fabFixture {
	t.Helper()
	f := setup(t)
	ctx := context.Background()
	ff := &fabFixture{fixture: f, fl: "it-fab-" + f.s, key: "it-fabkey-" + f.s}
	tok := ff.fl + "." + f.instA
	pol := "it-fabpol-" + f.s
	t.Cleanup(func() {
		_, _ = f.db.Exec("DELETE FROM signatures WHERE key_id = ?", ff.key)
		_, _ = f.db.Exec("DELETE FROM fabric_identities WHERE key_id = ?", ff.key)
		_, _ = f.db.Exec("DELETE FROM freezes WHERE target = ?", ff.key)
		_, _ = f.db.Exec("DELETE FROM policies WHERE policy_id = ?", pol)
		_, _ = f.db.Exec("DELETE FROM `keys` WHERE key_id = ?", ff.key)
		_, _ = f.db.Exec("DELETE FROM hsm_tokens WHERE token_id = ?", tok)
	})
	if err := keyreg.RegisterToken(ctx, f.db, keyreg.Token{TokenID: tok, Label: "it-fab-" + f.instA, LedgerID: ff.fl, InstitutionID: f.instA}); err != nil {
		t.Fatal(err)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := append([]byte{4}, append(k.PublicKey.X.FillBytes(make([]byte, 32)), k.PublicKey.Y.FillBytes(make([]byte, 32))...)...)
	if err := keyreg.RegisterKey(ctx, f.db, keyreg.Key{KeyID: ff.key, TokenID: tok, Purpose: signer.PurposeTransfer, PublicKey: pub, Curve: signer.CurveP256}); err != nil {
		t.Fatal(err)
	}
	ff.certPEM = selfCert(t, k, ff.key)
	if _, err := f.db.Exec(`INSERT INTO fabric_identities (key_id, msp_id, enrollment_id, cert_pem, serial, aki, not_after, status) VALUES (?, 'InstAMSP', ?, ?, ?, 'aa', ?, 'ENROLLED')`,
		ff.key, ff.key, string(ff.certPEM), "01"+f.s, time.Now().Add(time.Hour).UTC()); err != nil {
		t.Fatal(err)
	}
	body := policy.Body{AllowedFunctions: []string{"RegisterAccount"}, RequiredApprovals: 2, ApproverGroup: "it-grp-a-" + f.s, GasLimitCap: 1}
	b, _ := body.Canonical()
	if _, err := f.db.Exec(`INSERT INTO policies (policy_id, version, ledger_id, institution_id, key_purpose, body_json, status) VALUES (?, 1, ?, ?, 'TRANSFER', ?, 'ACTIVE')`,
		pol, ff.fl, f.instA, string(b)); err != nil {
		t.Fatal(err)
	}
	ff.svc = &Service{DB: f.db, Signer: &p256Signer{keys: map[string]*ecdsa.PrivateKey{ff.key: k}}, Callers: []string{"apid"},
		FabricMSP: func(l, i string) (string, bool) { return "InstAMSP", l == ff.fl && i == f.instA }}
	return ff
}

func (ff *fabFixture) fabIntent(t *testing.T, contract, fn string, args ...string) *intent.Intent {
	t.Helper()
	in := &intent.Intent{RequestID: ulid.Make().String(), Type: intent.TypeFabricTX, LedgerID: ff.fl, InstitutionID: ff.instA,
		KeyPurpose: signer.PurposeTransfer, Contract: contract, Function: fn, Args: args, DrafterID: ff.id("it-a1"),
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(intent.TimeLayout)}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	return in
}

func (ff *fabFixture) req(in *intent.Intent, kind string, payload []byte, approvals []approval.Approval) FabricRequest {
	b, _ := in.Canonical()
	h, _ := in.Hash()
	return FabricRequest{Intent: json.RawMessage(b), IntentHash: hex.EncodeToString(h[:]), Approvals: approvals, Kind: kind, Payload: payload}
}

// 정상: 제안 → 트랜잭션 → 커밋 서명(low-S DER, 공개키 검증), 같은 원문 재요청은 같은 서명, 감사 SIGN_FABRIC 3건.
func TestFabricSignFlow(t *testing.T) {
	ff := setupFabric(t)
	ctx := context.Background()
	in := ff.fabIntent(t, "sto-channel/sectoken", "RegisterAccount", "acct-1")
	pb := proposal(t, ff.certPEM, "RegisterAccount", []string{"acct-1"})
	r1, err := ff.svc.SignFabric(ctx, "apid", ff.req(in, KindProposal, pb, ff.ok(in)))
	if err != nil {
		t.Fatal(err)
	}
	again, err := ff.svc.SignFabric(ctx, "apid", ff.req(in, KindProposal, pb, ff.ok(in)))
	if err != nil || string(again.Signature) != string(r1.Signature) {
		t.Fatalf("같은 제안 재요청: %v", err)
	}
	tb := endorsed(t, pb, nil)
	r2, err := ff.svc.SignFabric(ctx, "apid", ff.req(in, KindTransaction, tb, ff.ok(in)))
	if err != nil {
		t.Fatal(err)
	}
	cr := commitBytes(t, pb)
	r3, err := ff.svc.SignFabric(ctx, "apid", ff.req(in, KindCommit, cr, ff.ok(in)))
	if err != nil {
		t.Fatal(err)
	}
	if r1.TxID == "" || r1.TxID != r2.TxID || r2.TxID != r3.TxID {
		t.Fatalf("txID %s %s %s", r1.TxID, r2.TxID, r3.TxID)
	}
	// 제안 서명은 SHA-256(ProposalBytes) 에 대한 low-S DER 이다
	pp, _, _, _, err := parseProposalBytes(proposalBytesOf(t, pb))
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(pp.propByte)
	k, _ := keyreg.Get(ctx, ff.db, ff.key)
	pub, _ := signer.P256Public(k.PublicKey)
	if !ecdsa.VerifyASN1(pub, d[:], r1.Signature) {
		t.Fatal("제안 서명이 공개키로 검증되지 않는다")
	}
	if n := ff.rows(t, in.RequestID); n != 3 {
		t.Fatalf("서명 기록 %d", n)
	}
	if n := ff.auditCount(t, "SIGN_FABRIC", in.RequestID); n != 3 {
		t.Fatalf("SIGN_FABRIC 감사 %d", n)
	}
}

func TestFabricSignRejections(t *testing.T) {
	ff := setupFabric(t)
	ctx := context.Background()
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherCert := selfCert(t, other, "someone")
	type tc struct {
		name, kind string
		build      func(in *intent.Intent) ([]byte, []approval.Approval)
		mut        func(in *intent.Intent) *intent.Intent
		caller     string
		pre        func(in *intent.Intent)
		step       int
		code       string
	}
	good := func(in *intent.Intent) ([]byte, []approval.Approval) {
		return proposal(t, ff.certPEM, in.Function, in.Args), ff.ok(in)
	}
	cases := []tc{
		{name: "업무 서버가 아닌 호출자", kind: KindProposal, build: good, caller: "stoctl", step: 1, code: CodeCallerNotAllowed},
		{name: "인자 바꿔치기", kind: KindProposal, build: func(in *intent.Intent) ([]byte, []approval.Approval) {
			return proposal(t, ff.certPEM, in.Function, []string{"acct-other"}), ff.ok(in)
		}, step: 7, code: CodeFabricMismatch},
		{name: "다른 체인코드", kind: KindProposal, build: good, mut: func(in *intent.Intent) *intent.Intent {
			return ff.fabIntent(t, "sto-channel/other", in.Function, in.Args...)
		}, step: 7, code: CodeFabricMismatch},
		{name: "생성자가 등록 신원과 다름", kind: KindProposal, build: func(in *intent.Intent) ([]byte, []approval.Approval) {
			return proposal(t, otherCert, in.Function, in.Args), ff.ok(in)
		}, step: 7, code: CodeFabricMismatch},
		{name: "제안 서명 전 트랜잭션", kind: KindTransaction, build: func(in *intent.Intent) ([]byte, []approval.Approval) {
			return endorsed(t, proposal(t, ff.certPEM, in.Function, in.Args), nil), ff.ok(in)
		}, step: 7, code: CodeFabricNoProposal},
		{name: "승인 1건", kind: KindProposal, build: func(in *intent.Intent) ([]byte, []approval.Approval) {
			return proposal(t, ff.certPEM, in.Function, in.Args), ff.ok(in)[:1]
		}, step: 6, code: policy.CodeApprovalInsufficient},
		{name: "동결된 키", kind: KindProposal, build: good, pre: func(*intent.Intent) {
			if _, err := ff.db.Exec(`INSERT INTO freezes (freeze_id, scope, target, reason, frozen_by) VALUES (?, 'KEY', ?, 'it', 'it')`, ulid.Make().String(), ff.key); err != nil {
				t.Fatal(err)
			}
		}, step: 4, code: CodeKeyFrozen},
		{name: "폐기된 신원", kind: KindProposal, build: good, pre: func(*intent.Intent) {
			_, _ = ff.db.Exec(`DELETE FROM freezes WHERE target = ?`, ff.key)
			if _, err := ff.db.Exec(`UPDATE fabric_identities SET status = 'REVOKED' WHERE key_id = ?`, ff.key); err != nil {
				t.Fatal(err)
			}
		}, step: 4, code: CodeFabricIdentity},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := ff.fabIntent(t, "sto-channel/sectoken", "RegisterAccount", "acct-"+c.name[:3])
			if c.mut != nil {
				in = c.mut(in)
			}
			if c.pre != nil {
				c.pre(in)
			}
			payload, apprs := c.build(in)
			caller := c.caller
			if caller == "" {
				caller = "apid"
			}
			_, err := ff.svc.SignFabric(ctx, caller, ff.req(in, c.kind, payload, apprs))
			wantReject(t, err, c.step, c.code)
			if n := ff.rows(t, in.RequestID); n != 0 {
				t.Fatalf("거부된 요청의 서명 기록 %d", n)
			}
			if n := ff.auditCount(t, "SIGN_REJECTED", in.RequestID); n != 1 {
				t.Fatalf("거부 감사 기록 %d", n)
			}
		})
	}
	_, _ = ff.db.Exec(`UPDATE fabric_identities SET status = 'ENROLLED' WHERE key_id = ?`, ff.key)

	// FABRIC_TX 가 아닌 intent
	evm := ff.issue(t, "10")
	b, _ := evm.Canonical()
	h, _ := evm.Hash()
	_, err := ff.svc.SignFabric(ctx, "apid", FabricRequest{Intent: b, IntentHash: hex.EncodeToString(h[:]), Approvals: ff.ok(evm), Kind: KindProposal, Payload: []byte("x")})
	wantReject(t, err, 3, CodeFabricNotFabricType)

	// 같은 요청의 다른 제안: 2단계 충돌
	in := ff.fabIntent(t, "sto-channel/sectoken", "RegisterAccount", "acct-dup")
	if _, err := ff.svc.SignFabric(ctx, "apid", ff.req(in, KindProposal, proposal(t, ff.certPEM, in.Function, in.Args), ff.ok(in))); err != nil {
		t.Fatal(err)
	}
	_, err = ff.svc.SignFabric(ctx, "apid", ff.req(in, KindProposal, proposal(t, ff.certPEM, in.Function, in.Args), ff.ok(in)))
	wantReject(t, err, 2, CodeRequestConflict)
}
