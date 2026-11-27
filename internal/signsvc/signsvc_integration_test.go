//go:build integration

// 통합 테스트: 서명 처리(설계서 5.3 의 1~9단계)와 request_id 1회 서명(D-6). T1.5, T2.4.
// 호스트에서 MySQL(make up && make migrate)에 signer_app 으로 접속한다.
// HSM 대신 go-ethereum 키를 쓰는 시험용 Signer 를 쓴다(HSM 서명 경로는 internal/signer/hsm 통합 테스트와
// test/ 의 종단 시험이 실제 SoftHSM2 로 확인한다). 만든 명부·정책·키 행은 시험이 끝나면 지운다.
// 설계서 16절의 서명 서버 거부 사례는 TestRejections 의 하위 시험 이름으로 하나씩 대응한다.
package signsvc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-sql-driver/mysql"
	"github.com/oklog/ulid/v2"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/evmtx"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/policy"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

const chainID = 20261124

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	pw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "deploy", "secrets", "signer_app_password"))
	if err != nil {
		t.Fatalf("비밀 파일(make up 필요): %v", err)
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr, cfg.DBName = "signer_app", strings.TrimSpace(string(pw)), "tcp", "127.0.0.1:3306", "signer"
	cfg.ParseTime = true
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("DB 접속(make up && make migrate 필요): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// fakeSigner 는 go-ethereum 키로 서명한다. 절반은 high-s 로 돌려줘 정규화 경로를 탄다.
type fakeSigner struct {
	keys  map[string]*ecdsa.PrivateKey
	calls atomic.Int32
	fail  atomic.Bool
}

func (f *fakeSigner) Generate(context.Context, signer.KeySpec) (signer.PublicKey, error) {
	return nil, errors.New("시험용")
}
func (f *fakeSigner) Destroy(context.Context, string) error { return errors.New("시험용") }
func (f *fakeSigner) SignDigest(_ context.Context, keyID string, d [32]byte) (*big.Int, *big.Int, error) {
	f.calls.Add(1)
	if f.fail.Load() {
		return nil, nil, errors.New("HSM 응답 없음(시험)")
	}
	k, ok := f.keys[keyID]
	if !ok {
		return nil, nil, fmt.Errorf("키 없음 %s", keyID)
	}
	sig, err := crypto.Sign(d[:], k)
	if err != nil {
		return nil, nil, err
	}
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64])
	if d[0]&1 == 1 {
		s = new(big.Int).Sub(crypto.S256().Params().N, s)
	}
	return r, s, nil
}

type fixture struct {
	db                   *sql.DB
	svc                  *Service
	fs                   *fakeSigner
	s                    string
	ledger, instA, instB string
	keyA, keyB           string
	addrA                common.Address
	appr                 map[string]ed25519.PrivateKey // 승인자 ID → 개인키
}

func rid() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var (
	contract    = common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")
	whitelisted = common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	stranger    = common.HexToAddress("0x00000000000000000000000000000000000000aA")
)

func setup(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	db := openDB(t)
	s := rid()
	f := &fixture{db: db, s: s, ledger: "it-ledger-" + s, instA: "it-a-" + s, instB: "it-b-" + s,
		keyA: "it-key-a-" + s, keyB: "it-key-b-" + s, fs: &fakeSigner{keys: map[string]*ecdsa.PrivateKey{}},
		appr: map[string]ed25519.PrivateKey{}}
	tokA, tokB := f.ledger+"."+f.instA, f.ledger+"."+f.instB
	polA, polB := "it-pol-a-"+s, "it-pol-b-"+s
	grpA, grpB := "it-grp-a-"+s, "it-grp-b-"+s
	ids := func(names ...string) []any {
		out := make([]any, len(names))
		for i, n := range names {
			out[i] = n + "-" + s
		}
		return out
	}
	apprIDs := ids("it-a1", "it-a2", "it-a3", "it-a4", "it-a5", "it-b1", "it-b2", "it-b3")
	t.Cleanup(func() {
		// 기동 점검에 걸리는 ACTIVE 키, 명부, 정책이 남지 않게 지운다. 감사 기록은 추가 전용이라 남는다.
		_, _ = db.Exec("DELETE FROM signatures WHERE key_id IN (?, ?)", f.keyA, f.keyB)
		_, _ = db.Exec("DELETE FROM freezes WHERE target IN (?, ?, ?)", f.keyA, f.instA, f.ledger)
		_, _ = db.Exec("DELETE FROM whitelists WHERE policy_id IN (?, ?)", polA, polB)
		_, _ = db.Exec("DELETE FROM policies WHERE policy_id IN (?, ?)", polA, polB)
		_, _ = db.Exec("DELETE FROM approver_groups WHERE group_id IN (?, ?)", grpA, grpB)
		_, _ = db.Exec("DELETE FROM approvers WHERE approver_id IN (?, ?, ?, ?, ?, ?, ?, ?)", apprIDs...)
		_, _ = db.Exec("DELETE FROM `keys` WHERE key_id IN (?, ?)", f.keyA, f.keyB)
		_, _ = db.Exec("DELETE FROM hsm_tokens WHERE token_id IN (?, ?)", tokA, tokB)
	})
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for tok, inst := range map[string]string{tokA: f.instA, tokB: f.instB} {
		must(keyreg.RegisterToken(ctx, db, keyreg.Token{TokenID: tok, Label: "it-" + inst, LedgerID: f.ledger, InstitutionID: inst}))
	}
	ka, _ := crypto.GenerateKey()
	kb, _ := crypto.GenerateKey()
	f.fs.keys[f.keyA], f.fs.keys[f.keyB] = ka, kb
	f.addrA = crypto.PubkeyToAddress(ka.PublicKey)
	must(keyreg.RegisterKey(ctx, db, keyreg.Key{KeyID: f.keyA, TokenID: tokA, Purpose: signer.PurposeIssue, PublicKey: crypto.FromECDSAPub(&ka.PublicKey)}))
	must(keyreg.RegisterKey(ctx, db, keyreg.Key{KeyID: f.keyB, TokenID: tokB, Purpose: signer.PurposeTransfer, PublicKey: crypto.FromECDSAPub(&kb.PublicKey)}))

	// 승인자: a1(기안자), a2, a3 은 기관 A 그룹, a4 는 기관 A 이지만 그룹 밖, a5 는 비활성, b1~b3 은 기관 B 그룹.
	type ap struct {
		id, inst, group, status string
	}
	for _, a := range []ap{
		{"it-a1", f.instA, grpA, "ACTIVE"}, {"it-a2", f.instA, grpA, "ACTIVE"}, {"it-a3", f.instA, grpA, "ACTIVE"},
		{"it-a4", f.instA, "", "ACTIVE"}, {"it-a5", f.instA, grpA, "DISABLED"},
		{"it-b1", f.instB, grpB, "ACTIVE"}, {"it-b2", f.instB, grpB, "ACTIVE"}, {"it-b3", f.instB, grpB, "ACTIVE"},
	} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		id := a.id + "-" + s
		f.appr[a.id] = priv
		_, err := db.Exec(`INSERT INTO approvers (approver_id, name, institution_id, role, ed25519_pubkey, status) VALUES (?, 'it', ?, 'APPROVER', ?, ?)`,
			id, a.inst, []byte(pub), a.status)
		must(err)
		if a.group != "" {
			_, err = db.Exec(`INSERT INTO approver_groups (group_id, approver_id) VALUES (?, ?)`, a.group, id)
			must(err)
		}
	}
	for _, p := range []struct {
		id, inst, purpose, group string
		fns                      []string
	}{
		{polA, f.instA, "ISSUE", grpA, []string{"issue(address,uint256)", "redeem(address,uint256)"}},
		{polB, f.instB, "TRANSFER", grpB, []string{"transferByAgent(address,address,uint256)"}},
	} {
		body := policy.Body{AllowedFunctions: p.fns, MaxAmount: "100000", RecipientWhitelist: true, RequiredApprovals: 2, ApproverGroup: p.group, GasLimitCap: 300000}
		b, _ := body.Canonical()
		_, err := db.Exec(`INSERT INTO policies (policy_id, version, ledger_id, institution_id, key_purpose, body_json, status) VALUES (?, 1, ?, ?, ?, ?, 'ACTIVE')`,
			p.id, f.ledger, p.inst, p.purpose, string(b))
		must(err)
		_, err = db.Exec(`INSERT INTO whitelists (policy_id, account_address) VALUES (?, ?)`, p.id, whitelisted.Hex())
		must(err)
	}
	f.svc = &Service{DB: db, Signer: f.fs, Chains: map[string]uint64{f.ledger: chainID}, MaxGas: 500000, Callers: []string{"apid"}}
	return f
}

func (f *fixture) id(short string) string { return short + "-" + f.s }

func (f *fixture) intent(t *testing.T, inst string, purpose signer.Purpose, fn string, args ...string) *intent.Intent {
	t.Helper()
	in := &intent.Intent{
		RequestID: ulid.Make().String(), Type: intent.TypeTX, LedgerID: f.ledger, InstitutionID: inst, KeyPurpose: purpose,
		Contract: contract.Hex(), Function: fn, Args: args, DrafterID: f.id("it-a1"),
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(intent.TimeLayout),
	}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	return in
}

func (f *fixture) issue(t *testing.T, amount string) *intent.Intent {
	return f.intent(t, f.instA, signer.PurposeIssue, "issue(address,uint256)", whitelisted.Hex(), amount)
}

func (f *fixture) approve(in *intent.Intent, d approval.Decision, short string) approval.Approval {
	h, _ := in.Hash()
	sig, _ := approval.Sign(f.appr[short], h, d)
	return approval.Approval{ApproverID: f.id(short), Decision: d, Signature: hex.EncodeToString(sig)}
}

func (f *fixture) ok(in *intent.Intent) []approval.Approval {
	return []approval.Approval{f.approve(in, approval.Approve, "it-a2"), f.approve(in, approval.Approve, "it-a3")}
}

func goodTx(t *testing.T, in *intent.Intent, nonce uint64) *types.Transaction {
	data, err := in.Calldata()
	if err != nil {
		t.Fatal(err)
	}
	return evmtx.NewUnsigned(big.NewInt(chainID), nonce, in.ContractAddress(), data, 100000)
}

func request(t *testing.T, in *intent.Intent, tx *types.Transaction, approvals []approval.Approval) Request {
	t.Helper()
	b, _ := in.Canonical()
	h, _ := in.Hash()
	raw, err := evmtx.EncodeUnsigned(tx)
	if err != nil {
		t.Fatal(err)
	}
	return Request{Intent: json.RawMessage(b), IntentHash: hex.EncodeToString(h[:]), Approvals: approvals, UnsignedTx: "0x" + hex.EncodeToString(raw)}
}

func wantReject(t *testing.T, err error, step int, code string) {
	t.Helper()
	var rj *Rejection
	if !errors.As(err, &rj) || rj.Step != step || rj.Code != code {
		t.Fatalf("거부 기대(단계 %d %s), 실제: %v", step, code, err)
	}
}

func (f *fixture) rows(t *testing.T, requestID string) int {
	var n int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM signatures WHERE request_id = ?", requestID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *fixture) auditCount(t *testing.T, action, requestID string) int {
	var n int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = ? AND subject = ?", action, requestID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSignAndReplay(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	in := f.issue(t, "1000")
	req := request(t, in, goodTx(t, in, 0), f.ok(in))
	res, err := f.svc.SignTx(ctx, "apid", req)
	if err != nil {
		t.Fatal(err)
	}
	signed := new(types.Transaction)
	if err := signed.UnmarshalBinary(common.FromHex(res.SignedTx)); err != nil {
		t.Fatal(err)
	}
	from, err := types.Sender(types.LatestSignerForChainID(big.NewInt(chainID)), signed)
	if err != nil || from != f.addrA || res.Address != f.addrA.Hex() || res.KeyID != f.keyA || signed.Hash().Hex() != res.TxHash {
		t.Fatalf("서명 결과 불일치: from=%s res=%+v err=%v", from, res, err)
	}
	again, err := f.svc.SignTx(ctx, "apid", req)
	if err != nil || *again != *res {
		t.Fatalf("재호출 결과가 다르다: %+v %v", again, err)
	}
	if f.fs.calls.Load() != 1 || f.rows(t, in.RequestID) != 1 || f.auditCount(t, "SIGN_TX", in.RequestID) != 1 {
		t.Fatalf("서명 호출 %d, 행 %d, 감사 %d (기대 1, 1, 1)", f.fs.calls.Load(), f.rows(t, in.RequestID), f.auditCount(t, "SIGN_TX", in.RequestID))
	}
}

// 같은 요청을 동시에 여러 번 보내도 서명은 한 번, 응답은 모두 같다.
func TestConcurrentSameRequestSignsOnce(t *testing.T) {
	f := setup(t)
	in := f.issue(t, "1000")
	req := request(t, in, goodTx(t, in, 0), f.ok(in))
	const n = 8
	var wg sync.WaitGroup
	res := make([]*Response, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res[i], errs[i] = f.svc.SignTx(context.Background(), "apid", req)
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("동시 요청 %d: %v", i, errs[i])
		}
		if *res[i] != *res[0] {
			t.Fatalf("동시 요청 응답이 다르다: %+v / %+v", res[i], res[0])
		}
	}
	if c := f.fs.calls.Load(); c != 1 {
		t.Fatalf("HSM 서명 호출 %d 회 (기대 1)", c)
	}
	if f.rows(t, in.RequestID) != 1 {
		t.Fatal("서명 기록이 1행이 아니다")
	}
}

func TestHSMFailureLeavesNoRecord(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	in := f.issue(t, "1000")
	req := request(t, in, goodTx(t, in, 0), f.ok(in))
	f.fs.fail.Store(true)
	_, err := f.svc.SignTx(ctx, "apid", req)
	wantReject(t, err, 8, CodeSignFailed)
	if f.rows(t, in.RequestID) != 0 {
		t.Fatal("HSM 실패 후 예약 행이 남았다")
	}
	f.fs.fail.Store(false)
	if _, err := f.svc.SignTx(ctx, "apid", req); err != nil {
		t.Fatalf("HSM 복구 후 재시도 실패: %v", err)
	}
}

func TestRejections(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	run := func(name string, step int, code string, build func() (Request, *Service)) {
		t.Run(name, func(t *testing.T) {
			req, svc := build()
			if svc == nil {
				svc = f.svc
			}
			_, err := svc.SignTx(ctx, "apid", req)
			wantReject(t, err, step, code)
			var peek struct {
				RequestID string `json:"request_id"`
			}
			_ = json.Unmarshal(req.Intent, &peek)
			if f.auditCount(t, "SIGN_REJECTED", peek.RequestID) != 1 {
				t.Fatalf("거부 감사 기록이 1건이 아니다")
			}
		})
	}
	std := func(in *intent.Intent) Request { return request(t, in, goodTx(t, in, 0), f.ok(in)) }

	// --- 설계서 16절: 승인 ---
	run("승인 수 부족", 6, policy.CodeApprovalInsufficient, func() (Request, *Service) {
		in := f.issue(t, "1000")
		return request(t, in, goodTx(t, in, 0), []approval.Approval{f.approve(in, approval.Approve, "it-a2")}), nil
	})
	run("기안자의 자기 승인", 6, policy.CodeApprovalSelf, func() (Request, *Service) {
		in := f.issue(t, "1000")
		return request(t, in, goodTx(t, in, 0), []approval.Approval{f.approve(in, approval.Approve, "it-a1"), f.approve(in, approval.Approve, "it-a2")}), nil
	})
	run("등록되지 않은 승인자", 6, approval.CodeUnknownApprover, func() (Request, *Service) {
		in := f.issue(t, "1000")
		a := f.approve(in, approval.Approve, "it-a2")
		a.ApproverID = "it-nobody-" + f.s
		return request(t, in, goodTx(t, in, 0), []approval.Approval{a, f.approve(in, approval.Approve, "it-a3")}), nil
	})
	run("위조된 승인 서명", 6, approval.CodeInvalidSignature, func() (Request, *Service) {
		in := f.issue(t, "1000")
		forged := f.approve(in, approval.Approve, "it-a4") // 다른 승인자 키로 서명한 값을 a2 이름으로 제출
		forged.ApproverID = f.id("it-a2")
		return request(t, in, goodTx(t, in, 0), []approval.Approval{forged, f.approve(in, approval.Approve, "it-a3")}), nil
	})
	run("승인 후 intent 변조(intent_hash 그대로)", 3, CodeIntentHash, func() (Request, *Service) {
		in := f.issue(t, "1000")
		req := std(in)
		tampered := *in
		tampered.Args = []string{in.Args[0], "99999"}
		b, _ := tampered.Canonical()
		req.Intent = b
		return req, nil
	})
	run("승인 후 intent 변조(intent_hash 도 다시 계산)", 6, approval.CodeInvalidSignature, func() (Request, *Service) {
		in := f.issue(t, "1000")
		approvals := f.ok(in) // 원래 intent 에 대한 승인
		tampered := *in
		tampered.Args = []string{in.Args[0], "99999"}
		return request(t, &tampered, goodTx(t, &tampered, 0), approvals), nil
	})
	// --- 설계서 16절: tx 대조 ---
	run("승인된 intent 와 다른 calldata", 7, evmtx.CodeTxCalldataMismatch, func() (Request, *Service) {
		in := f.issue(t, "1000")
		alt := *in
		alt.Args = []string{in.Args[0], "99999"}
		data, _ := alt.Calldata()
		return request(t, in, evmtx.NewUnsigned(big.NewInt(chainID), 0, in.ContractAddress(), data, 100000), f.ok(in)), nil
	})
	// --- 설계서 16절: 정책 ---
	run("수량 한도 초과", 5, policy.CodeAmountExceeded, func() (Request, *Service) { return std(f.issue(t, "100001")), nil })
	run("화이트리스트 밖 수신 계좌", 5, policy.CodeRecipientNotListed, func() (Request, *Service) {
		return std(f.intent(t, f.instA, signer.PurposeIssue, "issue(address,uint256)", stranger.Hex(), "10")), nil
	})
	run("허용되지 않은 함수", 5, policy.CodeFunctionNotAllowed, func() (Request, *Service) {
		return std(f.intent(t, f.instA, signer.PurposeIssue, "setAccountRestricted(address,bool)", whitelisted.Hex(), "true")), nil
	})
	// --- 설계서 16절: 키 ---
	run("다른 기관의 키 용도로 요청(기관 B 로 ISSUE)", 4, CodeKeyNotAvailable, func() (Request, *Service) {
		in := f.intent(t, f.instB, signer.PurposeIssue, "issue(address,uint256)", whitelisted.Hex(), "10")
		in.DrafterID = f.id("it-b1")
		return std(in), nil
	})
	// --- 설계서 16절: request_id, 만료 ---
	run("같은 request_id 로 다른 tx 재서명", 2, CodeRequestConflict, func() (Request, *Service) {
		in := f.issue(t, "1000")
		if _, err := f.svc.SignTx(ctx, "apid", std(in)); err != nil {
			t.Fatal(err)
		}
		return request(t, in, goodTx(t, in, 1), f.ok(in)), nil
	})
	run("만료된 요청", 3, CodeIntentExpired, func() (Request, *Service) {
		in := f.issue(t, "1000")
		svc := *f.svc
		svc.Now = func() time.Time { return in.Expires().Add(time.Second) }
		return std(in), &svc
	})
	// --- 추가 거부 사례 ---
	run("호출자(업무 서버 아님)", 1, CodeCallerNotAllowed, func() (Request, *Service) {
		in := f.issue(t, "1000")
		svc := *f.svc
		svc.Callers = []string{"someone-else"}
		return std(in), &svc
	})
	run("같은 승인자 중복", 6, policy.CodeApprovalDuplicate, func() (Request, *Service) {
		in := f.issue(t, "1000")
		a := f.approve(in, approval.Approve, "it-a2")
		return request(t, in, goodTx(t, in, 0), []approval.Approval{a, a}), nil
	})
	run("그룹 밖 승인자", 6, policy.CodeApprovalGroup, func() (Request, *Service) {
		in := f.issue(t, "1000")
		return request(t, in, goodTx(t, in, 0), []approval.Approval{f.approve(in, approval.Approve, "it-a2"), f.approve(in, approval.Approve, "it-a4")}), nil
	})
	run("다른 기관 승인자", 6, policy.CodeApprovalInstitution, func() (Request, *Service) {
		in := f.issue(t, "1000")
		return request(t, in, goodTx(t, in, 0), []approval.Approval{f.approve(in, approval.Approve, "it-a2"), f.approve(in, approval.Approve, "it-b2")}), nil
	})
	run("비활성 승인자", 6, approval.CodeApproverInactive, func() (Request, *Service) {
		in := f.issue(t, "1000")
		return request(t, in, goodTx(t, in, 0), []approval.Approval{f.approve(in, approval.Approve, "it-a2"), f.approve(in, approval.Approve, "it-a5")}), nil
	})
	run("반려 포함", 6, policy.CodeApprovalRejected, func() (Request, *Service) {
		in := f.issue(t, "1000")
		return request(t, in, goodTx(t, in, 0), []approval.Approval{f.approve(in, approval.Approve, "it-a2"), f.approve(in, approval.Reject, "it-a3"),
			f.approve(in, approval.Approve, "it-a1")}), nil
	})
	run("AUDIT 키로 tx 서명", 4, CodeKeyNotSignable, func() (Request, *Service) {
		return std(f.intent(t, f.instA, signer.PurposeAudit, "issue(address,uint256)", whitelisted.Hex(), "10")), nil
	})
	run("정책 가스 상한 초과", 5, policy.CodeGasLimitExceeded, func() (Request, *Service) {
		in := f.issue(t, "1000")
		data, _ := in.Calldata()
		return request(t, in, evmtx.NewUnsigned(big.NewInt(chainID), 0, in.ContractAddress(), data, 300001), f.ok(in)), nil
	})
	run("다른 to", 7, evmtx.CodeTxToMismatch, func() (Request, *Service) {
		in := f.issue(t, "1000")
		data, _ := in.Calldata()
		return request(t, in, evmtx.NewUnsigned(big.NewInt(chainID), 0, stranger, data, 100000), f.ok(in)), nil
	})
	run("다른 chainId", 7, evmtx.CodeTxChainIDMismatch, func() (Request, *Service) {
		in := f.issue(t, "1000")
		data, _ := in.Calldata()
		return request(t, in, evmtx.NewUnsigned(big.NewInt(1), 0, in.ContractAddress(), data, 100000), f.ok(in)), nil
	})
	run("0 이 아닌 value", 7, evmtx.CodeTxValueNonzero, func() (Request, *Service) {
		in := f.issue(t, "1000")
		data, _ := in.Calldata()
		to := in.ContractAddress()
		return request(t, in, types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(chainID), GasTipCap: big.NewInt(0), GasFeeCap: big.NewInt(0),
			Gas: 100000, To: &to, Value: big.NewInt(1), Data: data}), f.ok(in)), nil
	})
	run("알 수 없는 원장", 3, CodeLedgerUnknown, func() (Request, *Service) {
		in := f.issue(t, "1000")
		svc := *f.svc
		svc.Chains = map[string]uint64{}
		return std(in), &svc
	})
	// 동결은 마지막에(이후 기관 A ISSUE 요청이 모두 막힌다).
	run("동결된 키", 4, CodeKeyFrozen, func() (Request, *Service) {
		if _, err := f.db.Exec(`INSERT INTO freezes (freeze_id, scope, target, reason, frozen_by) VALUES (?, 'KEY', ?, 'it', 'it')`,
			"it-frz-"+rid(), f.keyA); err != nil {
			t.Fatal(err)
		}
		return std(f.issue(t, "1000")), nil
	})
	// 같은 request_id 시험의 첫 서명 1회 외에는 HSM 이 호출되지 않았다.
	if c := f.fs.calls.Load(); c != 1 {
		t.Fatalf("거부 사례에서 HSM 서명이 호출됐다(총 %d 회, 기대 1)", c)
	}
}

// 설계서 16절: RETIRED·DESTROYED 키
func TestRetiredAndDestroyedKeyRejected(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if err := keyreg.SetStatus(ctx, f.db, f.keyA, keyreg.StatusActive, keyreg.StatusRetired); err != nil {
		t.Fatal(err)
	}
	in := f.issue(t, "1000")
	_, err := f.svc.SignTx(ctx, "apid", request(t, in, goodTx(t, in, 0), f.ok(in)))
	wantReject(t, err, 4, CodeKeyNotAvailable)
	if err := keyreg.SetStatus(ctx, f.db, f.keyA, keyreg.StatusRetired, keyreg.StatusDestroyed); err != nil {
		t.Fatal(err)
	}
	in = f.issue(t, "1000")
	_, err = f.svc.SignTx(ctx, "apid", request(t, in, goodTx(t, in, 0), f.ok(in)))
	wantReject(t, err, 4, CodeKeyNotAvailable)
}
