//go:build integration

// 통합 테스트: Fabric 신원 키 작업(FABRIC_CSR·INSTALL_CERT·TOKEN·REVOKED, 설계서 10.5, D-26)의 거부 조건.
// 키는 시험용 P-256 키를 레지스트리에 직접 넣고, HSM 서명은 메모리 대역(p256Wrap)이 한다. 실제 CA·SoftHSM2 경로는
// test/fabric_e2e_test.go 가 확인한다.
package keyops

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

// p256Wrap 은 SignDigest 만 쓰는 대역이다(키 ID 별 P-256 개인키).
type p256Wrap struct {
	fakeWrap
	keys map[string]*ecdsa.PrivateKey
}

func (w *p256Wrap) SignDigest(_ context.Context, keyID string, d [32]byte) (*big.Int, *big.Int, error) {
	k, ok := w.keys[keyID]
	if !ok {
		return nil, nil, errors.New("키 없음")
	}
	return ecdsa.Sign(rand.Reader, k, d[:])
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, cn string) *testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: k}
}

func (ca *testCA) issue(t *testing.T, pub *ecdsa.PublicKey, cn string, serial int64) []byte {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (ca *testCA) crl(t *testing.T, serials ...int64) []byte {
	t.Helper()
	tpl := &x509.RevocationList{Number: big.NewInt(time.Now().UnixNano()), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour)}
	for _, s := range serials {
		tpl.RevokedCertificateEntries = append(tpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: big.NewInt(s), RevocationTime: time.Now()})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tpl, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

type fabFx struct {
	*fx
	ca    *testCA
	keyID string
	priv  *ecdsa.PrivateKey
}

func setupFabric(t *testing.T) *fabFx {
	t.Helper()
	f := setup(t)
	ca := newCA(t, "ca.insta.test")
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyID := f.id("fab")
	pub := signer.PublicKey(elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)) //nolint:staticcheck // 65바이트 비압축 형식
	if err := keyreg.RegisterKey(context.Background(), f.db, keyreg.Key{KeyID: keyID, TokenID: "it-tok-" + f.s, Purpose: signer.PurposeIssue,
		Curve: signer.CurveP256, PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.db.Exec("DELETE FROM fabric_identities WHERE key_id = ?", keyID) })
	f.ex.Wrap = &p256Wrap{keys: map[string]*ecdsa.PrivateKey{keyID: priv}}
	f.ex.Fabric = FabricConfig{
		MSP: func(l, i string) (string, bool) { return "InstAMSP", l == f.ledger && i == f.inst },
		Roots: func(l string) []*x509.Certificate {
			if l != f.ledger {
				return nil
			}
			return []*x509.Certificate{ca.cert}
		},
	}
	return &fabFx{fx: f, ca: ca, keyID: keyID, priv: priv}
}

// op 는 payload 를 약속값으로 묶은 2인 서명 요청이다.
func (f *fabFx) op(typ Type, payload []byte) Request {
	r := New(typ, time.Now())
	r.KeyID, r.Reason = f.keyID, "시험"
	if typ == TypeFabricCSR {
		r.Subject = "inst-a-issue"
	} else {
		h := sha256.Sum256(payload)
		r.Payload, r.PayloadSHA256 = payload, hex.EncodeToString(h[:])
	}
	r.Sign(f.id("s1"), f.admins["s1"])
	r.Sign(f.id("s2"), f.admins["s2"])
	return r
}

func (f *fabFx) run(r Request) (*Result, error) {
	return f.ex.Execute(context.Background(), r, "it", time.Now())
}

func tokenInput(t *testing.T, method, uri string) []byte {
	t.Helper()
	b, _ := json.Marshal(FabricTokenInput{Method: method, URI: uri, Body: []byte(`{}`)})
	return b
}

// 신원 키 작업은 HSM 키와 MSP 루트 CA 에 묶인 것만 받는다: 다른 공개키·다른 CA 의 인증서, 재발급이 아닌 토큰,
// 다른 CA 의 CRL, 해당 일련번호가 없는 CRL, 이중 폐기를 거부한다. 거부는 감사로그(KEYOP_REJECTED)에 남는다.
func TestFabricIdentityOpsRejections(t *testing.T) {
	f := setupFabric(t)
	ctx := context.Background()

	// CSR 은 HSM 키로 서명된다.
	res, err := f.run(f.op(TypeFabricCSR, nil))
	if err != nil {
		t.Fatalf("CSR: %v", err)
	}
	b, _ := pem.Decode([]byte(res.CSR))
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil || csr.CheckSignature() != nil || !csr.PublicKey.(*ecdsa.PublicKey).Equal(&f.priv.PublicKey) {
		t.Fatalf("CSR 서명·공개키: %v", err)
	}

	// 신원이 없으면 토큰·폐기를 거부한다.
	if _, err := f.run(f.op(TypeFabricToken, tokenInput(t, "POST", reenrollURI))); code(err) != CodeKeyState {
		t.Fatalf("신원 없이 토큰: %s", code(err))
	}

	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rogue := newCA(t, "rogue")
	for _, c := range []struct {
		name, want string
		payload    []byte
	}{
		{"다른 공개키 인증서", CodeKeyState, f.ca.issue(t, &other.PublicKey, "inst-a-issue", 10)},
		{"다른 CA 인증서", CodeInvalid, rogue.issue(t, &f.priv.PublicKey, "inst-a-issue", 11)},
		{"PEM 아님", CodeInvalid, []byte("not a certificate")},
	} {
		r := f.op(TypeFabricInstallCert, c.payload)
		if _, err := f.run(r); code(err) != c.want {
			t.Fatalf("%s: %s, 기대 %s", c.name, code(err), c.want)
		}
		if f.audits(t, "KEYOP_REJECTED", r.OpID) != 1 {
			t.Fatalf("%s: 거부 감사 없음", c.name)
		}
	}
	// payload 바꿔치기(서명된 약속값과 다름).
	swapped := f.op(TypeFabricInstallCert, f.ca.issue(t, &f.priv.PublicKey, "inst-a-issue", 12))
	swapped.Payload = f.ca.issue(t, &other.PublicKey, "inst-a-issue", 13)
	if _, err := f.run(swapped); code(err) != CodeInvalid {
		t.Fatalf("payload 바꿔치기: %s", code(err))
	}

	// 정상 등록.
	certPEM := f.ca.issue(t, &f.priv.PublicKey, "inst-a-issue", 20)
	if res, err := f.run(f.op(TypeFabricInstallCert, certPEM)); err != nil || res.Serial != hex.EncodeToString(big.NewInt(20).Bytes()) {
		t.Fatalf("인증서 등록: %v", err)
	}
	if id, err := keyreg.GetIdentity(ctx, f.db, f.keyID); err != nil || id.Status != keyreg.IdentityEnrolled {
		t.Fatalf("신원 상태: %v", err)
	}
	if _, err := f.run(f.op(TypeFabricInstallCert, certPEM)); code(err) != CodeKeyState {
		t.Fatalf("이중 등록: %s", code(err))
	}

	// 토큰은 재발급(POST /api/v1/reenroll)에만.
	for _, c := range []struct{ method, uri string }{{"POST", "/api/v1/register"}, {"POST", "/api/v1/revoke"}, {"GET", reenrollURI}} {
		if _, err := f.run(f.op(TypeFabricToken, tokenInput(t, c.method, c.uri))); code(err) != CodeInvalid {
			t.Fatalf("토큰 %s %s: %s", c.method, c.uri, code(err))
		}
	}
	res, err = f.run(f.op(TypeFabricToken, tokenInput(t, "POST", reenrollURI)))
	if err != nil {
		t.Fatalf("재발급 토큰: %v", err)
	}
	parts := strings.Split(res.Token, ".")
	sig, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1])
	b64 := base64.StdEncoding.EncodeToString
	d := sha256.Sum256([]byte("POST." + b64([]byte(reenrollURI)) + "." + b64([]byte(`{}`)) + "." + b64(certPEM)))
	if len(parts) != 2 || !ecdsa.VerifyASN1(&f.priv.PublicKey, d[:], sig) {
		t.Fatal("재발급 토큰 서명이 신원 키로 검증되지 않는다")
	}

	// 폐기: MSP 루트 CA 가 서명하고 해당 일련번호가 있는 CRL 만.
	for _, c := range []struct {
		name string
		crl  []byte
	}{
		{"다른 CA 의 CRL", rogue.crl(t, 20)},
		{"일련번호 없는 CRL", f.ca.crl(t, 21, 22)},
		{"PEM 아님", []byte("not a crl")},
	} {
		if _, err := f.run(f.op(TypeFabricRevoked, c.crl)); code(err) != CodeInvalid {
			t.Fatalf("%s: %s", c.name, code(err))
		}
	}
	if id, _ := keyreg.GetIdentity(ctx, f.db, f.keyID); id.Status != keyreg.IdentityEnrolled {
		t.Fatalf("거부 뒤 신원 상태 %s", id.Status)
	}
	if _, err := f.run(f.op(TypeFabricRevoked, f.ca.crl(t, 21, 20))); err != nil {
		t.Fatalf("폐기 기록: %v", err)
	}
	if id, _ := keyreg.GetIdentity(ctx, f.db, f.keyID); id.Status != keyreg.IdentityRevoked {
		t.Fatalf("폐기 뒤 신원 상태 %s", id.Status)
	}
	if _, err := f.run(f.op(TypeFabricRevoked, f.ca.crl(t, 20))); code(err) != CodeKeyState {
		t.Fatalf("이중 폐기: %s", code(err))
	}
	// 폐기된 신원으로는 토큰을 만들지 않는다.
	if _, err := f.run(f.op(TypeFabricToken, tokenInput(t, "POST", reenrollURI))); code(err) != CodeKeyState {
		t.Fatalf("폐기 뒤 토큰: %s", code(err))
	}
}

// secp256k1 키(EVM)와 MSP 설정이 없는 (원장, 기관)의 키로는 신원 작업을 하지 않는다.
func TestFabricIdentityOpsKeyScope(t *testing.T) {
	f := setupFabric(t)
	ctx := context.Background()
	gen := f.req(TypeGenerate, f.id("evm"), "s1", "s2")
	if _, err := f.ex.Execute(ctx, gen, "it", time.Now()); err != nil {
		t.Fatalf("EVM 키 생성: %v", err)
	}
	r := f.op(TypeFabricCSR, nil)
	r.KeyID, r.Approvals = f.id("evm"), nil
	r.Sign(f.id("s1"), f.admins["s1"])
	r.Sign(f.id("s2"), f.admins["s2"])
	if _, err := f.run(r); code(err) != CodeKeyState {
		t.Fatalf("secp256k1 키 CSR: %s", code(err))
	}
	f.ex.Fabric.MSP = func(string, string) (string, bool) { return "", false }
	if _, err := f.run(f.op(TypeFabricCSR, nil)); code(err) != CodeKeyState {
		t.Fatalf("MSP 설정 없는 키 CSR: %s", code(err))
	}
}
