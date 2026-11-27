//go:build integration

// 통합 테스트: 키 작업(생성·퇴역·폐기)의 승인 검증, 재전송 방지, 교체 시 활성화의 원자성, 폐기 조건과 증적.
// MySQL(signer 스키마)에 signer_app 으로 접속한다. HSM 은 메모리 대역(fakeHSM)이다. 실제 SoftHSM2 경로는
// test/ 의 종단 시험(실행 중인 signerd)이 확인한다. 만든 행은 시험이 끝나면 지운다(감사 기록은 추가 전용이라 남는다).
package keyops

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-sql-driver/mysql"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/backup"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

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
		t.Fatalf("DB 접속: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// fakeHSM 은 토큰 라벨·키 ID 별로 키를 메모리에 둔다.
type fakeHSM struct {
	mu        sync.Mutex
	keys      map[string]*ecdsa.PrivateKey // label/keyID
	failGen   bool
	failAfter bool // 생성은 하고 오류를 돌려준다(등록 전에 멈춘 경우 흉내)
}

func (h *fakeHSM) Generate(_ context.Context, spec signer.KeySpec) (signer.PublicKey, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failGen {
		return nil, errors.New("HSM 응답 없음(시험)")
	}
	k, _ := crypto.GenerateKey()
	h.keys[spec.TokenLabel+"/"+spec.KeyID] = k
	if h.failAfter {
		return nil, errors.New("생성 뒤 연결 끊김(시험)")
	}
	return signer.PublicKey(crypto.FromECDSAPub(&k.PublicKey)), nil
}

func (h *fakeHSM) PublicKeyOf(_ context.Context, label, id string) (signer.PublicKey, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	k, ok := h.keys[label+"/"+id]
	if !ok {
		return nil, errors.New("없음")
	}
	return signer.PublicKey(crypto.FromECDSAPub(&k.PublicKey)), nil
}

func (h *fakeHSM) DestroyIn(_ context.Context, label, id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.keys, label+"/"+id)
	return nil
}

func (h *fakeHSM) ObjectCount(_ context.Context, label, id string) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.keys[label+"/"+id]; ok {
		return 2, nil // 개인키·공개키
	}
	return 0, nil
}

type fx struct {
	db     *sql.DB
	ex     *Executor
	hsm    *fakeHSM
	s      string
	ledger string
	inst   string
	admins map[string]ed25519.PrivateKey
	keys   []string
}

func setup(t *testing.T) *fx {
	t.Helper()
	db := openDB(t)
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	s := hex.EncodeToString(b)
	f := &fx{db: db, hsm: &fakeHSM{keys: map[string]*ecdsa.PrivateKey{}}, s: s, ledger: "it-kop-" + s, inst: "it-inst-" + s, admins: map[string]ed25519.PrivateKey{}}
	group := "it-sec-" + s
	tok := "it-tok-" + s
	ctx := context.Background()
	if err := keyreg.RegisterToken(ctx, db, keyreg.Token{TokenID: tok, Label: tok, LedgerID: f.ledger, InstitutionID: f.inst}); err != nil {
		t.Fatal(err)
	}
	type ap struct{ id, role, status, group string }
	for _, a := range []ap{{"s1", "SECURITY_ADMIN", "ACTIVE", group}, {"s2", "SECURITY_ADMIN", "ACTIVE", group}, {"s3", "SECURITY_ADMIN", "ACTIVE", group},
		{"x1", "APPROVER", "ACTIVE", group}, {"s4", "SECURITY_ADMIN", "DISABLED", group}, {"s5", "SECURITY_ADMIN", "ACTIVE", ""}} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		f.admins[a.id] = priv
		id := f.id(a.id)
		if _, err := db.Exec(`INSERT INTO approvers (approver_id, name, institution_id, role, ed25519_pubkey, status) VALUES (?, 'it', 'platform', ?, ?, ?)`,
			id, a.role, []byte(pub), a.status); err != nil {
			t.Fatal(err)
		}
		if a.group != "" {
			if _, err := db.Exec(`INSERT INTO approver_groups (group_id, approver_id) VALUES (?, ?)`, a.group, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM key_ops WHERE key_id LIKE ?", "it-%-"+s+"%")
		_, _ = db.Exec("DELETE FROM `keys` WHERE token_id = ?", tok)
		_, _ = db.Exec("DELETE FROM hsm_tokens WHERE token_id = ?", tok)
		_, _ = db.Exec("DELETE FROM approver_groups WHERE group_id = ?", group)
		_, _ = db.Exec("DELETE FROM approvers WHERE approver_id LIKE ?", "it-%-"+s)
	})
	f.ex = &Executor{DB: db, HSM: f.hsm, AdminGroup: group, Approvals: 2}
	return f
}

func (f *fx) id(short string) string { return "it-" + short + "-" + f.s }

func (f *fx) req(t Type, keyID string, signers ...string) Request {
	r := New(t, time.Now())
	r.KeyID, r.Reason = keyID, "시험"
	if t == TypeGenerate {
		r.LedgerID, r.InstitutionID, r.Purpose = f.ledger, f.inst, signer.PurposeIssue
	}
	for _, s := range signers {
		r.Sign(f.id(s), f.admins[s])
	}
	return r
}

func resign(r Request, f *fx, signers ...string) Request {
	r.Approvals = nil
	for _, s := range signers {
		r.Sign(f.id(s), f.admins[s])
	}
	return r
}

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return fmt.Sprintf("(코드 없음: %v)", err)
}

func (f *fx) status(t *testing.T, keyID string) keyreg.Status {
	k, err := keyreg.Get(context.Background(), f.db, keyID)
	if err != nil {
		t.Fatal(err)
	}
	return k.Status
}

func (f *fx) audits(t *testing.T, action, subject string) int {
	var n int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = ? AND subject = ?`, action, subject).Scan(&n)
	return n
}

// 승인 검증: 보안관리자 M명이 필요하고, 하나라도 잘못되면 전체 거부. 거부는 감사로그에 남는다.
func TestApprovalChecks(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	now := time.Now()
	k := f.id("k-appr")
	cases := []struct {
		name string
		r    Request
		want string
	}{
		{"1명", f.req(TypeGenerate, k, "s1"), CodeInsufficient},
		{"중복", f.req(TypeGenerate, k, "s1", "s1"), CodeInvalid},
		{"보안관리자 아님", f.req(TypeGenerate, k, "s1", "x1"), CodeAdmin},
		{"비활성", f.req(TypeGenerate, k, "s1", "s4"), CodeAdmin},
		{"그룹 밖", f.req(TypeGenerate, k, "s1", "s5"), CodeAdmin},
	}
	forged := f.req(TypeGenerate, k, "s1", "s2")
	forged.Approvals[1].Signature = forged.Approvals[0].Signature
	cases = append(cases, struct {
		name string
		r    Request
		want string
	}{"위조 서명", forged, CodeSignature})
	// 업무 승인 서명(sto-approval-v1)을 키 작업 서명으로 재사용하면 거부된다(도메인 구분).
	cross := f.req(TypeGenerate, k)
	h := cross.Hash()
	for _, s := range []string{"s1", "s2"} {
		sig, _ := approval.Sign(f.admins[s], h, approval.Approve)
		cross.Approvals = append(cross.Approvals, Signature{AdminID: f.id(s), Signature: hex.EncodeToString(sig)})
	}
	cases = append(cases, struct {
		name string
		r    Request
		want string
	}{"업무 승인 서명 재사용", cross, CodeSignature})
	stale := f.req(TypeGenerate, k)
	stale.RequestedAt = now.Add(-10 * time.Minute).UTC().Format(TimeLayout)
	cases = append(cases, struct {
		name string
		r    Request
		want string
	}{"오래된 요청", resign(stale, f, "s1", "s2"), CodeStale})
	tampered := f.req(TypeGenerate, k, "s1", "s2")
	tampered.Purpose = signer.PurposeContractAdmin // 서명 뒤 용도 변경
	cases = append(cases, struct {
		name string
		r    Request
		want string
	}{"서명 뒤 내용 변경", tampered, CodeSignature})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := f.ex.Execute(ctx, c.r, "stoctl", now)
			if code(err) != c.want {
				t.Fatalf("%s: %v (기대 %s)", c.name, err, c.want)
			}
			if f.audits(t, "KEYOP_REJECTED", c.r.OpID) != 1 {
				t.Fatal("거부 감사 기록이 없다")
			}
		})
	}
	if len(f.hsm.keys) != 0 {
		t.Fatal("거부된 요청으로 HSM 키가 만들어졌다")
	}
}

// 생성 → 교체용 생성(PENDING) → 퇴역과 활성화(한 트랜잭션) → 폐기. 재전송과 상태 조건.
func TestRotateLifecycle(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	now := time.Now()
	old, nw := f.id("k-old"), f.id("k-new")

	r1 := f.req(TypeGenerate, old, "s1", "s2")
	res, err := f.ex.Execute(ctx, r1, "stoctl", now)
	if err != nil || res.Status != "ACTIVE" {
		t.Fatalf("첫 키 생성: %+v %v", res, err)
	}
	if _, err := f.ex.Execute(ctx, r1, "stoctl", now); code(err) != CodeReplay {
		t.Fatalf("같은 op_id 재전송: %v", err)
	}
	// 같은 범위에 ACTIVE 키가 있으므로 교체용 키는 PENDING 이다. Lookup 은 계속 이전 키 하나만 본다.
	r2 := f.req(TypeGenerate, nw)
	r2.RotatedFrom = old
	r2 = resign(r2, f, "s2", "s3")
	res, err = f.ex.Execute(ctx, r2, "stoctl", now)
	if err != nil || res.Status != "PENDING" {
		t.Fatalf("교체용 키 생성: %+v %v", res, err)
	}
	if k, err := keyreg.Lookup(ctx, f.db, f.ledger, f.inst, signer.PurposeIssue); err != nil || k.KeyID != old {
		t.Fatalf("교체 중 Lookup: %v %v", k, err)
	}
	// ACTIVE 키는 폐기할 수 없다.
	if _, err := f.ex.Execute(ctx, f.req(TypeDestroy, old, "s1", "s2"), "stoctl", now); code(err) != CodeKeyState {
		t.Fatalf("ACTIVE 키 폐기: %v", err)
	}
	// 다른 키를 후속으로 지정하면 거부되고, 이전 키는 그대로 ACTIVE 다(원자성).
	bad := f.req(TypeRetire, old)
	bad.Successor = f.id("k-other")
	if _, err := f.ex.Execute(ctx, resign(bad, f, "s1", "s3"), "stoctl", now); code(err) != CodeSuccessor {
		t.Fatalf("잘못된 후속 키: %v", err)
	}
	if f.status(t, old) != keyreg.StatusActive {
		t.Fatal("거부된 퇴역 뒤 이전 키 상태가 바뀌었다")
	}
	ret := f.req(TypeRetire, old)
	ret.Successor = nw
	res, err = f.ex.Execute(ctx, resign(ret, f, "s1", "s3"), "stoctl", now)
	if err != nil || res.Activate != nw {
		t.Fatalf("퇴역과 활성화: %+v %v", res, err)
	}
	if f.status(t, old) != keyreg.StatusRetired || f.status(t, nw) != keyreg.StatusActive {
		t.Fatalf("상태 %s %s", f.status(t, old), f.status(t, nw))
	}
	if k, err := keyreg.Lookup(ctx, f.db, f.ledger, f.inst, signer.PurposeIssue); err != nil || k.KeyID != nw {
		t.Fatalf("교체 뒤 Lookup: %v %v", k, err)
	}
	// 폐기: RETIRED 키만, HSM 객체가 없어졌는지 확인, 증적
	res, err = f.ex.Execute(ctx, f.req(TypeDestroy, old, "s2", "s3"), "stoctl", now)
	if err != nil || res.Status != "DESTROYED" || res.ObjectsRemaining == nil || *res.ObjectsRemaining != 0 {
		t.Fatalf("폐기: %+v %v", res, err)
	}
	if n, _ := f.hsm.ObjectCount(ctx, "it-tok-"+f.s, old); n != 0 {
		t.Fatal("폐기 뒤 HSM 객체가 남았다")
	}
	var payload string
	_ = f.db.QueryRow(`SELECT payload_json FROM audit_log WHERE action = 'KEY_DESTROYED' AND subject = ?`, old).Scan(&payload)
	if !strings.Contains(payload, `"objects_after":0`) || !strings.Contains(payload, `"objects_before":2`) {
		t.Fatalf("폐기 증적: %s", payload)
	}
	// DESTROYED·RETIRED 키는 다시 쓸 수 없다.
	if _, err := f.ex.Execute(ctx, f.req(TypeRetire, old, "s1", "s2"), "stoctl", now); code(err) != CodeKeyState {
		t.Fatalf("폐기된 키 퇴역: %v", err)
	}
	for _, a := range []string{"KEY_GENERATED", "KEY_ACTIVATED", "KEY_RETIRED", "KEY_DESTROYED"} {
		subj := old
		if a == "KEY_ACTIVATED" {
			subj = nw
		}
		if a == "KEY_GENERATED" && f.audits(t, a, nw) != 1 {
			t.Fatalf("%s 감사 기록(새 키)", a)
		}
		if f.audits(t, a, subj) != 1 {
			t.Fatalf("%s 감사 기록", a)
		}
	}
}

// HSM 생성 뒤 등록 전에 멈춘 경우: 같은 op_id 로 다시 보내면 남은 객체로 등록을 마친다(키가 둘 생기지 않는다).
func TestGenerateRetryAfterPartialFailure(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	k := f.id("k-retry")
	r := f.req(TypeGenerate, k, "s1", "s2")
	f.hsm.failAfter = true
	if _, err := f.ex.Execute(ctx, r, "stoctl", time.Now()); code(err) != CodeHSM {
		t.Fatalf("부분 실패: %v", err)
	}
	f.hsm.failAfter = false
	res, err := f.ex.Execute(ctx, r, "stoctl", time.Now())
	if err != nil {
		t.Fatalf("재시도: %v", err)
	}
	want, _ := f.hsm.PublicKeyOf(ctx, "it-tok-"+f.s, k)
	addr, _ := want.Address()
	if res.Address != addr.Hex() || len(f.hsm.keys) != 1 {
		t.Fatalf("재시도 결과 %+v (HSM 키 %d개)", res, len(f.hsm.keys))
	}
	if _, err := f.ex.Execute(ctx, r, "stoctl", time.Now()); code(err) != CodeReplay {
		t.Fatalf("완료 뒤 재전송: %v", err)
	}
}

// --- 백업·복구(T3.6): 시험용 래핑(개인키 XOR SHA-256(래핑 키)). 실제 C_WrapKey 경로는 internal/hsm 시험과 복구 리허설이 확인한다.

type fakeWrap struct {
	h    *fakeHSM
	wrap map[string][]byte // label/wrapID → key
}

func (w *fakeWrap) InjectWrappingKey(_ context.Context, label, id string, key []byte) error {
	w.wrap[label+"/"+id] = append([]byte(nil), key...)
	return nil
}
func (w *fakeWrap) HasWrappingKey(_ context.Context, label, id string) (bool, error) {
	_, ok := w.wrap[label+"/"+id]
	return ok, nil
}
func xorKey(priv []byte, key []byte) []byte {
	m := sha256.Sum256(key)
	out := make([]byte, len(priv))
	for i := range priv {
		out[i] = priv[i] ^ m[i%32]
	}
	return out
}
func (w *fakeWrap) WrapPrivateKey(_ context.Context, label, id, keyID string) ([]byte, error) {
	k, ok := w.h.keys[label+"/"+keyID]
	if !ok {
		return nil, errors.New("키 없음")
	}
	return xorKey(crypto.FromECDSA(k), w.wrap[label+"/"+id]), nil
}
func (w *fakeWrap) UnwrapPrivateKey(_ context.Context, label, id, keyID string, wrapped, _ []byte) error {
	k, err := crypto.ToECDSA(xorKey(wrapped, w.wrap[label+"/"+id]))
	if err != nil {
		return err
	}
	w.h.keys[label+"/"+keyID] = k
	return nil
}
func (w *fakeWrap) SignDigest(_ context.Context, keyID string, d [32]byte) (*big.Int, *big.Int, error) {
	for lk, k := range w.h.keys {
		if strings.HasSuffix(lk, "/"+keyID) {
			sig, err := crypto.Sign(d[:], k)
			if err != nil {
				return nil, nil, err
			}
			return new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64]), nil
		}
	}
	return nil, nil, errors.New("키 없음")
}

func TestBackupRestore(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	now := time.Now()
	w := &fakeWrap{h: f.hsm, wrap: map[string][]byte{}}
	f.ex.Wrap = w
	tok := "it-tok-" + f.s

	// 루트 키(CONTRACT_ADMIN)와 운영 키(ISSUE)
	root := f.req(TypeGenerate, f.id("k-root"))
	root.Purpose = signer.PurposeContractAdmin
	if _, err := f.ex.Execute(ctx, resign(root, f, "s1", "s2"), "stoctl", now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ex.Execute(ctx, f.req(TypeGenerate, f.id("k-op"), "s1", "s2"), "stoctl", now); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	inst := func(secretHex string, commit string) Request {
		r := New(TypeWrapInstall, now)
		r.LedgerID, r.InstitutionID, r.KeyID, r.Reason, r.SecretSHA256, r.Secret = f.ledger, f.inst, f.id("wrap"), "시험", commit, secretHex
		return resign(r, f, "s1", "s3")
	}
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	if _, err := f.ex.Execute(ctx, inst(hex.EncodeToString(other), backup.Commitment(key)), "stoctl", now); code(err) != CodeSecret {
		t.Fatalf("약속값과 다른 래핑 키: %v", err)
	}
	if _, err := f.ex.Execute(ctx, inst(hex.EncodeToString(key), backup.Commitment(key)), "stoctl", now); err != nil {
		t.Fatal(err)
	}
	var payload string
	_ = f.db.QueryRow(`SELECT payload_json FROM audit_log WHERE action = 'KEY_WRAP_INSTALLED' AND subject = ?`, f.id("wrap")).Scan(&payload)
	if strings.Contains(payload, hex.EncodeToString(key)) || !strings.Contains(payload, backup.Commitment(key)) {
		t.Fatalf("래핑 키 주입 감사 기록에 키 값이 있거나 약속값이 없다: %s", payload)
	}
	bk := func(keyID string) Request {
		r := New(TypeBackup, now)
		r.KeyID, r.WrapKeyID, r.Reason = keyID, f.id("wrap"), "시험"
		return resign(r, f, "s2", "s3")
	}
	if _, err := f.ex.Execute(ctx, bk(f.id("k-op")), "stoctl", now); code(err) != CodeKeyState {
		t.Fatalf("운영 키 백업: %v", err)
	}
	res, err := f.ex.Execute(ctx, bk(f.id("k-root")), "stoctl", now)
	if err != nil || res.Backup == nil || res.Backup.Validate() != nil {
		t.Fatalf("루트 키 백업: %+v %v", res, err)
	}
	file := res.Backup
	rs := func(fl *backup.File, withSecret bool) Request {
		r := New(TypeRestore, now)
		r.KeyID, r.WrapKeyID, r.Reason, r.Backup, r.BackupSHA256 = fl.KeyID, fl.WrapKeyID, "시험", fl, fl.Hash()
		if withSecret {
			r.SecretSHA256, r.Secret = backup.Commitment(key), hex.EncodeToString(key)
		}
		return resign(r, f, "s1", "s2")
	}
	// 객체가 있으면 복원하지 않는다.
	if _, err := f.ex.Execute(ctx, rs(file, false), "stoctl", now); code(err) != CodeKeyState {
		t.Fatalf("객체가 있는데 복원: %v", err)
	}
	// 토큰 분실: 키 객체와 래핑 키가 모두 없어졌다.
	delete(f.hsm.keys, tok+"/"+f.id("k-root"))
	delete(w.wrap, tok+"/"+f.id("wrap"))
	// 서명된 요청과 다른 백업 파일
	tampered := *file
	tampered.Ciphertext = hex.EncodeToString(xorKey(file.CiphertextBytes(), []byte("x")))
	r := rs(file, true)
	r.Backup = &tampered
	if _, err := f.ex.Execute(ctx, r, "stoctl", now); code(err) != CodeBackup {
		t.Fatalf("바뀐 백업 파일: %v", err)
	}
	// 래핑 키가 없는데 조각(비밀)을 안 보냈다.
	if _, err := f.ex.Execute(ctx, rs(file, false), "stoctl", now); code(err) != CodeSecret {
		t.Fatalf("래핑 키 없이 복원: %v", err)
	}
	// 다른 래핑 키로 복원하면 주소가 맞지 않아 거부하고 객체를 남기지 않는다.
	w.wrap[tok+"/"+f.id("wrap")] = other
	if _, err := f.ex.Execute(ctx, rs(file, false), "stoctl", now); code(err) != CodeRestore {
		t.Fatalf("다른 래핑 키로 복원: %v", err)
	}
	if n, _ := f.hsm.ObjectCount(ctx, tok, f.id("k-root")); n != 0 {
		t.Fatal("맞지 않는 복원 키가 남았다")
	}
	delete(w.wrap, tok+"/"+f.id("wrap"))
	res, err = f.ex.Execute(ctx, rs(file, true), "stoctl", now)
	if err != nil || res.Address != file.Address {
		t.Fatalf("복원: %+v %v", res, err)
	}
	if f.audits(t, "KEY_RESTORED", f.id("k-root")) != 1 || f.audits(t, "KEY_BACKED_UP", f.id("k-root")) != 1 {
		t.Fatal("백업·복원 감사 기록")
	}
}
