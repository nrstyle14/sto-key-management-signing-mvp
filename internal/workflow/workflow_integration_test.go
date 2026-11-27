//go:build integration

// 통합 테스트: 요청 상태 기계, 기안·승인, 서명 작업자, nonce 할당(T2.5).
// 호스트에서 MySQL(api 스키마)에 api_app 으로 접속한다. 서명 서버는 호출 횟수를 세는 시험용 대역(stub)이다
// ("서명 요청이 한 번만 나간다"를 서명 서버 쪽에서 센다). 만든 행은 시험이 끝나면 지운다.
package workflow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/go-sql-driver/mysql"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/evmtx"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/policy"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signsvc"
)

func apiDB(t *testing.T) *sql.DB {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	pw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "deploy", "secrets", "api_app_password"))
	if err != nil {
		t.Fatalf("비밀 파일(make up 필요): %v", err)
	}
	c := mysql.NewConfig()
	c.User, c.Passwd, c.Net, c.Addr, c.DBName = "api_app", strings.TrimSpace(string(pw)), "tcp", "127.0.0.1:3306", "api"
	c.ParseTime = true
	db, err := sql.Open("mysql", c.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("DB 접속(make up 필요): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type fakeDir struct {
	pols  []policy.Policy
	apprs []approval.Approver
	keys  []KeyInfo
	down  atomic.Bool
}

func (d *fakeDir) Policies(context.Context) ([]policy.Policy, error)      { return d.pols, nil }
func (d *fakeDir) Approvers(context.Context) ([]approval.Approver, error) { return d.apprs, nil }
func (d *fakeDir) Keys(context.Context) ([]KeyInfo, error) {
	if d.down.Load() {
		return nil, errors.New("서명 서버 응답 없음(시험)")
	}
	return d.keys, nil
}

// stubSigner 는 서명 서버 대역이다. 받은 요청 수와 미서명 tx 바이트를 기록한다.
type stubSigner struct {
	mu       sync.Mutex
	calls    int
	unsigned []string
	delay    time.Duration
	down     atomic.Bool
	reject   *signsvc.Rejection
}

func (s *stubSigner) SignTx(_ context.Context, req signsvc.Request) (*signsvc.Response, error) {
	s.mu.Lock()
	s.calls++
	s.unsigned = append(s.unsigned, req.UnsignedTx)
	s.mu.Unlock()
	time.Sleep(s.delay)
	if s.down.Load() {
		return nil, errors.New("connection refused(시험)")
	}
	if s.reject != nil {
		return nil, s.reject
	}
	return &signsvc.Response{RequestID: "x", KeyID: "k", Address: "0x0", TxHash: "0x" + strings.Repeat("ab", 32), SignedTx: "0x02" + req.UnsignedTx[4:]}, nil
}

type fakeChain struct{ pending uint64 }

func (c fakeChain) PendingNonceAt(context.Context, common.Address) (uint64, error) {
	return c.pending, nil
}

type fx struct {
	db      *sql.DB
	dir     *fakeDir
	svc     *Service
	ledger  string
	privs   map[string]ed25519.PrivateKey
	keyAddr common.Address
}

var whitelisted = common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").Hex()

func setup(t *testing.T) *fx {
	t.Helper()
	db := apiDB(t)
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	s := hex.EncodeToString(b)
	f := &fx{db: db, dir: &fakeDir{}, ledger: "it-ledger-" + s, privs: map[string]ed25519.PrivateKey{}}
	kb := make([]byte, 20)
	_, _ = rand.Read(kb)
	f.keyAddr = common.BytesToAddress(kb)
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE a FROM approvals a JOIN requests r USING (request_id) WHERE r.ledger_id = ?", f.ledger)
		_, _ = db.Exec("DELETE FROM requests WHERE ledger_id = ?", f.ledger)
		_, _ = db.Exec("DELETE FROM nonces WHERE ledger_id = ?", f.ledger)
	})
	for _, id := range []string{"apr-a-01", "apr-a-02", "apr-a-03", "apr-b-01"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		f.privs[id] = priv
		inst, grp := "inst-a", "inst-a-approvers"
		if strings.HasPrefix(id, "apr-b") {
			inst, grp = "inst-b", "inst-b-approvers"
		}
		f.dir.apprs = append(f.dir.apprs, approval.Approver{ApproverID: id, InstitutionID: inst, Role: "APPROVER", PublicKey: pub, Status: "ACTIVE", Groups: []string{grp}})
	}
	f.dir.pols = []policy.Policy{{PolicyID: "pol-a", Version: 1, LedgerID: f.ledger, InstitutionID: "inst-a", KeyPurpose: "ISSUE",
		Body:      policy.Body{AllowedFunctions: []string{"issue(address,uint256)"}, MaxAmount: "100000", RecipientWhitelist: true, RequiredApprovals: 2, ApproverGroup: "inst-a-approvers", GasLimitCap: 500000},
		Whitelist: []string{whitelisted}}}
	f.dir.keys = []KeyInfo{{KeyID: "k-a", LedgerID: f.ledger, InstitutionID: "inst-a", Purpose: "ISSUE", Address: f.keyAddr.Hex(), Status: "ACTIVE"}}
	f.svc = &Service{DB: db, Dir: f.dir, LedgerID: f.ledger, GasLimit: 300000}
	return f
}

func (f *fx) draft(t *testing.T, amount string) *Request {
	t.Helper()
	r, err := f.svc.Draft(context.Background(), DraftInput{InstitutionID: "inst-a", KeyPurpose: "ISSUE",
		Contract: common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3").Hex(), Function: "issue(address,uint256)",
		Args: []string{whitelisted, amount}, DrafterID: "apr-a-01"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *fx) sign(t *testing.T, r *Request, id string, d approval.Decision) approval.Approval {
	t.Helper()
	in, err := intent.Parse(r.Intent)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := in.Hash()
	sig, _ := approval.Sign(f.privs[id], h, d)
	return approval.Approval{ApproverID: id, Decision: d, Signature: hex.EncodeToString(sig)}
}

func (f *fx) approved(t *testing.T) *Request {
	t.Helper()
	r := f.draft(t, "1000")
	ctx := context.Background()
	if _, err := f.svc.AddApproval(ctx, r.RequestID, f.sign(t, r, "apr-a-02", approval.Approve)); err != nil {
		t.Fatal(err)
	}
	r2, err := f.svc.AddApproval(ctx, r.RequestID, f.sign(t, r, "apr-a-03", approval.Approve))
	if err != nil || r2.Status != StatusApproved {
		t.Fatalf("승인 2건 후 상태 %v %v", r2, err)
	}
	return r2
}

func apiCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func (f *fx) worker(s *stubSigner) *SignWorker {
	return &SignWorker{DB: f.db, LedgerID: f.ledger, Dir: f.dir, Signer: s, Chain: fakeChain{pending: 7}, Builder: evmtx.Builder{ChainID: 20261124, GasLimit: 300000, DeployGasLimit: 3000000}}
}

func (f *fx) status(t *testing.T, id string) Status {
	r, err := f.svc.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return r.Status
}

// 같은 요청을 두 작업자가 동시에 처리해도 서명 요청은 한 번만 나간다.
func TestTwoWorkersSendOneSignRequest(t *testing.T) {
	f := setup(t)
	r := f.approved(t)
	stub := &stubSigner{delay: 300 * time.Millisecond}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := f.worker(stub)
			for j := 0; j < 20; j++ {
				if _, err := w.RunOnce(context.Background()); err != nil {
					t.Errorf("작업자 오류: %v", err)
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	if stub.calls != 1 {
		t.Fatalf("서명 요청 %d 회 (기대 1)", stub.calls)
	}
	got, _ := f.svc.Get(context.Background(), r.RequestID)
	if got.Status != StatusSigned || got.RawTx == "" || got.Nonce == nil || *got.Nonce != 7 || got.SignerAddress != f.keyAddr.Hex() {
		t.Fatalf("서명 후 요청: %+v", got)
	}
}

// 서명 서버가 응답하지 않으면 APPROVED 에 머물고, 복구되면 같은 미서명 tx 로 진행된다(NFR-4).
func TestSignerDownStaysApprovedThenProceeds(t *testing.T) {
	f := setup(t)
	r := f.approved(t)
	stub := &stubSigner{}
	stub.down.Store(true)
	w := f.worker(stub)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		_, err := w.RunOnce(ctx)
		if i > 0 && !errors.Is(err, ErrTransient) {
			t.Fatalf("시도 %d: 일시 오류를 기대했다: %v", i, err)
		}
		if s := f.status(t, r.RequestID); s != StatusApproved {
			t.Fatalf("서명 서버 장애 중 상태 %s", s)
		}
	}
	stub.down.Store(false)
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if s := f.status(t, r.RequestID); s != StatusSigned {
		t.Fatalf("복구 후 상태 %s", s)
	}
	if len(stub.unsigned) != 4 {
		t.Fatalf("서명 요청 %d 회 (장애 3 + 복구 1)", len(stub.unsigned))
	}
	for _, u := range stub.unsigned[1:] {
		if u != stub.unsigned[0] {
			t.Fatal("재시도에서 다른 미서명 tx 를 보냈다(nonce 재할당)")
		}
	}
	var next uint64
	if err := f.db.QueryRow("SELECT next_nonce FROM nonces WHERE ledger_id = ?", f.ledger).Scan(&next); err != nil || next != 8 {
		t.Fatalf("nonce 는 한 번만 할당돼야 한다: next=%d %v", next, err)
	}
}

// 키 레지스트리를 못 읽는 동안에도(서명 서버 장애) APPROVED 에 머문다.
func TestDirectoryDownStaysApproved(t *testing.T) {
	f := setup(t)
	r := f.approved(t)
	f.dir.down.Store(true)
	w := f.worker(&stubSigner{})
	if _, err := w.RunOnce(context.Background()); !errors.Is(err, ErrTransient) {
		t.Fatalf("일시 오류 기대: %v", err)
	}
	if s := f.status(t, r.RequestID); s != StatusApproved {
		t.Fatalf("상태 %s", s)
	}
}

func TestSignerRejectionFails(t *testing.T) {
	f := setup(t)
	r := f.approved(t)
	stub := &stubSigner{reject: &signsvc.Rejection{Step: 4, Code: signsvc.CodeKeyFrozen, Msg: "동결"}}
	w := f.worker(stub)
	for i := 0; i < 2; i++ {
		if _, err := w.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := f.svc.Get(context.Background(), r.RequestID)
	if got.Status != StatusFailed || !strings.HasPrefix(got.Error, signsvc.CodeKeyFrozen) {
		t.Fatalf("거부 후 요청: %s %s", got.Status, got.Error)
	}
	// 서명되지 않고 끝난 요청의 nonce 는 돌려받아 다음 요청이 다시 쓴다.
	ctx := context.Background()
	tx, _ := f.db.BeginTx(ctx, nil)
	n, err := AllocateNonce(ctx, tx, fakeChain{pending: 7}, f.ledger, f.keyAddr)
	_ = tx.Rollback()
	if err != nil || got.Nonce == nil || n != *got.Nonce {
		t.Fatalf("다음 할당 nonce %d, 실패한 요청의 nonce %v (%v)", n, got.Nonce, err)
	}
}

func TestDraftAndApprovalChecks(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	// 사전 정책 검사
	_, err := f.svc.Draft(ctx, DraftInput{InstitutionID: "inst-a", KeyPurpose: "ISSUE", Contract: common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3").Hex(),
		Function: "issue(address,uint256)", Args: []string{whitelisted, "100001"}, DrafterID: "apr-a-01"})
	if apiCode(err) != policy.CodeAmountExceeded {
		t.Fatalf("한도 초과 기안: %v", err)
	}
	_, err = f.svc.Draft(ctx, DraftInput{InstitutionID: "inst-a", KeyPurpose: "ISSUE", Contract: common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3").Hex(),
		Function: "issue(address,uint256)", Args: []string{whitelisted, "1"}, DrafterID: "apr-b-01"})
	if apiCode(err) != CodeDrafterUnknown {
		t.Fatalf("다른 기관 기안자: %v", err)
	}
	r := f.draft(t, "10")
	if r.Status != StatusPendingApproval {
		t.Fatalf("기안 상태 %s", r.Status)
	}
	if _, err := f.svc.AddApproval(ctx, r.RequestID, f.sign(t, r, "apr-a-01", approval.Approve)); apiCode(err) != policy.CodeApprovalSelf {
		t.Fatalf("자기 승인: %v", err)
	}
	if _, err := f.svc.AddApproval(ctx, r.RequestID, f.sign(t, r, "apr-b-01", approval.Approve)); apiCode(err) != policy.CodeApprovalInstitution {
		t.Fatalf("다른 기관 승인자: %v", err)
	}
	forged := f.sign(t, r, "apr-a-03", approval.Approve)
	forged.ApproverID = "apr-a-02"
	if _, err := f.svc.AddApproval(ctx, r.RequestID, forged); apiCode(err) != approval.CodeInvalidSignature {
		t.Fatalf("위조 서명: %v", err)
	}
	reject := f.sign(t, r, "apr-a-02", approval.Reject)
	reject.Decision = approval.Approve // 반려 서명을 승인으로 둔갑
	if _, err := f.svc.AddApproval(ctx, r.RequestID, reject); apiCode(err) != approval.CodeInvalidSignature {
		t.Fatalf("반려 서명 둔갑: %v", err)
	}
	if got, err := f.svc.AddApproval(ctx, r.RequestID, f.sign(t, r, "apr-a-02", approval.Approve)); err != nil || got.Status != StatusPendingApproval {
		t.Fatalf("승인 1건: %v %v", got, err)
	}
	if _, err := f.svc.AddApproval(ctx, r.RequestID, f.sign(t, r, "apr-a-02", approval.Approve)); apiCode(err) != policy.CodeApprovalDuplicate {
		t.Fatalf("같은 승인자 두 번: %v", err)
	}
	got, err := f.svc.AddApproval(ctx, r.RequestID, f.sign(t, r, "apr-a-03", approval.Reject))
	if err != nil || got.Status != StatusRejected {
		t.Fatalf("반려 1건 → REJECTED: %v %v", got, err)
	}
	if _, err := f.svc.AddApproval(ctx, r.RequestID, f.sign(t, r, "apr-a-03", approval.Approve)); apiCode(err) != CodeNotPending {
		t.Fatalf("반려된 요청에 승인: %v", err)
	}
}

func TestExpire(t *testing.T) {
	f := setup(t)
	pending := f.draft(t, "10")
	approved := f.approved(t)
	// APPROVED 요청에 nonce 가 할당된 뒤 만료되면 nonce 를 돌려준다.
	w := f.worker(&stubSigner{})
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	n, err := ExpireOnce(context.Background(), f.db, f.ledger, time.Now().Add(2*time.Hour))
	if err != nil || n < 2 {
		t.Fatalf("만료 처리 %d %v", n, err)
	}
	for _, id := range []string{pending.RequestID, approved.RequestID} {
		if s := f.status(t, id); s != StatusExpired {
			t.Fatalf("%s 상태 %s", id, s)
		}
	}
	var next uint64
	if err := f.db.QueryRow("SELECT next_nonce FROM nonces WHERE ledger_id = ?", f.ledger).Scan(&next); err != nil || next != 7 {
		t.Fatalf("만료된 요청의 nonce 반환: next=%d %v", next, err)
	}
}

func TestAllocateNonceSequence(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	addr := common.HexToAddress("0x00000000000000000000000000000000000000cC")
	var got []uint64
	for i, pending := range []uint64{5, 5, 9, 0} { // 체인 pending 이 앞서 나가면 그 값부터
		tx, _ := f.db.BeginTx(ctx, nil)
		n, err := AllocateNonce(ctx, tx, fakeChain{pending: pending}, f.ledger, addr)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		got = append(got, n)
		_ = i
	}
	if !bytes.Equal([]byte{byte(got[0]), byte(got[1]), byte(got[2]), byte(got[3])}, []byte{5, 6, 9, 10}) {
		t.Fatalf("nonce 순서 %v (기대 5 6 9 10)", got)
	}
}
