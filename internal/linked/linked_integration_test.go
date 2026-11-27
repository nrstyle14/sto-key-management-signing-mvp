//go:build integration

// 통합 테스트: 계좌 등록과 원장 등록 요청 기안의 원자성, 원장에 가는 값(이름·계좌번호 없음), 이벤트 반영(보유 수량).
// MySQL(api 스키마)에 api_app 으로 접속한다. 서명 서버 명부는 시험용 대역이다. 실제 원장·HSM 을 거치는
// 계좌 등록 → 발행 → 보유 수량 반영은 test/linked_e2e_test.go 가 확인한다.
package linked

import (
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
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/go-sql-driver/mysql"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/policy"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
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
}

func (d *fakeDir) Policies(context.Context) ([]policy.Policy, error)      { return d.pols, nil }
func (d *fakeDir) Approvers(context.Context) ([]approval.Approver, error) { return d.apprs, nil }
func (d *fakeDir) Keys(context.Context) ([]workflow.KeyInfo, error)       { return nil, nil }

type fx struct {
	db       *sql.DB
	svc      *Service
	s        string
	ledger   string
	code     string
	contract common.Address
}

func randAddr() common.Address {
	var a common.Address
	_, _ = rand.Read(a[:])
	return a
}

func setup(t *testing.T) *fx {
	t.Helper()
	db := apiDB(t)
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	s := hex.EncodeToString(b)
	f := &fx{db: db, s: s, ledger: "it-led-" + s, code: "ITL" + strings.ToUpper(s), contract: randAddr()}
	if _, err := db.Exec(`INSERT INTO securities (issue_code, name, ledger_id, contract_address, circulation_status) VALUES (?, '시험', ?, ?, 'ACTIVE')`,
		f.code, f.ledger, f.contract.Hex()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM holdings WHERE issue_code = ?", f.code)
		_, _ = db.Exec("DELETE FROM accounts WHERE account_no LIKE ?", "IT-%-"+strings.ToUpper(s))
		_, _ = db.Exec("DELETE FROM requests WHERE ledger_id = ?", f.ledger)
		_, _ = db.Exec("DELETE FROM securities WHERE issue_code = ?", f.code)
	})
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := &fakeDir{apprs: []approval.Approver{{ApproverID: "apr-a-01", InstitutionID: "inst-a", Role: "APPROVER", PublicKey: pub, Status: "ACTIVE", Groups: []string{"g"}}}}
	dir.pols = []policy.Policy{{PolicyID: "pol-t", Version: 1, LedgerID: f.ledger, InstitutionID: "inst-a", KeyPurpose: "TRANSFER",
		Body: policy.Body{AllowedFunctions: []string{fnRegister}, MaxAmount: "100", RecipientWhitelist: true, RequiredApprovals: 2, ApproverGroup: "g", GasLimitCap: 500000}}}
	f.svc = &Service{DB: db, WF: &workflow.Service{DB: db, Dir: dir, LedgerID: f.ledger, GasLimit: 300000}, LedgerID: f.ledger}
	return f
}

func (f *fx) no(short string) string { return "IT-" + short + "-" + strings.ToUpper(f.s) }

func (f *fx) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func wfCode(err error) string {
	var e *workflow.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// 계좌 등록은 무작위 주소의 PENDING 계좌와 registerAccount(주소, 기관) 요청을 한 트랜잭션에서 만든다.
// 원장에 가는 intent 에는 권리자 이름·계좌번호가 없다. 실패하면 둘 다 남지 않는다.
func TestRegister(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	holder := "홍길동시험" + f.s
	acc, req, err := f.svc.Register(ctx, RegisterInput{AccountNo: f.no("A"), InstitutionID: "inst-a", HolderName: holder, IssueCode: f.code, DrafterID: "apr-a-01"})
	if err != nil {
		t.Fatal(err)
	}
	if acc.Status != StatusPending || !common.IsHexAddress(acc.OnchainAddress) || common.HexToAddress(acc.OnchainAddress) == (common.Address{}) {
		t.Fatalf("계좌 %+v", acc)
	}
	in, err := intent.Parse(req.Intent)
	if err != nil {
		t.Fatal(err)
	}
	if in.Function != fnRegister || in.Contract != f.contract.Hex() || len(in.Args) != 2 || in.Args[0] != acc.OnchainAddress || in.Args[1] != "inst-a" ||
		in.KeyPurpose != "TRANSFER" || req.Status != workflow.StatusPendingApproval {
		t.Fatalf("등록 요청 intent %s", req.Intent)
	}
	if s := string(req.Intent); strings.Contains(s, holder) || strings.Contains(s, acc.AccountNo) {
		t.Fatalf("원장에 가는 intent 에 권리자 이름·계좌번호가 있다: %s", s)
	}
	var payload string
	if err := f.db.QueryRow(`SELECT payload_json FROM audit_log WHERE action = 'ACCOUNT_CREATED' AND subject = ?`, acc.AccountNo).Scan(&payload); err != nil {
		t.Fatalf("감사 기록: %v", err)
	}
	if strings.Contains(payload, holder) || !strings.Contains(payload, req.RequestID) {
		t.Fatalf("감사 payload %s", payload)
	}
	// 같은 계좌번호: 409, 요청도 남지 않는다
	before := f.count(t, `SELECT COUNT(*) FROM requests WHERE ledger_id = ?`, f.ledger)
	_, _, err = f.svc.Register(ctx, RegisterInput{AccountNo: f.no("A"), InstitutionID: "inst-a", HolderName: "x", IssueCode: f.code, DrafterID: "apr-a-01"})
	if wfCode(err) != CodeExists || f.count(t, `SELECT COUNT(*) FROM requests WHERE ledger_id = ?`, f.ledger) != before {
		t.Fatalf("중복 계좌번호: %v", err)
	}
	// 기안 실패(기관 정책 없음): 계좌도 남지 않는다
	_, _, err = f.svc.Register(ctx, RegisterInput{AccountNo: f.no("B"), InstitutionID: "inst-b", HolderName: "x", IssueCode: f.code, DrafterID: "apr-a-01"})
	if err == nil || f.count(t, `SELECT COUNT(*) FROM accounts WHERE account_no = ?`, f.no("B")) != 0 {
		t.Fatalf("기안 실패 뒤 계좌가 남았다: %v", err)
	}
	// 없는 종목, 형식 오류
	if _, _, err := f.svc.Register(ctx, RegisterInput{AccountNo: f.no("C"), InstitutionID: "inst-a", HolderName: "x", IssueCode: "NOPE" + f.s, DrafterID: "apr-a-01"}); wfCode(err) != CodeSecurityUnknown {
		t.Fatalf("없는 종목: %v", err)
	}
	if _, _, err := f.svc.Register(ctx, RegisterInput{AccountNo: "bad no", InstitutionID: "inst-a", HolderName: "x", IssueCode: f.code, DrafterID: "apr-a-01"}); wfCode(err) != CodeBadRequest {
		t.Fatalf("계좌번호 형식: %v", err)
	}
	// 다른 종목 등록은 요청만 추가한다(같은 주소)
	r2, err := f.svc.AddRegistration(ctx, acc.AccountNo, f.code, "apr-a-01")
	if err != nil {
		t.Fatal(err)
	}
	if in2, _ := intent.Parse(r2.Intent); in2 == nil || in2.Args[0] != acc.OnchainAddress {
		t.Fatalf("추가 등록 intent %s", r2.Intent)
	}
}

func ev(contract common.Address, name string, p map[string]string) ledger.Event {
	return ledger.Event{Name: name, Payload: p, Raw: types.Log{Address: contract}}
}

// 이벤트 반영: 연계장부 계좌의 수량만 바뀌고, 없는 주소·등록되지 않은 종목은 오류 없이 건너뛴다.
func TestApplyEvent(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := randAddr()
	if _, err := f.db.Exec(`INSERT INTO accounts (account_no, institution_id, holder_name, onchain_address, status) VALUES (?, 'inst-a', 'x', ?, 'PENDING')`, f.no("E"), a.Hex()); err != nil {
		t.Fatal(err)
	}
	u := randAddr() // 연계장부에 없는 주소
	apply := func(e ledger.Event) {
		t.Helper()
		tx, err := f.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := ApplyEvent(ctx, tx, f.ledger, e); err != nil {
			_ = tx.Rollback()
			t.Fatalf("%s: %v", e.Name, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	qty := func() string {
		t.Helper()
		h, err := Holdings(ctx, f.db, f.code, f.no("E"))
		if err != nil {
			t.Fatal(err)
		}
		if len(h) == 0 {
			return "-"
		}
		return h[0].Quantity
	}
	status := func() string {
		var s string
		_ = f.db.QueryRow(`SELECT status FROM accounts WHERE account_no = ?`, f.no("E")).Scan(&s)
		return s
	}
	c := f.contract
	apply(ev(c, "AccountRegistered", map[string]string{"account": a.Hex(), "institutionId": "inst-b"}))
	if status() != StatusPending {
		t.Fatal("다른 기관으로 등록된 이벤트가 계좌를 활성화했다")
	}
	apply(ev(c, "AccountRegistered", map[string]string{"account": strings.ToLower(a.Hex()), "institutionId": "inst-a"}))
	if status() != StatusActive {
		t.Fatal("AccountRegistered 뒤에도 PENDING")
	}
	steps := []struct {
		e    ledger.Event
		want string
	}{
		{ev(c, "Issued", map[string]string{"account": a.Hex(), "amount": "100"}), "100"},
		{ev(c, "Issued", map[string]string{"account": u.Hex(), "amount": "50"}), "100"},
		{ev(c, "Transferred", map[string]string{"from": a.Hex(), "to": u.Hex(), "amount": "30", "agent": u.Hex()}), "70"},
		{ev(c, "Transferred", map[string]string{"from": u.Hex(), "to": a.Hex(), "amount": "5", "agent": u.Hex()}), "75"},
		{ev(c, "Redeemed", map[string]string{"account": a.Hex(), "amount": "10"}), "65"},
		{ev(randAddr(), "Issued", map[string]string{"account": a.Hex(), "amount": "1000"}), "65"},                                                // 등록되지 않은 종목
		{ev(c, "CirculationChanged", map[string]string{"active": "false"}), "65"},                                                                // 수량과 무관한 이벤트
		{ev(c, "Issued", map[string]string{"account": a.Hex(), "amount": "1000000000000000000000000000000"}), "1000000000000000000000000000065"}, // 큰 수(DECIMAL)
	}
	for i, s := range steps {
		apply(s.e)
		if got := qty(); got != s.want {
			t.Fatalf("단계 %d %s: 수량 %s (기대 %s)", i, s.e.Name, got, s.want)
		}
	}
	if f.count(t, `SELECT COUNT(*) FROM holdings WHERE issue_code = ?`, f.code) != 1 {
		t.Fatal("연계장부에 없는 주소의 보유 수량 행이 생겼다")
	}
	// 수량 형식 오류는 오류(구간 롤백 → 다시 읽기)
	tx, _ := f.db.Begin()
	defer tx.Rollback()
	if err := ApplyEvent(ctx, tx, f.ledger, ev(c, "Issued", map[string]string{"account": a.Hex(), "amount": "1.5"})); err == nil {
		t.Fatal("소수 수량을 받아들였다")
	}
}
