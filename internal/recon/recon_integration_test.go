//go:build integration

// 통합 테스트: 대사의 세 가지 비교(계좌 잔고, 총발행량, 이벤트 재생)와 결과·알람·감사 기록.
// MySQL(api 스키마)에 api_app 으로 접속한다. 원장 조회는 시험용 대역(fakeChain)이다. 실제 Besu 를 쓰는 대사는
// test/linked_e2e_test.go 의 TestReconDetectsTamperedHolding 이 확인한다.
package recon

import (
	"context"
	"crypto/rand"
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

	"github.com/ethereum/go-ethereum/common"
	"github.com/go-sql-driver/mysql"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/alarm"
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

// fakeChain 은 블록별 잔고·총량 대역이다. 요청된 블록을 기록한다.
type fakeChain struct {
	mu     sync.Mutex
	bal    map[common.Address]int64
	total  int64
	fail   bool
	blocks map[uint64]bool
}

func (c *fakeChain) BalanceOfAt(_ context.Context, _, a common.Address, b uint64) (*big.Int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blocks[b] = true
	if c.fail {
		return nil, errors.New("RPC 응답 없음(시험)")
	}
	return big.NewInt(c.bal[a]), nil
}

func (c *fakeChain) TotalSupplyAt(_ context.Context, _ common.Address, b uint64) (*big.Int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blocks[b] = true
	return big.NewInt(c.total), nil
}

type fx struct {
	db       *sql.DB
	run      *Runner
	chain    *fakeChain
	s, code  string
	ledger   string
	contract common.Address
	a, b, u  common.Address // a·b 연계장부 계좌, u 연계장부 밖
}

func randAddr() common.Address {
	var a common.Address
	_, _ = rand.Read(a[:])
	return a
}

func setup(t *testing.T) *fx {
	t.Helper()
	db := apiDB(t)
	bs := make([]byte, 4)
	_, _ = rand.Read(bs)
	s := hex.EncodeToString(bs)
	f := &fx{db: db, s: s, code: "ITR" + strings.ToUpper(s), ledger: "it-rec-" + s, contract: randAddr(), a: randAddr(), b: randAddr(), u: randAddr()}
	f.chain = &fakeChain{bal: map[common.Address]int64{}, blocks: map[uint64]bool{}}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO securities (issue_code, name, ledger_id, contract_address, circulation_status) VALUES (?, '대사 시험', ?, ?, 'ACTIVE')`, f.code, f.ledger, f.contract.Hex())
	exec(`INSERT INTO ledger_cursor (ledger_id, contract_address, last_block) VALUES (?, ?, 120)`, f.ledger, f.contract.Hex())
	for _, x := range []struct {
		no   string
		addr common.Address
	}{{f.no("A"), f.a}, {f.no("B"), f.b}} {
		exec(`INSERT INTO accounts (account_no, institution_id, holder_name, onchain_address, status) VALUES (?, 'inst-a', 'x', ?, 'ACTIVE')`, x.no, x.addr.Hex())
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE d FROM recon_diffs d WHERE d.issue_code = ?`, f.code)
		_, _ = db.Exec(`DELETE FROM recon_runs WHERE scope = ?`, f.code)
		_, _ = db.Exec(`DELETE FROM holdings WHERE issue_code = ?`, f.code)
		_, _ = db.Exec(`DELETE FROM accounts WHERE account_no LIKE ?`, "IT-%-"+strings.ToUpper(s))
		_, _ = db.Exec(`DELETE FROM registry_events WHERE ledger_id = ?`, f.ledger)
		_, _ = db.Exec(`DELETE FROM ledger_cursor WHERE ledger_id = ?`, f.ledger)
		_, _ = db.Exec(`DELETE FROM securities WHERE issue_code = ?`, f.code)
		_, _ = db.Exec(`DELETE FROM alarms WHERE subject = ?`, f.code)
	})
	// 원장: A 발행 700 → A→B 200 → A→U 50 (U 는 연계장부 밖). 결과 A 450, B 200, U 50, 총 700
	n := 0
	event := func(name, payload string) {
		n++
		tx := make([]byte, 32)
		_, _ = rand.Read(tx)
		exec(`INSERT INTO registry_events (ledger_id, contract_address, block_number, block_hash, block_time, tx_hash, log_index, event, payload_json, raw_log)
			VALUES (?, ?, ?, ?, UTC_TIMESTAMP(6), ?, 0, ?, ?, '{}')`, f.ledger, f.contract.Hex(), 100+n, make([]byte, 32), tx, name, payload)
	}
	event("Issued", fmt.Sprintf(`{"account":"%s","amount":"700"}`, f.a.Hex()))
	event("Transferred", fmt.Sprintf(`{"agent":"%s","amount":"200","from":"%s","to":"%s"}`, f.u.Hex(), f.a.Hex(), f.b.Hex()))
	event("Transferred", fmt.Sprintf(`{"agent":"%s","amount":"50","from":"%s","to":"%s"}`, f.u.Hex(), f.a.Hex(), f.u.Hex()))
	event("RoleGranted", `{"role":"x"}`)
	f.chain.bal[f.a], f.chain.bal[f.b], f.chain.bal[f.u], f.chain.total = 450, 200, 50, 700
	exec(`INSERT INTO holdings (account_no, issue_code, quantity) VALUES (?, ?, 450), (?, ?, 200)`, f.no("A"), f.code, f.no("B"), f.code)
	f.run = &Runner{DB: db, LedgerID: f.ledger, Chain: f.chain, Alarms: &alarm.Recorder{DB: db}}
	return f
}

func (f *fx) no(short string) string { return "IT-" + short + "-" + strings.ToUpper(f.s) }

func kinds(ds []Diff) string {
	var out []string
	for _, d := range ds {
		out = append(out, fmt.Sprintf("%s/%s/%s/%s/%s", d.Kind, d.AccountNo, d.Address, d.Expected, d.Actual))
	}
	return strings.Join(out, " ")
}

// 연계장부 밖 주소(U)에 수량이 있으면 그 주소(UNLINKED_HOLDER)와 총발행량 차이만 보고한다. 계좌 잔고는 일치한다.
// 연계장부 수량을 바꾸면 그 계좌의 잔고·재생 차이와 총량 차이를 정확히 보고하고 알람·감사 기록을 남긴다.
func TestReconCompare(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	r, err := f.run.Run(ctx, f.code)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("TOTAL_SUPPLY///700/650 UNLINKED_HOLDER//%s/50/0", f.u.Hex())
	if r.Status != StatusMismatch || kinds(r.Diffs) != want || !f.chain.blocks[120] || len(f.chain.blocks) != 1 {
		t.Fatalf("첫 대사 %s: %s (블록 %v)", r.Status, kinds(r.Diffs), f.chain.blocks)
	}
	// U 를 연계장부에 넣고 수량을 맞추면 일치
	if _, err := f.db.Exec(`INSERT INTO accounts (account_no, institution_id, holder_name, onchain_address, status) VALUES (?, 'inst-a', 'x', ?, 'ACTIVE')`, f.no("U"), f.u.Hex()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO holdings (account_no, issue_code, quantity) VALUES (?, ?, 50)`, f.no("U"), f.code); err != nil {
		t.Fatal(err)
	}
	if r, err = f.run.Run(ctx, f.code); err != nil || r.Status != StatusOK || len(r.Diffs) != 0 {
		t.Fatalf("일치 대사: %v %s %s", err, r.Status, kinds(r.Diffs))
	}
	// 연계장부 수량 임의 변경(B 200 → 207)
	if _, err := f.db.Exec(`UPDATE holdings SET quantity = 207 WHERE account_no = ? AND issue_code = ?`, f.no("B"), f.code); err != nil {
		t.Fatal(err)
	}
	r, err = f.run.Run(ctx, f.code)
	if err != nil {
		t.Fatal(err)
	}
	b := f.no("B")
	want = fmt.Sprintf("BALANCE/%s/%s/200/207 TOTAL_SUPPLY///700/707 EVENT_REPLAY/%s/%s/200/207", b, f.b.Hex(), b, f.b.Hex())
	if r.Status != StatusMismatch || kinds(r.Diffs) != want {
		t.Fatalf("변경 뒤 대사: %s", kinds(r.Diffs))
	}
	got, err := Get(ctx, f.db, r.RunID)
	if err != nil || got.DiffCount != 3 || kinds(got.Diffs) != want || got.Diffs[0].BlockNumber != 120 {
		t.Fatalf("저장된 결과: %v %+v", err, got)
	}
	var alarms, audits int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM alarms WHERE rule = ? AND subject = ?`, alarm.RuleTotalMismatch, f.code).Scan(&alarms)
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'RECON_RUN' AND subject = ?`, fmt.Sprintf("recon-%d", r.RunID)).Scan(&audits)
	if alarms != 1 || audits != 1 { // 첫 대사의 알람 뒤 10분 안이라 두 번째 불일치는 알람을 다시 내지 않는다
		t.Fatalf("알람 %d, 감사 %d", alarms, audits)
	}
}

// 원장 조회가 실패하면 실행은 ERROR 로 남는다. 없는 종목은 실행을 만들지 않는다.
func TestReconErrors(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.chain.fail = true
	r, err := f.run.Run(ctx, f.code)
	if err == nil || r == nil || r.Status != StatusError {
		t.Fatalf("원장 실패: %v %+v", err, r)
	}
	got, err := Get(ctx, f.db, r.RunID)
	if err != nil || got.Status != StatusError || got.Error == "" {
		t.Fatalf("저장된 ERROR 실행: %v %+v", err, got)
	}
	if _, err := f.run.Run(ctx, "NOPE"+f.s); !errors.Is(err, ErrSecurityNotFound) {
		t.Fatalf("없는 종목: %v", err)
	}
}
