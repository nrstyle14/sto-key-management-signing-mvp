// Package recon 은 연계장부와 원장의 대사 배치다(설계서 11절, FR-7.2, 요구사항 D-2-3·C-1-2).
//
// 종목마다 연계장부가 반영한 블록(ledger_cursor.last_block)을 기준 시점으로 잡고 세 가지를 비교한다.
//
//	① BALANCE: 연계장부 계좌마다 원장 balanceOf(기준 블록) 와 holdings
//	② TOTAL_SUPPLY: 원장 totalSupply(기준 블록) 와 holdings 합계(초과분·착오기재 감지)
//	③ EVENT_REPLAY: 보존한 registry_events 를 처음부터 다시 계산한 계좌별 수량과 holdings
//	   (재생 결과 연계장부에 없는 주소에 수량이 있으면 UNLINKED_HOLDER 로 함께 보고한다)
//
// 커서·계좌·보유 수량·이벤트는 한 읽기 트랜잭션(REPEATABLE READ 일관 스냅숏)에서 읽는다. 이벤트 수신 작업자는
// 이벤트·커서·보유 수량을 한 트랜잭션에 쓰므로 스냅숏 안에서 셋은 같은 블록까지를 반영한다.
// 기대값(expected)은 원장 쪽(원장 조회 또는 이벤트 재생), 실제값(actual)은 연계장부 쪽이다.
// 결과는 recon_runs·recon_diffs 에 남고, 불일치 종목마다 알람(TOTAL_MISMATCH)과 감사 기록(RECON_RUN)을 남긴다.
package recon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/alarm"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
)

// 비교 종류
const (
	KindBalance     = "BALANCE"
	KindTotalSupply = "TOTAL_SUPPLY"
	KindEventReplay = "EVENT_REPLAY"
	KindUnlinked    = "UNLINKED_HOLDER"
)

// 실행 상태
const (
	StatusRunning  = "RUNNING"
	StatusOK       = "OK"
	StatusMismatch = "MISMATCH"
	StatusError    = "ERROR"
)

// ErrSecurityNotFound 는 대사 범위로 준 종목이 없다는 것이다.
var ErrSecurityNotFound = errors.New("recon: 종목이 없다")

// Chain 은 기준 블록 시점의 원장 조회다(besu.Adapter 가 구현).
type Chain interface {
	BalanceOfAt(ctx context.Context, contract, account common.Address, block uint64) (*big.Int, error)
	TotalSupplyAt(ctx context.Context, contract common.Address, block uint64) (*big.Int, error)
}

// Runner 는 대사 실행기다.
type Runner struct {
	DB       *sql.DB
	LedgerID string
	Chain    Chain
	Alarms   *alarm.Recorder // nil 이면 알람을 내지 않는다
	// AlarmWithin 은 같은 종목 알람을 다시 내지 않는 기간이다(기본 24시간, 주기 실행의 중복 알람 방지).
	// 불일치 자체는 실행마다 recon_runs·recon_diffs 에 남는다.
	AlarmWithin time.Duration
}

// Diff 는 불일치 한 건이다.
type Diff struct {
	IssueCode   string `json:"issue_code"`
	Kind        string `json:"kind"`
	AccountNo   string `json:"account_no,omitempty"`
	Address     string `json:"address,omitempty"`
	Expected    string `json:"expected"` // 원장 쪽
	Actual      string `json:"actual"`   // 연계장부 쪽
	BlockNumber uint64 `json:"block_number"`
}

// Security 는 종목 하나의 대사 요약이다.
type Security struct {
	IssueCode   string `json:"issue_code"`
	Contract    string `json:"contract_address"`
	BlockNumber uint64 `json:"block_number"`
	TotalSupply string `json:"total_supply"`
	Holdings    string `json:"holdings_total"`
	Accounts    int    `json:"accounts"`
	Diffs       int    `json:"diffs"`
}

// Run 은 대사 실행 한 번의 결과다.
type Run struct {
	RunID      uint64     `json:"run_id"`
	Scope      string     `json:"scope,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Status     string     `json:"status"`
	DiffCount  int        `json:"diff_count"`
	Error      string     `json:"error,omitempty"`
	Securities []Security `json:"securities,omitempty"` // 실행 응답에만 있다
	Diffs      []Diff     `json:"diffs"`
}

type account struct{ no, addr string }

type snapshot struct {
	block    uint64
	accounts []account
	holdings map[string]*big.Int // account_no → 수량
	replay   map[string]*big.Int // 주소 → 이벤트 재생 수량
}

// Run 은 대사를 실행한다. scope 가 비어 있지 않으면 그 종목만. 원장 조회가 실패하면 실행을 ERROR 로 남기고 오류를 돌려준다.
func (r *Runner) Run(ctx context.Context, scope string) (*Run, error) {
	type sec struct{ code, contract string }
	q := `SELECT issue_code, contract_address FROM securities WHERE ledger_id = ? AND contract_address IS NOT NULL`
	args := []any{r.LedgerID}
	if scope != "" {
		q += ` AND issue_code = ?`
		args = append(args, scope)
	}
	rows, err := r.DB.QueryContext(ctx, q+` ORDER BY issue_code`, args...)
	if err != nil {
		return nil, err
	}
	var secs []sec
	for rows.Next() {
		var s sec
		if err := rows.Scan(&s.code, &s.contract); err != nil {
			rows.Close()
			return nil, err
		}
		secs = append(secs, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if scope != "" && len(secs) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrSecurityNotFound, scope)
	}
	var scopeArg any
	if scope != "" {
		scopeArg = scope
	}
	res, err := r.DB.ExecContext(ctx, `INSERT INTO recon_runs (scope, status) VALUES (?, ?)`, scopeArg, StatusRunning)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	run := &Run{RunID: uint64(id), Scope: scope, StartedAt: time.Now().UTC(), Status: StatusRunning, Diffs: []Diff{}}
	// 한 종목의 원장 조회가 실패해도 나머지 종목은 비교한다. 실패가 하나라도 있으면 실행은 ERROR 다.
	var errs []error
	for _, s := range secs {
		sum, diffs, err := r.compare(ctx, s.code, common.HexToAddress(s.contract))
		if err != nil {
			errs = append(errs, fmt.Errorf("종목 %s: %w", s.code, err))
			continue
		}
		run.Securities = append(run.Securities, *sum)
		run.Diffs = append(run.Diffs, diffs...)
	}
	return run, r.finish(ctx, run, errors.Join(errs...))
}

// finish 는 불일치를 저장하고 실행을 닫는다. 감사 기록과 알람을 남긴다.
func (r *Runner) finish(ctx context.Context, run *Run, runErr error) error {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return errors.Join(runErr, err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, d := range run.Diffs {
		var acc, addr any
		if d.AccountNo != "" {
			acc = d.AccountNo
		}
		if d.Address != "" {
			addr = d.Address
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO recon_diffs (run_id, issue_code, kind, account_no, address, expected, actual, block_number)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, run.RunID, d.IssueCode, d.Kind, acc, addr, d.Expected, d.Actual, d.BlockNumber); err != nil {
			return errors.Join(runErr, err)
		}
	}
	run.DiffCount = len(run.Diffs)
	run.Status = StatusOK
	var errText any
	switch {
	case runErr != nil:
		run.Status, run.Error = StatusError, runErr.Error()
		errText = run.Error
	case run.DiffCount > 0:
		run.Status = StatusMismatch
	}
	if _, err := tx.ExecContext(ctx, `UPDATE recon_runs SET status = ?, diff_count = ?, error = ?, finished_at = CURRENT_TIMESTAMP(6) WHERE run_id = ?`,
		run.Status, run.DiffCount, errText, run.RunID); err != nil {
		return errors.Join(runErr, err)
	}
	byCode := map[string][]string{}
	for _, d := range run.Diffs {
		byCode[d.IssueCode] = append(byCode[d.IssueCode], d.Kind)
	}
	codes := make([]string, 0, len(byCode))
	for c := range byCode {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	if _, err := audit.Append(ctx, tx, audit.Entry{Actor: "apid", Action: "RECON_RUN", Subject: fmt.Sprintf("recon-%d", run.RunID), Payload: map[string]any{
		"run_id": run.RunID, "scope": run.Scope, "status": run.Status, "count": run.DiffCount, "issue_code": codes,
	}}); err != nil {
		return errors.Join(runErr, err)
	}
	if err := tx.Commit(); err != nil {
		return errors.Join(runErr, err)
	}
	now := time.Now().UTC()
	run.FinishedAt = &now
	if r.Alarms != nil {
		within := r.AlarmWithin
		if within == 0 {
			within = 24 * time.Hour
		}
		for _, c := range codes {
			if _, err := r.Alarms.Raise(ctx, alarm.RuleTotalMismatch, c, map[string]any{"run_id": run.RunID, "issue_code": c,
				"diffs": len(byCode[c]), "kinds": byCode[c]}, within); err != nil {
				return errors.Join(runErr, err)
			}
		}
	}
	return runErr
}

// read 는 한 종목의 커서·계좌·보유 수량·이벤트 재생을 한 일관 스냅숏에서 읽는다.
func (r *Runner) read(ctx context.Context, code string, contract common.Address) (*snapshot, error) {
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	s := &snapshot{holdings: map[string]*big.Int{}, replay: map[string]*big.Int{}}
	if err := tx.QueryRowContext(ctx, `SELECT last_block FROM ledger_cursor WHERE ledger_id = ? AND contract_address = ?`, r.LedgerID, contract.Hex()).Scan(&s.block); err != nil {
		return nil, fmt.Errorf("이벤트 커서: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT account_no, onchain_address FROM accounts ORDER BY account_no`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a account
		if err := rows.Scan(&a.no, &a.addr); err != nil {
			rows.Close()
			return nil, err
		}
		s.accounts = append(s.accounts, a)
	}
	rows.Close()
	if rows, err = tx.QueryContext(ctx, `SELECT account_no, CAST(quantity AS CHAR) FROM holdings WHERE issue_code = ?`, code); err != nil {
		return nil, err
	}
	for rows.Next() {
		var no, q string
		if err := rows.Scan(&no, &q); err != nil {
			rows.Close()
			return nil, err
		}
		v, ok := new(big.Int).SetString(q, 10)
		if !ok {
			rows.Close()
			return nil, fmt.Errorf("보유 수량 %q 형식", q)
		}
		s.holdings[no] = v
	}
	rows.Close()
	if rows, err = tx.QueryContext(ctx, `SELECT event, payload_json FROM registry_events WHERE ledger_id = ? AND contract_address = ?
		AND event IN ('Issued', 'Redeemed', 'Transferred') ORDER BY block_number, log_index`, r.LedgerID, contract.Hex()); err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name, payload string
		if err := rows.Scan(&name, &payload); err != nil {
			return nil, err
		}
		if err := s.applyReplay(name, payload); err != nil {
			return nil, err
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return s, tx.Commit()
}

func (s *snapshot) applyReplay(name, payload string) error {
	p, err := parsePayload(payload)
	if err != nil {
		return err
	}
	amt, ok := new(big.Int).SetString(p["amount"], 10)
	if !ok || amt.Sign() < 0 {
		return fmt.Errorf("이벤트 %s 수량 %q", name, p["amount"])
	}
	move := func(addr string, v *big.Int) {
		a := common.HexToAddress(addr).Hex()
		if s.replay[a] == nil {
			s.replay[a] = new(big.Int)
		}
		s.replay[a].Add(s.replay[a], v)
	}
	neg := new(big.Int).Neg(amt)
	switch name {
	case "Issued":
		move(p["account"], amt)
	case "Redeemed":
		move(p["account"], neg)
	case "Transferred":
		move(p["from"], neg)
		move(p["to"], amt)
	}
	return nil
}

func zeroIfNil(v *big.Int) *big.Int {
	if v == nil {
		return new(big.Int)
	}
	return v
}

// compare 는 한 종목의 세 가지 비교다.
func (r *Runner) compare(ctx context.Context, code string, contract common.Address) (*Security, []Diff, error) {
	s, err := r.read(ctx, code, contract)
	if err != nil {
		return nil, nil, err
	}
	sum := &Security{IssueCode: code, Contract: contract.Hex(), BlockNumber: s.block, Accounts: len(s.accounts)}
	var diffs []Diff
	add := func(kind, no, addr string, expected, actual *big.Int) {
		if expected.Cmp(actual) != 0 {
			diffs = append(diffs, Diff{IssueCode: code, Kind: kind, AccountNo: no, Address: addr, Expected: expected.String(),
				Actual: actual.String(), BlockNumber: s.block})
		}
	}
	total := new(big.Int)
	for _, q := range s.holdings {
		total.Add(total, q)
	}
	// ① 계좌별 원장 잔고
	linked := map[string]bool{}
	for _, a := range s.accounts {
		linked[common.HexToAddress(a.addr).Hex()] = true
		bal, err := r.Chain.BalanceOfAt(ctx, contract, common.HexToAddress(a.addr), s.block)
		if err != nil {
			return nil, nil, fmt.Errorf("balanceOf(%s, 블록 %d): %w", a.addr, s.block, err)
		}
		add(KindBalance, a.no, a.addr, bal, zeroIfNil(s.holdings[a.no]))
	}
	// ② 총발행량
	ts, err := r.Chain.TotalSupplyAt(ctx, contract, s.block)
	if err != nil {
		return nil, nil, fmt.Errorf("totalSupply(블록 %d): %w", s.block, err)
	}
	add(KindTotalSupply, "", "", ts, total)
	// ③ 이벤트 재생
	for _, a := range s.accounts {
		add(KindEventReplay, a.no, a.addr, zeroIfNil(s.replay[common.HexToAddress(a.addr).Hex()]), zeroIfNil(s.holdings[a.no]))
	}
	addrs := make([]string, 0, len(s.replay))
	for a := range s.replay {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	for _, a := range addrs {
		if !linked[a] {
			add(KindUnlinked, "", a, s.replay[a], new(big.Int))
		}
	}
	sum.TotalSupply, sum.Holdings, sum.Diffs = ts.String(), total.String(), len(diffs)
	return sum, diffs, nil
}

// List 는 최근 실행 목록이다(불일치 상세 없음).
func List(ctx context.Context, db *sql.DB, limit int) ([]Run, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := db.QueryContext(ctx, `SELECT run_id, COALESCE(scope, ''), started_at, finished_at, status, diff_count, COALESCE(error, '')
		FROM recon_runs ORDER BY run_id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		var r Run
		var fin sql.NullTime
		if err := rows.Scan(&r.RunID, &r.Scope, &r.StartedAt, &fin, &r.Status, &r.DiffCount, &r.Error); err != nil {
			return nil, err
		}
		if fin.Valid {
			t := fin.Time.UTC()
			r.FinishedAt = &t
		}
		r.StartedAt = r.StartedAt.UTC()
		r.Diffs = []Diff{}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get 은 실행 하나와 불일치 상세다. id 가 0 이면 가장 최근 실행이다.
func Get(ctx context.Context, db *sql.DB, id uint64) (*Run, error) {
	q := `SELECT run_id, COALESCE(scope, ''), started_at, finished_at, status, diff_count, COALESCE(error, '') FROM recon_runs `
	var row *sql.Row
	if id == 0 {
		row = db.QueryRowContext(ctx, q+`ORDER BY run_id DESC LIMIT 1`)
	} else {
		row = db.QueryRowContext(ctx, q+`WHERE run_id = ?`, id)
	}
	var r Run
	var fin sql.NullTime
	if err := row.Scan(&r.RunID, &r.Scope, &r.StartedAt, &fin, &r.Status, &r.DiffCount, &r.Error); err != nil {
		return nil, err
	}
	if fin.Valid {
		t := fin.Time.UTC()
		r.FinishedAt = &t
	}
	r.StartedAt = r.StartedAt.UTC()
	rows, err := db.QueryContext(ctx, `SELECT issue_code, kind, COALESCE(account_no, ''), COALESCE(address, ''), CAST(expected AS CHAR), CAST(actual AS CHAR),
		COALESCE(block_number, 0) FROM recon_diffs WHERE run_id = ? ORDER BY id`, r.RunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	r.Diffs = []Diff{}
	for rows.Next() {
		var d Diff
		if err := rows.Scan(&d.IssueCode, &d.Kind, &d.AccountNo, &d.Address, &d.Expected, &d.Actual, &d.BlockNumber); err != nil {
			return nil, err
		}
		r.Diffs = append(r.Diffs, d)
	}
	return &r, rows.Err()
}

func parsePayload(s string) (map[string]string, error) {
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, fmt.Errorf("이벤트 payload: %w", err)
	}
	return m, nil
}
