// Package registry 는 원장 이벤트 수신과 전자등록정보 보존이다(설계서 10.4, FR-6.4).
//
// 종목마다 api.ledger_cursor 에 마지막 처리 블록을 두고, [cursor+1, head-확정깊이] 구간의 로그를
// api.registry_events 에 저장한다. 이벤트 저장과 커서 갱신은 같은 DB 트랜잭션이므로, 작업자가 중간에 죽으면
// 둘 다 반영되지 않고 다음 실행이 같은 구간을 다시 읽는다(빠짐·중복 없음). 같은 로그는
// (ledger_id, tx_hash, log_index) 유니크 키로도 막는다.
package registry

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger"
)

// Source 는 이벤트 조회다(ledger.Ledger 의 일부).
type Source interface {
	HeadBlock(ctx context.Context) (uint64, error)
	Events(ctx context.Context, contract common.Address, from, to uint64) ([]ledger.Event, error)
}

// Worker 는 커서 기반 이벤트 수신 작업자다.
type Worker struct {
	DB       *sql.DB
	LedgerID string
	Source   Source
	// ConfirmDepth 는 확정 깊이다. QBFT 는 즉시 확정이므로 기본 0(설계서 10.4).
	ConfirmDepth uint64
	// MaxBlocks 는 한 번에 읽는 블록 수 상한이다(기본 1000).
	MaxBlocks uint64
	// beforeCommit 은 시험용 훅이다: 이벤트를 넣은 뒤 커밋 전에 불린다(오류를 돌려주면 롤백 = 작업자 중단 흉내).
	beforeCommit func(contract common.Address, inserted int) error
}

// Result 는 한 종목의 한 번 처리 결과다.
type Result struct {
	Contract common.Address
	From, To uint64
	Events   int
}

// RunOnce 는 모든 종목 커서를 한 구간씩 진행한다. 진행한 구간들을 돌려준다.
// 최신 블록 번호는 한 번만 읽어 이번 실행의 모든 종목에 같은 상한을 쓴다.
func (w *Worker) RunOnce(ctx context.Context) ([]Result, error) {
	head, err := w.Source.HeadBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("registry: 최신 블록: %w", err)
	}
	if head < w.ConfirmDepth {
		return nil, nil
	}
	upper := head - w.ConfirmDepth
	rows, err := w.DB.QueryContext(ctx, `SELECT contract_address FROM ledger_cursor WHERE ledger_id = ? ORDER BY contract_address`, w.LedgerID)
	if err != nil {
		return nil, err
	}
	var contracts []common.Address
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			rows.Close()
			return nil, err
		}
		contracts = append(contracts, common.HexToAddress(a))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []Result
	for _, c := range contracts {
		r, err := w.advance(ctx, c, upper)
		if err != nil {
			return out, err
		}
		if r != nil {
			out = append(out, *r)
		}
	}
	return out, nil
}

// advance 는 한 종목의 커서를 잠그고 [last+1, min(upper, last+MaxBlocks)] 를 처리한다.
func (w *Worker) advance(ctx context.Context, contract common.Address, upper uint64) (*Result, error) {
	maxBlocks := w.MaxBlocks
	if maxBlocks == 0 {
		maxBlocks = 1000
	}
	tx, err := w.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var last uint64
	// 같은 커서를 두 작업자가 동시에 처리하지 않게 잠근다(다른 작업자는 건너뛴다).
	err = tx.QueryRowContext(ctx, `SELECT last_block FROM ledger_cursor WHERE ledger_id = ? AND contract_address = ? FOR UPDATE SKIP LOCKED`,
		w.LedgerID, contract.Hex()).Scan(&last)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if last >= upper {
		return nil, nil
	}
	from, to := last+1, min(upper, last+maxBlocks)
	evs, err := w.Source.Events(ctx, contract, from, to)
	if err != nil {
		return nil, fmt.Errorf("registry: %s 이벤트 [%d, %d]: %w", contract.Hex(), from, to, err)
	}
	for _, e := range evs {
		if e.BlockNumber < from || e.BlockNumber > to || e.Raw.Address != contract {
			return nil, fmt.Errorf("registry: 구간 밖 로그(블록 %d, 주소 %s)", e.BlockNumber, e.Raw.Address.Hex())
		}
		payload, err := canonicalJSON(e.Payload)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(e.Raw)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO registry_events (ledger_id, contract_address, block_number, block_hash, block_time, tx_hash, log_index, event, payload_json, raw_log)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, w.LedgerID, contract.Hex(), e.BlockNumber, e.BlockHash[:], e.BlockTime, e.TxHash[:], e.LogIndex, e.Name, payload, string(raw)); err != nil {
			return nil, fmt.Errorf("registry: 이벤트 저장(블록 %d, 로그 %d): %w", e.BlockNumber, e.LogIndex, err)
		}
	}
	if w.beforeCommit != nil {
		if err := w.beforeCommit(contract, len(evs)); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ledger_cursor SET last_block = ? WHERE ledger_id = ? AND contract_address = ? AND last_block = ?`,
		to, w.LedgerID, contract.Hex(), last); err != nil {
		return nil, err
	}
	if len(evs) > 0 {
		if _, err := audit.Append(ctx, tx, audit.Entry{Actor: "apid", Action: "REGISTRY_EVENTS_STORED", Subject: contract.Hex(), Payload: map[string]any{
			"ledger_id": w.LedgerID, "contract_address": contract.Hex(), "from_block": from, "to_block": to, "count": len(evs),
		}}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Result{Contract: contract, From: from, To: to, Events: len(evs)}, nil
}

// canonicalJSON 은 키 사전순·HTML 이스케이프 없는 JSON 이다(바이트를 그대로 보존해 저장).
func canonicalJSON(m map[string]string) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return "", err
	}
	return string(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

// Run 은 주기마다 RunOnce 를 돈다. 구간이 남아 있으면(따라잡는 중) 기다리지 않고 바로 다시 돈다.
func (w *Worker) Run(ctx context.Context, interval time.Duration, logf func(msg string, args ...any)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		res, err := w.RunOnce(ctx)
		if err != nil {
			logf("이벤트 수신 오류", "err", err)
		}
		busy := false
		for _, r := range res {
			if r.To-r.From+1 >= max(w.MaxBlocks, 1000) {
				busy = true
			}
		}
		if busy && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Event 는 저장된 이벤트 조회 결과다(GET /v1/registry-events).
type Event struct {
	ID          uint64            `json:"id"`
	LedgerID    string            `json:"ledger_id"`
	BlockNumber uint64            `json:"block_number"`
	BlockHash   string            `json:"block_hash"`
	BlockTime   time.Time         `json:"block_time"`
	TxHash      string            `json:"tx_hash"`
	LogIndex    uint              `json:"log_index"`
	Contract    string            `json:"contract"`
	Event       string            `json:"event"`
	Payload     map[string]string `json:"payload"`
}

// List 는 원장의 저장된 이벤트를 저장 순서(종목별로 블록·로그 순서)로 돌려준다. contract 가 비어 있지 않으면 그 종목만.
// afterID 보다 큰 id 부터 limit 건(페이지 단위 조회).
func List(ctx context.Context, db *sql.DB, ledgerID, contract string, afterID uint64, limit int) ([]Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT id, ledger_id, contract_address, block_number, block_hash, block_time, tx_hash, log_index, event, payload_json
		FROM registry_events WHERE ledger_id = ? AND id > ?`
	args := []any{ledgerID, afterID}
	if contract != "" {
		q += ` AND contract_address = ?`
		args = append(args, common.HexToAddress(contract).Hex())
	}
	q += ` ORDER BY id LIMIT ?`
	args = append(args, limit)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var bh, th []byte
		var payload string
		if err := rows.Scan(&e.ID, &e.LedgerID, &e.Contract, &e.BlockNumber, &bh, &e.BlockTime, &th, &e.LogIndex, &e.Event, &payload); err != nil {
			return nil, err
		}
		e.BlockHash, e.TxHash = common.BytesToHash(bh).Hex(), common.BytesToHash(th).Hex()
		e.BlockTime = e.BlockTime.UTC()
		if err := json.Unmarshal([]byte(payload), &e.Payload); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
