package workflow

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger"
)

// 원장 제출 실패 코드(요청 error 와 감사 기록)
const (
	CodeLedgerRejected      = "LEDGER_REJECTED"
	CodeLedgerNonceConflict = "LEDGER_NONCE_CONFLICT"
)

// Submitter 는 서명된 tx 를 원장에 제출한다(ledger.Ledger.Submit).
type Submitter interface {
	Submit(ctx context.Context, raw []byte) (ledger.TxHash, error)
}

// SubmitWorker 는 SIGNED 요청의 서명된 tx 를 원장에 제출한다(설계서 5.4, T3.2).
//   - 요청 행은 `FOR UPDATE SKIP LOCKED` 로 잡는다. 제출은 저장된 같은 서명된 tx 바이트로만 한다(다시 서명하지 않음, D-6).
//   - 노드가 받으면(이미 알려진 tx·이미 확정된 tx 포함) SUBMITTED 와 제출 시각을 남긴다.
//   - 노드가 영구 거부하면(nonce 충돌, 형식 위반) FAILED. 연결 실패 같은 일시 오류는 SIGNED 로 남겨 다음 주기에 다시 보낸다.
type SubmitWorker struct {
	DB       *sql.DB
	LedgerID string
	Ledger   Submitter
	Now      func() time.Time
}

func (w *SubmitWorker) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}

// RunOnce 는 SIGNED 요청 하나를 제출한다. 처리한 요청이 있으면 true 다.
func (w *SubmitWorker) RunOnce(ctx context.Context) (bool, error) {
	tx, err := w.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var id string
	var raw, stored []byte
	err = tx.QueryRowContext(ctx, `SELECT request_id, raw_tx, tx_hash FROM requests
		WHERE status = 'SIGNED' AND ledger_id = ? ORDER BY updated_at LIMIT 1 FOR UPDATE SKIP LOCKED`, w.LedgerID).Scan(&id, &raw, &stored)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	h, err := w.Ledger.Submit(ctx, raw)
	switch {
	case err == nil:
		if len(stored) == 32 && common.BytesToHash(stored) != h {
			return true, fmt.Errorf("workflow: 제출한 tx 해시 %s 가 저장된 값과 다르다(%s)", h.Hex(), id)
		}
		if err := Transition(ctx, tx, id, StatusSigned, StatusSubmitted, map[string]any{"submitted_at": w.now()}); err != nil {
			return true, err
		}
		if _, err := audit.Append(ctx, tx, audit.Entry{Actor: "apid", Action: "REQUEST_LEDGER_SUBMITTED", Subject: id,
			Payload: map[string]any{"request_id": id, "status": string(StatusSubmitted), "tx_hash": h.Hex()}}); err != nil {
			return true, err
		}
		return true, tx.Commit()
	case errors.Is(err, ledger.ErrNonceConflict), errors.Is(err, ledger.ErrRejected):
		code := CodeLedgerRejected
		if errors.Is(err, ledger.ErrNonceConflict) {
			code = CodeLedgerNonceConflict
		}
		msg := truncate(err.Error(), 300)
		if err := Transition(ctx, tx, id, StatusSigned, StatusFailed, map[string]any{"error": code + ": " + msg}); err != nil {
			return true, err
		}
		if _, err := audit.Append(ctx, tx, audit.Entry{Actor: "apid", Action: "REQUEST_FAILED", Subject: id,
			Payload: map[string]any{"request_id": id, "status": string(StatusFailed), "code": code, "reason": msg}}); err != nil {
			return true, err
		}
		return true, tx.Commit()
	default:
		_ = tx.Rollback()
		_, _ = w.DB.ExecContext(ctx, `UPDATE requests SET updated_at = CURRENT_TIMESTAMP(6) WHERE request_id = ? AND status = 'SIGNED'`, id)
		return true, fmt.Errorf("%w: 원장 제출: %v", ErrTransient, err)
	}
}

// Run 은 주기마다 SIGNED 요청을 제출한다. ctx 가 끝나면 멈춘다.
func (w *SubmitWorker) Run(ctx context.Context, interval time.Duration, logf func(msg string, args ...any)) {
	runLoop(ctx, interval, logf, "제출 작업 오류", w.RunOnce)
}

// runLoop 는 주기마다 step 을 여러 번 돌린다. 일시 오류는 한 주기에 최대 3번까지 넘기고 다음 요청을 진행한다.
func runLoop(ctx context.Context, interval time.Duration, logf func(msg string, args ...any), label string, step func(context.Context) (bool, error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		transient := 0
		for i := 0; i < 50; i++ {
			did, err := step(ctx)
			if err != nil {
				logf(label, "err", err)
				if errors.Is(err, ErrTransient) && transient < 3 {
					transient++
					continue
				}
				break
			}
			if !did {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
