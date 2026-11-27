package workflow

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger"
)

// 원장 확정 실패 코드
const (
	CodeLedgerReverted = "LEDGER_REVERTED"
	CodeLedgerTimeout  = "LEDGER_TIMEOUT"
)

// ReceiptSource 는 영수증 조회와 재제출이다(ledger.Ledger 의 일부).
type ReceiptSource interface {
	Submitter
	Receipt(ctx context.Context, h ledger.TxHash) (*ledger.Receipt, error)
}

// ReceiptWorker 는 SUBMITTED 요청을 영수증 기준으로 확정한다(설계서 5.4, T3.3·T3.4).
//   - 영수증 status 1 이면 CONFIRMED, 0 이면 FAILED(LEDGER_REVERTED). 확정 블록을 남긴다.
//   - 배포 요청이 확정되면 종목(securities)과 이벤트 수신 커서(ledger_cursor)를 같은 트랜잭션으로 등록한다.
//   - 영수증이 없으면 ResubmitAfter 마다 같은 서명된 tx 를 다시 제출한다(풀에서 빠진 경우).
//     Timeout 이 지나도 없으면 마지막으로 영수증을 다시 확인한 뒤 FAILED(LEDGER_TIMEOUT).
type ReceiptWorker struct {
	DB            *sql.DB
	LedgerID      string
	Ledger        ReceiptSource
	ResubmitAfter time.Duration // 기본 30초
	Timeout       time.Duration // 기본 10분
	Now           func() time.Time
	// OnConfirmed 는 확정 직후(커밋 뒤) 부른다(이벤트 수신 작업자 깨우기 등).
	OnConfirmed func(ctx context.Context, r *Request)
}

func (w *ReceiptWorker) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}

// RunOnce 는 SUBMITTED 요청 하나를 확인한다. 처리할 요청이 있었으면 true 다.
func (w *ReceiptWorker) RunOnce(ctx context.Context) (bool, error) {
	resubmit, timeout := w.ResubmitAfter, w.Timeout
	if resubmit <= 0 {
		resubmit = 30 * time.Second
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	tx, err := w.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var id, typ, intentJSON string
	var raw, txHash []byte
	var submitted, updated time.Time
	// 마지막 확인에서 1초 이상 지난 요청만 잡는다(한 주기에 같은 요청을 거듭 확인하지 않게).
	err = tx.QueryRowContext(ctx, `SELECT request_id, type, intent_json, raw_tx, tx_hash, submitted_at, updated_at FROM requests
		WHERE status = 'SUBMITTED' AND ledger_id = ? AND updated_at <= CURRENT_TIMESTAMP(6) - INTERVAL 1 SECOND
		ORDER BY updated_at LIMIT 1 FOR UPDATE SKIP LOCKED`, w.LedgerID).
		Scan(&id, &typ, &intentJSON, &raw, &txHash, &submitted, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	h := common.BytesToHash(txHash)
	rc, err := w.Ledger.Receipt(ctx, h)
	switch {
	case err == nil:
		if err := w.settle(ctx, tx, id, typ, intentJSON, rc); err != nil {
			return true, err
		}
		if err := tx.Commit(); err != nil {
			return true, err
		}
		if w.OnConfirmed != nil && rc.Succeeded() {
			if r, gerr := (&Service{DB: w.DB}).Get(ctx, id); gerr == nil {
				w.OnConfirmed(ctx, r)
			}
		}
		return true, nil
	case !errors.Is(err, ledger.ErrReceiptNotFound):
		_ = tx.Rollback()
		w.touch(ctx, id)
		return true, fmt.Errorf("%w: 영수증 조회: %v", ErrTransient, err)
	}

	now := w.now()
	if now.Sub(submitted.UTC()) >= timeout {
		if err := w.fail(ctx, tx, id, CodeLedgerTimeout, fmt.Sprintf("제출 후 %s 동안 영수증 없음", timeout), nil); err != nil {
			return true, err
		}
		return true, tx.Commit()
	}
	// 재제출은 제출 시각부터 resubmit 간격마다 한 번이다. updated_at 은 마지막 확인 시각이다.
	sub := submitted.UTC()
	if now.Sub(sub)/resubmit <= updated.UTC().Sub(sub)/resubmit || now.Sub(sub) < resubmit {
		_ = tx.Rollback()
		w.touch(ctx, id)
		return true, nil // 아직 기다린다(대기열 뒤로)
	}
	// 풀에서 빠졌을 수 있으므로 같은 서명된 tx 를 다시 보낸다(다시 서명하지 않음).
	if _, err := w.Ledger.Submit(ctx, raw); err != nil {
		if errors.Is(err, ledger.ErrNonceConflict) || errors.Is(err, ledger.ErrRejected) {
			// nonce 가 다른 tx 로 쓰였거나 노드가 거부: 이 tx 는 반영될 수 없다. 영수증을 마지막으로 확인한다.
			if rc, rerr := w.Ledger.Receipt(ctx, h); rerr == nil {
				if err := w.settle(ctx, tx, id, typ, intentJSON, rc); err != nil {
					return true, err
				}
				return true, tx.Commit()
			}
			code := CodeLedgerRejected
			if errors.Is(err, ledger.ErrNonceConflict) {
				code = CodeLedgerNonceConflict
			}
			if err := w.fail(ctx, tx, id, code, truncate(err.Error(), 300), nil); err != nil {
				return true, err
			}
			return true, tx.Commit()
		}
		_ = tx.Rollback()
		w.touch(ctx, id)
		return true, fmt.Errorf("%w: 재제출: %v", ErrTransient, err)
	}
	_ = tx.Rollback()
	w.touch(ctx, id)
	return true, nil
}

// touch 는 요청을 대기열 뒤로 보낸다(재제출 간격의 기준 시각이기도 하다).
func (w *ReceiptWorker) touch(ctx context.Context, id string) {
	_, _ = w.DB.ExecContext(ctx, `UPDATE requests SET updated_at = CURRENT_TIMESTAMP(6) WHERE request_id = ? AND status = 'SUBMITTED'`, id)
}

func (w *ReceiptWorker) settle(ctx context.Context, tx *sql.Tx, id, typ, intentJSON string, rc *ledger.Receipt) error {
	if !rc.Succeeded() {
		return w.fail(ctx, tx, id, CodeLedgerReverted, fmt.Sprintf("영수증 status %d (블록 %d)", rc.Status, rc.BlockNumber), &rc.BlockNumber)
	}
	set := map[string]any{"block_number": rc.BlockNumber}
	payload := map[string]any{"request_id": id, "status": string(StatusConfirmed), "tx_hash": rc.TxHash.Hex(), "block_number": rc.BlockNumber}
	if typ == intent.TypeDeploy {
		if rc.ContractAddress == nil {
			return w.fail(ctx, tx, id, CodeLedgerReverted, "배포 영수증에 컨트랙트 주소가 없다", &rc.BlockNumber)
		}
		addr := rc.ContractAddress.Hex()
		set["contract_address"] = addr
		payload["contract_address"] = addr
	}
	if err := Transition(ctx, tx, id, StatusSubmitted, StatusConfirmed, set); err != nil {
		return err
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{Actor: "apid", Action: "REQUEST_CONFIRMED", Subject: id, Payload: payload}); err != nil {
		return err
	}
	if typ == intent.TypeDeploy {
		return registerSecurity(ctx, tx, w.LedgerID, id, intentJSON, *rc.ContractAddress, rc.BlockNumber)
	}
	return nil
}

func (w *ReceiptWorker) fail(ctx context.Context, tx *sql.Tx, id, code, msg string, block *uint64) error {
	set := map[string]any{"error": code + ": " + msg}
	payload := map[string]any{"request_id": id, "status": string(StatusFailed), "code": code, "reason": msg}
	if block != nil {
		set["block_number"] = *block
		payload["block_number"] = *block
	}
	if err := Transition(ctx, tx, id, StatusSubmitted, StatusFailed, set); err != nil {
		return err
	}
	_, err := audit.Append(ctx, tx, audit.Entry{Actor: "apid", Action: "REQUEST_FAILED", Subject: id, Payload: payload})
	return err
}

// registerSecurity 는 확정된 배포 요청의 종목과 이벤트 수신 커서를 등록한다.
// 생성자 인자는 (종목명, 종목 코드, 관리자 주소)다. 커서는 배포 블록 바로 앞에서 시작해 배포 블록의 이벤트부터 받는다.
func registerSecurity(ctx context.Context, tx *sql.Tx, ledgerID, id, intentJSON string, contract common.Address, block uint64) error {
	in, err := intent.Parse([]byte(intentJSON))
	if err != nil {
		return fmt.Errorf("workflow: 저장된 배포 intent(%s): %w", id, err)
	}
	if len(in.Args) < 2 {
		return fmt.Errorf("workflow: 배포 intent 의 생성자 인자가 부족하다(%s)", id)
	}
	name, code := in.Args[0], in.Args[1]
	if _, err := tx.ExecContext(ctx, `INSERT INTO securities (issue_code, name, ledger_id, contract_address, circulation_status) VALUES (?, ?, ?, ?, 'ACTIVE')`,
		code, name, ledgerID, contract.Hex()); err != nil {
		return fmt.Errorf("workflow: 종목 등록(%s): %w", code, err)
	}
	start := uint64(0)
	if block > 0 {
		start = block - 1
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO ledger_cursor (ledger_id, contract_address, last_block) VALUES (?, ?, ?)`,
		ledgerID, contract.Hex(), start); err != nil {
		return fmt.Errorf("workflow: 이벤트 커서 등록(%s): %w", code, err)
	}
	_, err = audit.Append(ctx, tx, audit.Entry{Actor: "apid", Action: "SECURITY_REGISTERED", Subject: code, Payload: map[string]any{
		"request_id": id, "issue_code": code, "ledger_id": ledgerID, "contract_address": contract.Hex(), "block_number": block,
	}})
	return err
}

// Run 은 주기마다 SUBMITTED 요청을 확인한다.
func (w *ReceiptWorker) Run(ctx context.Context, interval time.Duration, logf func(msg string, args ...any)) {
	runLoop(ctx, interval, logf, "확정 작업 오류", w.RunOnce)
}
