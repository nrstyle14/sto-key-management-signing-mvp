package workflow

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signsvc"
)

// Fabric 요청 처리(설계서 10.5, D-26). 상태는 EVM 요청과 같다: APPROVED → SIGNED → SUBMITTED → CONFIRMED/FAILED.
//
//	APPROVED: 제안 생성 → PROPOSAL 서명 → 보증 → TRANSACTION 서명 → SIGNED(raw_tx = 보증된 트랜잭션, tx_hash = txID)
//	SIGNED:   TRANSACTION 서명(같은 원문이라 서명 서버가 저장된 서명을 준다) → 제출 → SUBMITTED(raw_tx = 커밋 상태 요청)
//	SUBMITTED: COMMIT 서명 → 커밋 상태 → CONFIRMED(block_number) 또는 FAILED(FABRIC_INVALID)
//
// 각 단계는 요청 행을 잠근 채 한 번에 한다. 단계 사이에 중단되면 다음 실행이 그 단계부터 이어 간다.
// 보증 뒤 SIGNED 저장 전에 중단되면 다음 실행의 새 제안이 서명 서버 2단계(같은 요청의 다른 제안)에서 거부돼 FAILED 로 닫힌다.

// Fabric 오류 코드
const (
	CodeFabricEndorse = "FABRIC_ENDORSE_FAILED"
	CodeFabricSubmit  = "FABRIC_SUBMIT_FAILED"
	CodeFabricInvalid = "FABRIC_INVALID"
	CodeFabricOff     = "FABRIC_LEDGER_OFF"
)

// FabricLedger 는 Fabric 게이트웨이(internal/ledger/fabric.Adapter)다.
type FabricLedger interface {
	NewProposal(certPEM []byte, mspID, channel, chaincode, fn string, args []string) ([]byte, string, error)
	Endorse(ctx context.Context, certPEM []byte, mspID string, proposal, sig []byte) ([]byte, error)
	Submit(ctx context.Context, certPEM []byte, mspID string, transaction, sig []byte) ([]byte, error)
	Status(ctx context.Context, certPEM []byte, mspID string, commit, sig []byte) (bool, uint64, string, error)
}

// FabricSigner 는 서명 서버의 Fabric 원문 서명이다.
type FabricSigner interface {
	SignFabric(ctx context.Context, req signsvc.FabricRequest) (*signsvc.FabricResponse, error)
}

// FabricIdentities 는 (원장, 기관, 용도)의 ACTIVE Fabric 신원(인증서, MSP)이다.
type FabricIdentities interface {
	FabricIdentity(ctx context.Context, ledgerID, institutionID, purpose string) (certPEM []byte, mspID string, err error)
}

// FabricWorker 는 Fabric 요청 작업자다.
type FabricWorker struct {
	DB         *sql.DB
	LedgerID   string
	Ledger     FabricLedger
	Signer     FabricSigner
	Identities FabricIdentities
	// IsTransient 는 다시 시도할 오류인지다(게이트웨이·서명 서버 응답 없음).
	IsTransient func(error) bool
}

func (w *FabricWorker) transient(err error) bool {
	return errors.Is(err, ErrTransient) || (w.IsTransient != nil && w.IsTransient(err))
}

// RunOnce 는 Fabric 요청 하나를 한 단계 진행한다. 진행한 요청이 있으면 true.
func (w *FabricWorker) RunOnce(ctx context.Context) (bool, error) {
	tx, err := w.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var id, intentJSON string
	var status Status
	var hash, raw []byte
	var expires time.Time
	err = tx.QueryRowContext(ctx, `SELECT request_id, status, intent_json, intent_hash, raw_tx, expires_at FROM requests
		WHERE ledger_id = ? AND status IN ('APPROVED', 'SIGNED', 'SUBMITTED') AND updated_at <= CURRENT_TIMESTAMP(6) - INTERVAL 200000 MICROSECOND
		ORDER BY updated_at LIMIT 1 FOR UPDATE SKIP LOCKED`, w.LedgerID).Scan(&id, &status, &intentJSON, &hash, &raw, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	in, err := intent.Parse([]byte(intentJSON))
	if err != nil {
		return true, fmt.Errorf("workflow: 저장된 intent 해석(%s): %w", id, err)
	}
	if status == StatusApproved && time.Now().After(expires) {
		if err := w.close(ctx, tx, id, StatusApproved, StatusExpired, "REQUEST_EXPIRED", map[string]any{"reason": "서명 전에 만료"}, nil); err != nil {
			return true, err
		}
		return true, tx.Commit()
	}
	cert, mspID, err := w.Identities.FabricIdentity(ctx, in.LedgerID, in.InstitutionID, string(in.KeyPurpose))
	if err != nil {
		return true, w.retry(ctx, tx, id, fmt.Errorf("%w: Fabric 신원 조회: %v", ErrTransient, err))
	}
	req := signsvc.FabricRequest{Intent: []byte(intentJSON), IntentHash: hex.EncodeToString(hash)}
	if req.Approvals, err = loadApprovals(ctx, tx, id); err != nil {
		return true, err
	}
	sign := func(kind string, payload []byte) (*signsvc.FabricResponse, error) {
		r := req
		r.Kind, r.Payload = kind, payload
		return w.Signer.SignFabric(ctx, r)
	}
	// fail 은 영구 실패로 닫는다. 일시 오류면 다음 실행으로 미룬다.
	fail := func(code string, cause error) error {
		if w.transient(cause) {
			return w.retry(ctx, tx, id, cause)
		}
		var rj *signsvc.Rejection
		if errors.As(cause, &rj) {
			code = rj.Code
		}
		msg := cause.Error()
		if len(msg) > 400 {
			msg = msg[:400]
		}
		if err := w.close(ctx, tx, id, status, StatusFailed, "REQUEST_FAILED", map[string]any{"code": code, "reason": msg},
			map[string]any{"error": code + ": " + msg}); err != nil {
			return err
		}
		return tx.Commit()
	}

	switch status {
	case StatusApproved:
		channel, chaincode := in.FabricTarget()
		proposal, txID, err := w.Ledger.NewProposal(cert, mspID, channel, chaincode, in.Function, in.Args)
		if err != nil {
			return true, fail(CodeFabricEndorse, err)
		}
		sp, err := sign(signsvc.KindProposal, proposal)
		if err != nil {
			return true, fail(CodeFabricEndorse, err)
		}
		prepared, err := w.Ledger.Endorse(ctx, cert, mspID, proposal, sp.Signature)
		if err != nil {
			return true, fail(CodeFabricEndorse, err)
		}
		st, err := sign(signsvc.KindTransaction, prepared)
		if err != nil {
			return true, fail(CodeFabricEndorse, err)
		}
		txHash, _ := hex.DecodeString(txID)
		if err := w.close(ctx, tx, id, StatusApproved, StatusSigned, "REQUEST_SIGNED", map[string]any{"tx_hash": txID, "key_id": st.KeyID},
			map[string]any{"raw_tx": prepared, "tx_hash": txHash}); err != nil {
			return true, err
		}
		return true, tx.Commit()
	case StatusSigned:
		st, err := sign(signsvc.KindTransaction, raw)
		if err != nil {
			return true, fail(CodeFabricSubmit, err)
		}
		commit, err := w.Ledger.Submit(ctx, cert, mspID, raw, st.Signature)
		if err != nil {
			return true, fail(CodeFabricSubmit, err)
		}
		if err := w.close(ctx, tx, id, StatusSigned, StatusSubmitted, "REQUEST_LEDGER_SUBMITTED", map[string]any{"tx_hash": st.TxID},
			map[string]any{"raw_tx": commit, "submitted_at": time.Now().UTC()}); err != nil {
			return true, err
		}
		return true, tx.Commit()
	default: // SUBMITTED
		sc, err := sign(signsvc.KindCommit, raw)
		if err != nil {
			return true, fail(CodeFabricInvalid, err)
		}
		ok, block, code, err := w.Ledger.Status(ctx, cert, mspID, raw, sc.Signature)
		if err != nil {
			return true, fail(CodeFabricInvalid, err)
		}
		if !ok {
			return true, fail(CodeFabricInvalid, fmt.Errorf("커밋 무효(%s)", code))
		}
		if err := w.close(ctx, tx, id, StatusSubmitted, StatusConfirmed, "REQUEST_CONFIRMED", map[string]any{"tx_hash": sc.TxID, "block_number": block},
			map[string]any{"block_number": block}); err != nil {
			return true, err
		}
		return true, tx.Commit()
	}
}

// retry 는 행 잠금을 풀고 updated_at 만 바꿔 다른 요청이 먼저 처리되게 한다.
func (w *FabricWorker) retry(ctx context.Context, tx *sql.Tx, id string, cause error) error {
	_ = tx.Rollback()
	_, _ = w.DB.ExecContext(ctx, `UPDATE requests SET updated_at = CURRENT_TIMESTAMP(6) WHERE request_id = ?`, id)
	return cause
}

func (w *FabricWorker) close(ctx context.Context, tx *sql.Tx, id string, from, to Status, action string, payload, set map[string]any) error {
	if err := Transition(ctx, tx, id, from, to, set); err != nil {
		return err
	}
	payload["request_id"], payload["status"] = id, string(to)
	_, err := audit.Append(ctx, tx, audit.Entry{Actor: "apid", Action: action, Subject: id, Payload: payload})
	return err
}

func loadApprovals(ctx context.Context, tx *sql.Tx, id string) ([]approval.Approval, error) {
	rows, err := tx.QueryContext(ctx, `SELECT approver_id, decision, signature FROM approvals WHERE request_id = ? ORDER BY approver_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []approval.Approval
	for rows.Next() {
		var a approval.Approval
		var sig []byte
		if err := rows.Scan(&a.ApproverID, &a.Decision, &sig); err != nil {
			return nil, err
		}
		a.Signature = hex.EncodeToString(sig)
		out = append(out, a)
	}
	return out, rows.Err()
}

// Run 은 주기마다 RunOnce 를 돈다. 진행한 요청이 있으면 기다리지 않고 바로 다시 돈다.
func (w *FabricWorker) Run(ctx context.Context, interval time.Duration, logf func(msg string, args ...any)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		did, err := w.RunOnce(ctx)
		if err != nil {
			logf("Fabric 작업 오류", "err", err)
		}
		if did && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
