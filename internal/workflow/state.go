// Package workflow 는 업무 서버의 요청 상태 기계(설계서 5.4), 기안·승인, 서명 요청 작업자, nonce 할당(5.5)이다.
package workflow

import (
	"context"
	"errors"
	"fmt"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/store"
)

// Status 는 요청 상태다(설계서 5.4).
type Status string

// 요청 상태
const (
	StatusDraft           Status = "DRAFT"
	StatusPendingApproval Status = "PENDING_APPROVAL"
	StatusApproved        Status = "APPROVED"
	StatusRejected        Status = "REJECTED"
	StatusExpired         Status = "EXPIRED"
	StatusSigned          Status = "SIGNED"
	StatusSubmitted       Status = "SUBMITTED"
	StatusConfirmed       Status = "CONFIRMED"
	StatusFailed          Status = "FAILED"
)

// transitions 는 허용되는 상태 전이다(설계서 5.4 상태도).
var transitions = map[Status][]Status{
	StatusDraft:           {StatusPendingApproval},
	StatusPendingApproval: {StatusApproved, StatusRejected, StatusExpired},
	StatusApproved:        {StatusSigned, StatusFailed, StatusExpired},
	StatusSigned:          {StatusSubmitted},
	StatusSubmitted:       {StatusConfirmed, StatusFailed},
}

// 오류
var (
	ErrInvalidTransition = errors.New("workflow: 허용되지 않은 상태 전이")
	ErrStateChanged      = errors.New("workflow: 요청 상태가 이미 바뀌었다")
)

// CanTransition 은 from → to 가 허용되는지 돌려준다.
func CanTransition(from, to Status) bool {
	for _, s := range transitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Transition 은 상태 전이를 조건부 갱신(`UPDATE … WHERE status = 이전상태`)으로 한다(설계서 5.4).
// set 은 함께 바꿀 컬럼(이름 → 값)이다. 이름은 이 패키지 안에서만 넘긴다.
func Transition(ctx context.Context, db store.DBTX, requestID string, from, to Status, set map[string]any) error {
	if !CanTransition(from, to) {
		return fmt.Errorf("%w: %s → %s", ErrInvalidTransition, from, to)
	}
	q := "UPDATE requests SET status = ?"
	args := []any{string(to)}
	for _, col := range []string{"signer_address", "nonce", "unsigned_tx", "raw_tx", "tx_hash", "error"} {
		if v, ok := set[col]; ok {
			q += ", " + col + " = ?"
			args = append(args, v)
		}
	}
	q += " WHERE request_id = ? AND status = ?"
	args = append(args, requestID, string(from))
	res, err := db.ExecContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("workflow: 상태 전이: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("%w: %s (기대 %s)", ErrStateChanged, requestID, from)
	}
	return nil
}
