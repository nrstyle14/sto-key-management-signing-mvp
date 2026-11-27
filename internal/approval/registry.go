package approval

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/store"
)

// Approver 는 서명 서버의 승인자 명부 행이다.
type Approver struct {
	ApproverID    string            `json:"approver_id"`
	Name          string            `json:"name"`
	InstitutionID string            `json:"institution_id"`
	Role          string            `json:"role"`
	PublicKey     ed25519.PublicKey `json:"ed25519_pubkey"`
	Status        string            `json:"status"`
	Groups        []string          `json:"groups"`
}

// 승인 검증 거부 코드(설계서 5.3 의 6단계)
const (
	CodeUnknownApprover  = "APPROVAL_UNKNOWN_APPROVER"
	CodeApproverInactive = "APPROVAL_APPROVER_INACTIVE"
	CodeInvalidSignature = "APPROVAL_INVALID_SIGNATURE"
)

// Error 는 승인 한 건의 검증 실패다.
type Error struct{ Code, ApproverID, Msg string }

func (e *Error) Error() string { return fmt.Sprintf("%s(%s): %s", e.Code, e.ApproverID, e.Msg) }

// ErrNotFound 는 승인자가 없다는 뜻이다.
var ErrNotFound = errors.New("approval: 승인자가 없다")

// Lookup 은 승인자와 소속 그룹을 조회한다.
func Lookup(ctx context.Context, db store.DBTX, approverID string) (*Approver, error) {
	a := &Approver{}
	var pub []byte
	err := db.QueryRowContext(ctx, `SELECT approver_id, name, institution_id, role, ed25519_pubkey, status FROM approvers WHERE approver_id = ?`,
		approverID).Scan(&a.ApproverID, &a.Name, &a.InstitutionID, &a.Role, &pub, &a.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("approval: 승인자 조회: %w", err)
	}
	a.PublicKey = pub
	rows, err := db.QueryContext(ctx, `SELECT group_id FROM approver_groups WHERE approver_id = ? ORDER BY group_id`, approverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, err
		}
		a.Groups = append(a.Groups, g)
	}
	return a, rows.Err()
}

// List 는 전체 승인자 명부다(GET /v1/approvers).
func List(ctx context.Context, db store.DBTX) ([]Approver, error) {
	rows, err := db.QueryContext(ctx, `SELECT approver_id FROM approvers ORDER BY approver_id`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	out := []Approver{}
	for _, id := range ids {
		a, err := Lookup(ctx, db, id)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ApproverID < out[j].ApproverID })
	return out, nil
}

// VerifyOne 은 승인 한 건을 명부와 대조한다: 등록된 승인자, ACTIVE 상태, 서명 유효.
// 그룹·기관·기안자·승인 수 조건은 정책 검사(internal/policy)가 한다.
func VerifyOne(ctx context.Context, db store.DBTX, a Approval, intentHash [32]byte) (*Approver, error) {
	ap, err := Lookup(ctx, db, a.ApproverID)
	if errors.Is(err, ErrNotFound) {
		return nil, &Error{Code: CodeUnknownApprover, ApproverID: a.ApproverID, Msg: "등록되지 않은 승인자"}
	}
	if err != nil {
		return nil, err
	}
	if ap.Status != "ACTIVE" {
		return nil, &Error{Code: CodeApproverInactive, ApproverID: a.ApproverID, Msg: "상태 " + ap.Status}
	}
	sig, err := a.SignatureBytes()
	if err != nil || !Verify(ap.PublicKey, intentHash, a.Decision, sig) {
		return nil, &Error{Code: CodeInvalidSignature, ApproverID: a.ApproverID, Msg: "서명이 intent_hash·결정과 맞지 않는다"}
	}
	return ap, nil
}
