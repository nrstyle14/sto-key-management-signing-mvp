package workflow

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/go-sql-driver/mysql"
	"github.com/oklog/ulid/v2"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/policy"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signsvc"
)

// KeyInfo 는 서명 서버 키 레지스트리의 공개 정보다(GET /v1/keys).
type KeyInfo struct {
	KeyID         string `json:"key_id"`
	LedgerID      string `json:"ledger_id"`
	InstitutionID string `json:"institution_id"`
	Purpose       string `json:"purpose"`
	Address       string `json:"address"`
	Status        string `json:"status"`
}

// Directory 는 서명 서버가 가진 정책·승인자 명부·키 레지스트리의 조회다(업무 서버는 조회만 한다, 설계서 7.2).
type Directory interface {
	Policies(ctx context.Context) ([]policy.Policy, error)
	Approvers(ctx context.Context) ([]approval.Approver, error)
	Keys(ctx context.Context) ([]KeyInfo, error)
}

// SignerClient 는 서명 서버 호출이다. 서명 서버가 거부하면 *signsvc.Rejection 을, 응답이 없거나 일시 오류면 다른 오류를 돌려준다.
type SignerClient interface {
	SignTx(ctx context.Context, req signsvc.Request) (*signsvc.Response, error)
}

// Error 는 업무 API 의 오류(HTTP 상태와 코드)다.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func apiErr(status int, code, format string, a ...any) *Error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, a...)}
}

// 업무 API 오류 코드(서명 거부 코드와 겹치는 것은 같은 이름을 쓴다)
const (
	CodeBadRequest       = "BAD_REQUEST"
	CodeNotFound         = "REQUEST_NOT_FOUND"
	CodeNotPending       = "REQUEST_NOT_PENDING"
	CodeDrafterUnknown   = "DRAFTER_UNKNOWN"
	CodeDirectoryFailure = "SIGNER_DIRECTORY_UNAVAILABLE"
	CodeUnknownCode      = "DEPLOY_CODE_UNKNOWN"
	CodeSecurityExists   = "SECURITY_EXISTS"
)

// Request 는 요청 조회 결과다.
type Request struct {
	RequestID       string          `json:"request_id"`
	Type            string          `json:"type"`
	LedgerID        string          `json:"ledger_id"`
	InstitutionID   string          `json:"institution_id"`
	Intent          json.RawMessage `json:"intent"`
	IntentHash      string          `json:"intent_hash"`
	Status          Status          `json:"status"`
	DrafterID       string          `json:"drafter_id"`
	SignerAddress   string          `json:"signer_address,omitempty"`
	Nonce           *uint64         `json:"nonce,omitempty"`
	TxHash          string          `json:"tx_hash,omitempty"`
	RawTx           string          `json:"raw_tx,omitempty"`
	Error           string          `json:"error,omitempty"`
	BlockNumber     *uint64         `json:"block_number,omitempty"`     // 확정 블록(CONFIRMED·확정 후 FAILED)
	ContractAddress string          `json:"contract_address,omitempty"` // 배포 요청이 만든 컨트랙트
	ExpiresAt       time.Time       `json:"expires_at"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	Approvals       []ApprovalRow   `json:"approvals"`
}

// ApprovalRow 는 저장된 승인·반려다.
type ApprovalRow struct {
	ApproverID string    `json:"approver_id"`
	Decision   string    `json:"decision"`
	Signature  string    `json:"signature"`
	CreatedAt  time.Time `json:"created_at"`
}

// Service 는 기안·승인 처리다.
type Service struct {
	DB       *sql.DB
	Dir      Directory
	LedgerID string
	GasLimit uint64 // 미서명 tx 에 넣을 가스 한도(사전 정책 검사에도 쓴다)
	// FabricLedgerID 는 Fabric 원장 ID 다(D-26). 비우면 FABRIC_TX 기안을 거부한다.
	FabricLedgerID string
	// DeployGasLimit 은 배포 요청의 가스 한도다(사전 정책 검사용).
	DeployGasLimit uint64
	// KnownCode 는 업무 서버가 배포 tx 를 만들 수 있는 바이트코드인지다(배포 기안의 사전 검사).
	KnownCode func(codeHash common.Hash) bool
	Now       func() time.Time
	// OnHighAmount 는 수량이 정책 한도의 80% 이상인 기안에서 부른다(알람, 설계서 7.4).
	OnHighAmount func(ctx context.Context, req *Request, p *policy.Policy)
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// DraftInput 은 기안 요청 본문이다(POST /v1/requests).
type DraftInput struct {
	Type             string   `json:"type"`
	InstitutionID    string   `json:"institution_id"`
	KeyPurpose       string   `json:"key_purpose"`
	Contract         string   `json:"contract"`
	Function         string   `json:"function"`
	Args             []string `json:"args"`
	CodeHash         string   `json:"code_hash,omitempty"` // DEPLOY 만(생성 바이트코드 keccak256)
	DrafterID        string   `json:"drafter_id"`
	ExpiresInSeconds int      `json:"expires_in_seconds"`
}

func findPolicy(list []policy.Policy, in *intent.Intent) (*policy.Policy, error) {
	var found []policy.Policy
	for _, p := range list {
		if p.LedgerID == in.LedgerID && p.InstitutionID == in.InstitutionID && p.KeyPurpose == in.KeyPurpose {
			found = append(found, p)
		}
	}
	switch len(found) {
	case 0:
		return nil, apiErr(422, policy.CodeNotFound, "(%s, %s, %s) 의 정책이 없다", in.LedgerID, in.InstitutionID, in.KeyPurpose)
	case 1:
		return &found[0], nil
	}
	return nil, apiErr(422, policy.CodeAmbiguous, "정책이 여러 개다")
}

func findApprover(list []approval.Approver, id string) *approval.Approver {
	for i := range list {
		if list[i].ApproverID == id {
			return &list[i]
		}
	}
	return nil
}

// Draft 는 요청을 기안해 PENDING_APPROVAL 로 저장한다. 명백한 정책 위반은 여기서 일찍 돌려준다(최종 판단은 서명 서버).
func (s *Service) Draft(ctx context.Context, d DraftInput) (*Request, error) {
	return s.DraftWith(ctx, d, nil)
}

// DraftWith 는 Draft 와 같고, 요청을 저장하는 같은 DB 트랜잭션에서 extra 를 실행한다(연계장부 계좌 등록, D-22).
// extra 가 오류를 돌려주면 요청도 저장되지 않는다.
func (s *Service) DraftWith(ctx context.Context, d DraftInput, extra func(ctx context.Context, tx *sql.Tx, requestID string) error) (*Request, error) {
	if d.Type == "" {
		d.Type = intent.TypeTX
	}
	if d.ExpiresInSeconds == 0 {
		d.ExpiresInSeconds = 3600
	}
	if d.ExpiresInSeconds < 60 || d.ExpiresInSeconds > 86400 {
		return nil, apiErr(400, CodeBadRequest, "expires_in_seconds 는 60~86400 이다")
	}
	ledgerID := s.LedgerID
	if d.Type == intent.TypeFabricTX {
		if s.FabricLedgerID == "" {
			return nil, apiErr(422, CodeFabricOff, "Fabric 원장이 꺼져 있다(make up-fabric)")
		}
		ledgerID = s.FabricLedgerID
	}
	in := &intent.Intent{
		RequestID: ulid.Make().String(), Type: d.Type, LedgerID: ledgerID, InstitutionID: d.InstitutionID,
		KeyPurpose: signer.Purpose(d.KeyPurpose), Contract: d.Contract, Function: d.Function, Args: d.Args, DrafterID: d.DrafterID,
		CodeHash:  d.CodeHash,
		ExpiresAt: s.now().Add(time.Duration(d.ExpiresInSeconds) * time.Second).Format(intent.TimeLayout),
	}
	if in.Args == nil {
		in.Args = []string{}
	}
	if err := in.Validate(); err != nil {
		return nil, apiErr(422, signsvc.CodeIntentInvalid, "%v", err)
	}
	if in.Type == intent.TypeDeploy {
		if s.KnownCode == nil || !s.KnownCode(in.CodeHashBytes()) {
			return nil, apiErr(422, CodeUnknownCode, "code_hash %s 의 바이트코드를 업무 서버가 모른다", in.CodeHash)
		}
		if len(in.Args) < 2 {
			return nil, apiErr(422, signsvc.CodeIntentInvalid, "생성자 인자는 (종목명, 종목 코드, 관리자 주소)다")
		}
		var n int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM securities WHERE issue_code = ?`, in.Args[1]).Scan(&n); err != nil {
			return nil, err
		}
		if n > 0 {
			return nil, apiErr(409, CodeSecurityExists, "종목 코드 %s 가 이미 있다", in.Args[1])
		}
	}
	apprs, err := s.Dir.Approvers(ctx)
	if err != nil {
		return nil, apiErr(503, CodeDirectoryFailure, "승인자 명부 조회: %v", err)
	}
	// 기안자는 같은 기관에 등록된 ACTIVE 승인자여야 한다(기안자 인증은 MVP 범위 밖: 보고서 참조).
	if dr := findApprover(apprs, in.DrafterID); dr == nil || dr.Status != "ACTIVE" || dr.InstitutionID != in.InstitutionID {
		return nil, apiErr(422, CodeDrafterUnknown, "기안자 %s 는 기관 %s 의 등록된 담당자가 아니다", in.DrafterID, in.InstitutionID)
	}
	pols, err := s.Dir.Policies(ctx)
	if err != nil {
		return nil, apiErr(503, CodeDirectoryFailure, "정책 조회: %v", err)
	}
	p, err := findPolicy(pols, in)
	if err != nil {
		return nil, err
	}
	gas := s.GasLimit
	switch in.Type {
	case intent.TypeDeploy:
		gas = s.DeployGasLimit
	case intent.TypeFabricTX:
		gas = 0 // Fabric 에는 가스가 없다
	}
	if err := policy.Evaluate(p, in, gas); err != nil {
		var v *policy.Violation
		if errors.As(err, &v) {
			return nil, apiErr(422, v.Code, "%s", v.Msg)
		}
		return nil, err
	}
	canon, err := in.Canonical()
	if err != nil {
		return nil, err
	}
	h, _ := in.Hash()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO requests (request_id, type, ledger_id, institution_id, intent_json, intent_hash, status, drafter_id, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, in.RequestID, in.Type, in.LedgerID, in.InstitutionID, string(canon), h[:],
		string(StatusPendingApproval), in.DrafterID, in.Expires()); err != nil {
		return nil, fmt.Errorf("workflow: 기안 저장: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{Actor: in.DrafterID, Action: "REQUEST_SUBMITTED", Subject: in.RequestID, Payload: map[string]any{
		"request_id": in.RequestID, "type": in.Type, "ledger_id": in.LedgerID, "institution_id": in.InstitutionID,
		"purpose": string(in.KeyPurpose), "function": in.Function, "contract": in.Contract, "intent_hash": hex.EncodeToString(h[:]),
		"policy_id": p.PolicyID, "status": string(StatusPendingApproval), "args": in.Args, "code_hash": in.CodeHash,
	}}); err != nil {
		return nil, err
	}
	if extra != nil {
		if err := extra(ctx, tx, in.RequestID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	req, err := s.Get(ctx, in.RequestID)
	if err == nil && s.OnHighAmount != nil && policy.HighAmount(p, in) {
		s.OnHighAmount(ctx, req, p)
	}
	return req, err
}

// AddApproval 은 승인·반려 한 건을 받는다. 서명·명부·정책 조건을 업무 서버에서도 확인한다(서명 서버가 다시 확인한다).
// 반려 1건이면 REJECTED, 서로 다른 승인 M건이면 APPROVED 로 전이한다.
func (s *Service) AddApproval(ctx context.Context, requestID string, a approval.Approval) (*Request, error) {
	if !a.Decision.Valid() || a.ApproverID == "" {
		return nil, apiErr(400, CodeBadRequest, "approver_id, decision(APPROVE|REJECT) 이 필요하다")
	}
	sig, err := a.SignatureBytes()
	if err != nil {
		return nil, apiErr(400, CodeBadRequest, "%v", err)
	}
	apprs, err := s.Dir.Approvers(ctx)
	if err != nil {
		return nil, apiErr(503, CodeDirectoryFailure, "승인자 명부 조회: %v", err)
	}
	pols, err := s.Dir.Policies(ctx)
	if err != nil {
		return nil, apiErr(503, CodeDirectoryFailure, "정책 조회: %v", err)
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var status, intentJSON, drafter string
	var hash []byte
	var expires time.Time
	err = tx.QueryRowContext(ctx, `SELECT status, intent_json, intent_hash, drafter_id, expires_at FROM requests WHERE request_id = ? FOR UPDATE`,
		requestID).Scan(&status, &intentJSON, &hash, &drafter, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apiErr(404, CodeNotFound, "요청 %s 가 없다", requestID)
	}
	if err != nil {
		return nil, err
	}
	if Status(status) != StatusPendingApproval {
		return nil, apiErr(409, CodeNotPending, "요청 상태가 %s 다", status)
	}
	if !s.now().Before(expires) {
		return nil, apiErr(409, signsvc.CodeIntentExpired, "만료된 요청이다")
	}
	in, err := intent.Parse([]byte(intentJSON))
	if err != nil {
		return nil, fmt.Errorf("workflow: 저장된 intent 해석: %w", err)
	}
	var h [32]byte
	copy(h[:], hash)
	ap := findApprover(apprs, a.ApproverID)
	switch {
	case ap == nil:
		return nil, apiErr(422, approval.CodeUnknownApprover, "등록되지 않은 승인자 %s", a.ApproverID)
	case ap.Status != "ACTIVE":
		return nil, apiErr(422, approval.CodeApproverInactive, "승인자 %s 상태 %s", a.ApproverID, ap.Status)
	case !approval.Verify(ap.PublicKey, h, a.Decision, sig):
		return nil, apiErr(422, approval.CodeInvalidSignature, "서명이 이 요청의 intent_hash·결정과 맞지 않는다")
	}
	p, err := findPolicy(pols, in)
	if err != nil {
		return nil, err
	}
	// 승인 한 건에 대한 조건(기안자 본인, 기관, 그룹). 승인 수는 아래에서 센다.
	if err := policy.CheckApprovals(&policy.Policy{Body: policy.Body{ApproverGroup: p.Body.ApproverGroup, RequiredApprovals: 1}},
		drafter, in.InstitutionID, []policy.ApproverRef{{ApproverID: ap.ApproverID, InstitutionID: ap.InstitutionID, Groups: ap.Groups, Decision: "APPROVE"}}); err != nil {
		var v *policy.Violation
		if errors.As(err, &v) {
			return nil, apiErr(422, v.Code, "%s", v.Msg)
		}
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO approvals (request_id, approver_id, decision, signature) VALUES (?, ?, ?, ?)`,
		requestID, a.ApproverID, string(a.Decision), sig); err != nil {
		var me *mysql.MySQLError
		if errors.As(err, &me) && me.Number == 1062 {
			return nil, apiErr(409, policy.CodeApprovalDuplicate, "승인자 %s 는 이미 결정을 냈다", a.ApproverID)
		}
		return nil, err
	}
	var approvedCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM approvals WHERE request_id = ? AND decision = 'APPROVE'`, requestID).Scan(&approvedCount); err != nil {
		return nil, err
	}
	action, next := "APPROVAL_ADDED", Status("")
	switch {
	case a.Decision == approval.Reject:
		action, next = "REQUEST_REJECTED", StatusRejected
	case approvedCount >= p.Body.RequiredApprovals:
		action, next = "REQUEST_APPROVED", StatusApproved
	}
	if next != "" {
		if err := Transition(ctx, tx, requestID, StatusPendingApproval, next, nil); err != nil {
			return nil, err
		}
	}
	payload := map[string]any{"request_id": requestID, "approver_id": a.ApproverID, "decision": string(a.Decision),
		"count": approvedCount, "policy_id": p.PolicyID}
	if next != "" {
		payload["status"] = string(next)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{Actor: a.ApproverID, Action: action, Subject: requestID, Payload: payload}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.Get(ctx, requestID)
}

const requestCols = `request_id, type, ledger_id, institution_id, intent_json, intent_hash, status, drafter_id,
	COALESCE(signer_address, ''), nonce, tx_hash, raw_tx, COALESCE(error, ''), expires_at, created_at, updated_at,
	block_number, COALESCE(contract_address, '')`

func scanRequest(sc interface{ Scan(...any) error }) (*Request, error) {
	var r Request
	var intentJSON, status string
	var hash, txHash, raw []byte
	var nonce, block sql.NullInt64
	if err := sc.Scan(&r.RequestID, &r.Type, &r.LedgerID, &r.InstitutionID, &intentJSON, &hash, &status, &r.DrafterID,
		&r.SignerAddress, &nonce, &txHash, &raw, &r.Error, &r.ExpiresAt, &r.CreatedAt, &r.UpdatedAt, &block, &r.ContractAddress); err != nil {
		return nil, err
	}
	if block.Valid {
		b := uint64(block.Int64)
		r.BlockNumber = &b
	}
	r.Intent, r.IntentHash, r.Status = json.RawMessage(intentJSON), hex.EncodeToString(hash), Status(status)
	if nonce.Valid {
		n := uint64(nonce.Int64)
		r.Nonce = &n
	}
	if len(txHash) == 32 {
		r.TxHash = common.BytesToHash(txHash).Hex()
	}
	if len(raw) > 0 {
		r.RawTx = "0x" + hex.EncodeToString(raw)
	}
	r.ExpiresAt, r.CreatedAt, r.UpdatedAt = r.ExpiresAt.UTC(), r.CreatedAt.UTC(), r.UpdatedAt.UTC()
	return &r, nil
}

// Get 은 요청과 승인 목록을 조회한다.
func (s *Service) Get(ctx context.Context, requestID string) (*Request, error) {
	r, err := scanRequest(s.DB.QueryRowContext(ctx, `SELECT `+requestCols+` FROM requests WHERE request_id = ?`, requestID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, apiErr(404, CodeNotFound, "요청 %s 가 없다", requestID)
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT approver_id, decision, signature, created_at FROM approvals WHERE request_id = ? ORDER BY created_at, approver_id`, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	r.Approvals = []ApprovalRow{}
	for rows.Next() {
		var a ApprovalRow
		var sig []byte
		if err := rows.Scan(&a.ApproverID, &a.Decision, &sig, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.Signature, a.CreatedAt = hex.EncodeToString(sig), a.CreatedAt.UTC()
		r.Approvals = append(r.Approvals, a)
	}
	return r, rows.Err()
}

// List 는 요청 목록이다(최근 순, 상태로 거를 수 있다).
func (s *Service) List(ctx context.Context, status string, limit int) ([]Request, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT ` + requestCols + ` FROM requests`
	var args []any
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, strings.ToUpper(status))
	}
	q += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Request{}
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// HTTPStatus 는 오류의 HTTP 상태다.
func HTTPStatus(err error) (int, string, string) {
	var e *Error
	if errors.As(err, &e) {
		return e.Status, e.Code, e.Msg
	}
	return http.StatusInternalServerError, "INTERNAL", "내부 오류"
}
