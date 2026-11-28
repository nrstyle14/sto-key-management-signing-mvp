// Package policy 는 정책 모델과 평가다(설계서 7.2, FR-3.2).
// 평가 결과는 통과(nil) 또는 구체적인 거부 코드다.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"

	"github.com/ethereum/go-ethereum/common"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/store"
)

// 거부 코드(설계서 5.3 의 5단계·6단계)
const (
	CodeNotFound             = "POLICY_NOT_FOUND"
	CodeAmbiguous            = "POLICY_AMBIGUOUS"
	CodeScopeMismatch        = "POLICY_SCOPE_MISMATCH"
	CodeFunctionNotAllowed   = "POLICY_FUNCTION_NOT_ALLOWED"
	CodeFunctionUnmapped     = "POLICY_FUNCTION_UNMAPPED"
	CodeAmountExceeded       = "POLICY_AMOUNT_EXCEEDED"
	CodeRecipientNotListed   = "POLICY_RECIPIENT_NOT_WHITELISTED"
	CodeGasLimitExceeded     = "POLICY_GAS_LIMIT_EXCEEDED"
	CodeApprovalInsufficient = "APPROVAL_INSUFFICIENT"
	CodeApprovalSelf         = "APPROVAL_SELF"
	CodeApprovalDuplicate    = "APPROVAL_DUPLICATE"
	CodeApprovalGroup        = "APPROVAL_GROUP_MISMATCH"
	CodeApprovalInstitution  = "APPROVAL_INSTITUTION_MISMATCH"
	CodeApprovalRejected     = "APPROVAL_REJECTED"
)

// Violation 은 정책 위반이다.
type Violation struct{ Code, Msg string }

func (v *Violation) Error() string { return v.Code + ": " + v.Msg }

func violate(code, format string, a ...any) error {
	return &Violation{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Body 는 policies.body_json 의 형식이다. 알 수 없는 필드는 거부한다.
type Body struct {
	AllowedFunctions   []string `json:"allowed_functions" yaml:"allowed_functions"`
	MaxAmount          string   `json:"max_amount,omitempty" yaml:"max_amount"` // 10진수 문자열, 비우면 한도 없음
	RecipientWhitelist bool     `json:"recipient_whitelist" yaml:"recipient_whitelist"`
	RequiredApprovals  int      `json:"required_approvals" yaml:"required_approvals"`
	ApproverGroup      string   `json:"approver_group" yaml:"approver_group"`
	GasLimitCap        uint64   `json:"gas_limit_cap" yaml:"gas_limit_cap"`
}

var (
	fnRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\([a-z0-9,]*\)$`)
	// fabricFnRe 는 Fabric 체인코드 함수 이름이다(D-26, intent FABRIC_TX 의 function 과 같은 형식).
	fabricFnRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
)

// Validate 는 본문 값을 확인한다.
func (b *Body) Validate() error {
	var errs []error
	if len(b.AllowedFunctions) == 0 {
		errs = append(errs, errors.New("allowed_functions 가 비었다"))
	}
	seen := map[string]bool{}
	for _, f := range b.AllowedFunctions {
		if !(fnRe.MatchString(f) || fabricFnRe.MatchString(f)) || seen[f] {
			errs = append(errs, fmt.Errorf("함수 서명 %q 가 정규 형식이 아니거나 중복이다", f))
		}
		seen[f] = true
	}
	if b.MaxAmount != "" {
		if n, ok := new(big.Int).SetString(b.MaxAmount, 10); !ok || n.Sign() <= 0 || n.String() != b.MaxAmount {
			errs = append(errs, fmt.Errorf("max_amount %q 는 선행 0 없는 양의 10진수 문자열이어야 한다", b.MaxAmount))
		}
	}
	if b.RequiredApprovals < 1 {
		errs = append(errs, errors.New("required_approvals 는 1 이상이어야 한다"))
	}
	if b.ApproverGroup == "" {
		errs = append(errs, errors.New("approver_group 이 필요하다"))
	}
	if b.GasLimitCap == 0 {
		errs = append(errs, errors.New("gas_limit_cap 이 필요하다"))
	}
	return errors.Join(errs...)
}

// ParseBody 는 body_json 을 엄격하게 해석한다(숫자를 float 로 읽지 않는다).
func ParseBody(raw []byte) (*Body, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	var b Body
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("policy: 본문 해석: %w", err)
	}
	if err := b.Validate(); err != nil {
		return nil, fmt.Errorf("policy: 본문 검증: %w", err)
	}
	return &b, nil
}

// Canonical 은 저장용 JSON 이다(필드 순서 고정, 공백 없음).
func (b *Body) Canonical() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(b); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Policy 는 평가에 쓰는 정책이다.
type Policy struct {
	PolicyID      string         `json:"policy_id"`
	Version       int            `json:"version"`
	LedgerID      string         `json:"ledger_id"`
	InstitutionID string         `json:"institution_id"`
	KeyPurpose    signer.Purpose `json:"key_purpose"`
	Body          Body           `json:"body"`
	Whitelist     []string       `json:"whitelist"` // EIP-55 주소
}

// Role 은 함수 인자 중 수신 계좌와 수량의 위치다(-1 은 없음).
type Role struct{ Recipient, Amount int }

// roles 는 토큰증권 컨트랙트(설계서 10.2) 함수의 인자 역할이다.
// 여기에 없는 함수는 정책이 수량 한도나 화이트리스트를 요구하면 거부한다.
var roles = map[string]Role{
	"issue(address,uint256)":                   {Recipient: 0, Amount: 1},
	"redeem(address,uint256)":                  {Recipient: -1, Amount: 1},
	"transferByAgent(address,address,uint256)": {Recipient: 1, Amount: 2},
	"registerAccount(address,string)":          {Recipient: -1, Amount: -1},
	"setAccountRestricted(address,bool)":       {Recipient: -1, Amount: -1},
	"setCirculation(bool)":                     {Recipient: -1, Amount: -1},
	"pause()":                                  {Recipient: -1, Amount: -1},
	"unpause()":                                {Recipient: -1, Amount: -1},
	"grantRole(bytes32,address)":               {Recipient: -1, Amount: -1},
	"revokeRole(bytes32,address)":              {Recipient: -1, Amount: -1},
	"renounceRole(bytes32,address)":            {Recipient: -1, Amount: -1},
	"setAgentInstitution(address,string)":      {Recipient: -1, Amount: -1},
	"constructor(string,string,address)":       {Recipient: -1, Amount: -1}, // 종목 배포(D-19)
}

// RoleOf 는 함수의 인자 역할이다.
func RoleOf(function string) (Role, bool) {
	r, ok := roles[function]
	return r, ok
}

// Amount 는 intent 의 수량 인자다(없으면 false).
func Amount(in *intent.Intent) (*big.Int, bool) {
	r, ok := RoleOf(in.Function)
	if !ok || r.Amount < 0 || r.Amount >= len(in.Args) {
		return nil, false
	}
	n, ok := new(big.Int).SetString(in.Args[r.Amount], 10)
	return n, ok
}

// Evaluate 는 정책 범위, 함수 허용, 수량 한도, 수신 계좌 화이트리스트, 가스 한도 상한을 검사한다(5단계).
func Evaluate(p *Policy, in *intent.Intent, gas uint64) error {
	if p.LedgerID != in.LedgerID || p.InstitutionID != in.InstitutionID || p.KeyPurpose != in.KeyPurpose {
		return violate(CodeScopeMismatch, "정책 %s 범위와 요청 범위가 다르다", p.PolicyID)
	}
	allowed := false
	for _, f := range p.Body.AllowedFunctions {
		if f == in.Function {
			allowed = true
		}
	}
	if !allowed {
		return violate(CodeFunctionNotAllowed, "함수 %s 는 정책 %s 에서 허용되지 않는다", in.Function, p.PolicyID)
	}
	role, mapped := RoleOf(in.Function)
	if !mapped && (p.Body.MaxAmount != "" || p.Body.RecipientWhitelist) {
		return violate(CodeFunctionUnmapped, "함수 %s 의 수량·수신 계좌 위치를 알 수 없어 한도를 검사할 수 없다", in.Function)
	}
	if p.Body.MaxAmount != "" && role.Amount >= 0 {
		max, _ := new(big.Int).SetString(p.Body.MaxAmount, 10)
		amt, ok := Amount(in)
		if !ok {
			return violate(CodeFunctionUnmapped, "수량 인자를 읽을 수 없다")
		}
		if amt.Cmp(max) > 0 {
			return violate(CodeAmountExceeded, "수량 %s 이 한도 %s 를 넘는다", amt, max)
		}
	}
	if p.Body.RecipientWhitelist && role.Recipient >= 0 {
		rcpt := common.HexToAddress(in.Args[role.Recipient])
		listed := false
		for _, w := range p.Whitelist {
			if common.HexToAddress(w) == rcpt {
				listed = true
			}
		}
		if !listed {
			return violate(CodeRecipientNotListed, "수신 계좌 %s 가 화이트리스트에 없다", rcpt.Hex())
		}
	}
	if gas > p.Body.GasLimitCap {
		return violate(CodeGasLimitExceeded, "가스 한도 %d 가 정책 상한 %d 를 넘는다", gas, p.Body.GasLimitCap)
	}
	return nil
}

// ApproverRef 는 서명이 확인된 승인 한 건의 승인자 정보다.
type ApproverRef struct {
	ApproverID    string
	InstitutionID string
	Groups        []string
	Decision      string
}

// CheckApprovals 는 승인 조건을 검사한다(6단계). 하나라도 조건에 맞지 않으면 요청 전체를 거부한다.
//   - 같은 승인자 중복 불가, 기안자 본인 불가, 요청 기관 소속, 정책 승인자 그룹 소속, 반려 포함 불가
//   - 서로 다른 승인자 M(required_approvals)명 이상
func CheckApprovals(p *Policy, drafterID, institutionID string, refs []ApproverRef) error {
	seen := map[string]bool{}
	for _, r := range refs {
		if seen[r.ApproverID] {
			return violate(CodeApprovalDuplicate, "승인자 %s 가 중복됐다", r.ApproverID)
		}
		seen[r.ApproverID] = true
		if r.ApproverID == drafterID {
			return violate(CodeApprovalSelf, "기안자 %s 는 자기 요청을 승인할 수 없다", r.ApproverID)
		}
		if r.InstitutionID != institutionID {
			return violate(CodeApprovalInstitution, "승인자 %s 의 기관 %s 이 요청 기관 %s 와 다르다", r.ApproverID, r.InstitutionID, institutionID)
		}
		inGroup := false
		for _, g := range r.Groups {
			if g == p.Body.ApproverGroup {
				inGroup = true
			}
		}
		if !inGroup {
			return violate(CodeApprovalGroup, "승인자 %s 는 그룹 %s 에 없다", r.ApproverID, p.Body.ApproverGroup)
		}
		if r.Decision != "APPROVE" {
			return violate(CodeApprovalRejected, "승인자 %s 가 반려했다", r.ApproverID)
		}
	}
	if len(seen) < p.Body.RequiredApprovals {
		return violate(CodeApprovalInsufficient, "승인 %d 건, 필요 %d 건", len(seen), p.Body.RequiredApprovals)
	}
	return nil
}

// HighAmount 는 수량이 정책 한도의 80% 이상인지 돌려준다(알람 규칙, 설계서 7.4). big.Int 로 계산한다.
func HighAmount(p *Policy, in *intent.Intent) bool {
	if p.Body.MaxAmount == "" {
		return false
	}
	amt, ok := Amount(in)
	if !ok {
		return false
	}
	max, _ := new(big.Int).SetString(p.Body.MaxAmount, 10)
	lhs := new(big.Int).Mul(amt, big.NewInt(100))
	rhs := new(big.Int).Mul(max, big.NewInt(80))
	return lhs.Cmp(rhs) >= 0
}

// Lookup 은 (원장, 기관, 용도)의 ACTIVE 정책을 하나만 돌려준다. 없거나 둘 이상이면 거부한다.
func Lookup(ctx context.Context, db store.DBTX, ledgerID, institutionID string, purpose signer.Purpose) (*Policy, error) {
	rows, err := db.QueryContext(ctx, `SELECT policy_id, version, body_json FROM policies
		WHERE ledger_id = ? AND institution_id = ? AND key_purpose = ? AND status = 'ACTIVE'`, ledgerID, institutionID, string(purpose))
	if err != nil {
		return nil, fmt.Errorf("policy: 조회: %w", err)
	}
	type row struct {
		id   string
		ver  int
		body string
	}
	var found []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.ver, &r.body); err != nil {
			rows.Close()
			return nil, err
		}
		found = append(found, r)
	}
	rows.Close()
	switch len(found) {
	case 0:
		return nil, violate(CodeNotFound, "(%s, %s, %s) 의 ACTIVE 정책이 없다", ledgerID, institutionID, purpose)
	case 1:
	default:
		return nil, violate(CodeAmbiguous, "(%s, %s, %s) 의 ACTIVE 정책이 %d 개다", ledgerID, institutionID, purpose, len(found))
	}
	body, err := ParseBody([]byte(found[0].body))
	if err != nil {
		return nil, err
	}
	p := &Policy{PolicyID: found[0].id, Version: found[0].ver, LedgerID: ledgerID, InstitutionID: institutionID, KeyPurpose: purpose, Body: *body}
	if p.Whitelist, err = whitelist(ctx, db, p.PolicyID); err != nil {
		return nil, err
	}
	return p, nil
}

func whitelist(ctx context.Context, db store.DBTX, policyID string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT account_address FROM whitelists WHERE policy_id = ? ORDER BY account_address`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListActive 는 ACTIVE 정책 전체다(GET /v1/policies, 업무 서버의 사전 검사용).
func ListActive(ctx context.Context, db store.DBTX) ([]Policy, error) {
	rows, err := db.QueryContext(ctx, `SELECT policy_id, version, ledger_id, institution_id, key_purpose, body_json FROM policies WHERE status = 'ACTIVE' ORDER BY policy_id`)
	if err != nil {
		return nil, err
	}
	var out []Policy
	for rows.Next() {
		var p Policy
		var purpose, body string
		if err := rows.Scan(&p.PolicyID, &p.Version, &p.LedgerID, &p.InstitutionID, &purpose, &body); err != nil {
			rows.Close()
			return nil, err
		}
		p.KeyPurpose = signer.Purpose(purpose)
		b, err := ParseBody([]byte(body))
		if err != nil {
			rows.Close()
			return nil, err
		}
		p.Body = *b
		out = append(out, p)
	}
	rows.Close()
	for i := range out {
		if out[i].Whitelist, err = whitelist(ctx, db, out[i].PolicyID); err != nil {
			return nil, err
		}
	}
	if out == nil {
		out = []Policy{}
	}
	return out, nil
}
