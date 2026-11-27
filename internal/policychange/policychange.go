// Package policychange 는 승인된 정책 변경이다(설계서 7.2, FR-3.4, D-22). 지금은 화이트리스트 주소 추가만 있다.
//
// 키 작업(D-20)처럼 보안관리자 M명이 서명한 요청을 서명 서버가 직접 받는다(POST /v1/policy-changes, 호출자 stoctl).
// 서명 대상은 도메인 문자열 "sto-policy-v1" 과 정규화한 JSON 이라 키 작업·업무 승인·동결 서명과 서로 재사용할 수 없다.
// change_id 는 한 번만 쓰이고(policy_changes 기본 키), requested_at 은 서명 서버 시각과 허용 오차(기본 5분) 안이어야 한다.
// 변경과 기록·감사는 한 DB 트랜잭션이다.
package policychange

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/go-sql-driver/mysql"
	"github.com/oklog/ulid/v2"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/adminsig"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/policy"
)

// 도메인과 시각 형식
const (
	Domain     = "sto-policy-v1"
	TimeLayout = "2006-01-02T15:04:05Z"
)

// TypeWhitelistAdd 는 화이트리스트 주소 추가다.
const TypeWhitelistAdd = "WHITELIST_ADD"

// 거부 코드
const (
	CodeInvalid      = "POLICY_CHANGE_INVALID"
	CodeStale        = "POLICY_CHANGE_STALE"
	CodeReplay       = "POLICY_CHANGE_REPLAY"
	CodeAdmin        = "POLICY_CHANGE_NOT_SECURITY_ADMIN"
	CodeSignature    = "POLICY_CHANGE_INVALID_SIGNATURE"
	CodeInsufficient = "POLICY_CHANGE_APPROVAL_INSUFFICIENT"
	CodePolicy       = "POLICY_CHANGE_POLICY_INVALID"
)

// Error 는 정책 변경 거부다.
type Error struct{ Code, Msg string }

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func fail(code, format string, a ...any) error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Request 는 정책 변경 요청이다. 서명은 Approvals 를 뺀 나머지 필드의 Message 에 대한 것이다.
type Request struct {
	ChangeID    string               `json:"change_id"`
	Type        string               `json:"type"`
	PolicyIDs   []string             `json:"policy_ids"`
	Address     string               `json:"address"` // EIP-55
	Reason      string               `json:"reason"`
	RequestedAt string               `json:"requested_at"`
	Approvals   []adminsig.Signature `json:"approvals"`
}

// Result 는 실행 결과다.
type Result struct {
	ChangeID  string   `json:"change_id"`
	Type      string   `json:"type"`
	PolicyIDs []string `json:"policy_ids"`
	Address   string   `json:"address"`
	Added     int      `json:"added"` // 새로 들어간 정책 수(이미 있던 정책은 세지 않는다)
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Message 는 서명 대상 바이트다(승인자마다 같다).
func (r Request) Message() []byte {
	m := map[string]any{"change_id": r.ChangeID, "type": r.Type, "policy_ids": r.PolicyIDs, "address": r.Address,
		"reason": r.Reason, "requested_at": r.RequestedAt}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(m)
	return append([]byte(Domain), bytes.TrimRight(buf.Bytes(), "\n")...)
}

// Hash 는 SHA-256(Message) 다(policy_changes.intent_hash).
func (r Request) Hash() [32]byte { return sha256.Sum256(r.Message()) }

// NewWhitelistAdd 는 새 화이트리스트 추가 요청을 만든다(stoctl). 정책 ID 는 정렬하고 주소는 EIP-55 로 바꾼다.
func NewWhitelistAdd(policyIDs []string, address common.Address, reason string, now time.Time) Request {
	ids := append([]string(nil), policyIDs...)
	sort.Strings(ids)
	return Request{ChangeID: ulid.Make().String(), Type: TypeWhitelistAdd, PolicyIDs: ids, Address: address.Hex(),
		Reason: reason, RequestedAt: now.UTC().Format(TimeLayout)}
}

// Sign 은 보안관리자 서명을 붙인다.
func (r *Request) Sign(adminID string, priv ed25519.PrivateKey) {
	r.Approvals = append(r.Approvals, adminsig.Signature{AdminID: adminID, Signature: hex.EncodeToString(ed25519.Sign(priv, r.Message()))})
}

// Executor 는 서명 서버의 정책 변경 실행기다.
type Executor struct {
	DB         *sql.DB
	AdminGroup string        // 보안관리자 그룹
	Approvals  int           // 필요한 서로 다른 보안관리자 수(M)
	MaxSkew    time.Duration // requested_at 허용 오차(기본 5분)
}

func (e *Executor) validate(r Request, now time.Time) error {
	if u, err := ulid.ParseStrict(r.ChangeID); err != nil || u.String() != r.ChangeID {
		return fail(CodeInvalid, "change_id 는 대문자 ULID 여야 한다")
	}
	if r.Type != TypeWhitelistAdd {
		return fail(CodeInvalid, "지원하는 변경은 %s 뿐이다(받은 값 %q)", TypeWhitelistAdd, r.Type)
	}
	if r.Reason == "" || len(r.Reason) > 500 {
		return fail(CodeInvalid, "reason 은 1~500자다")
	}
	if len(r.PolicyIDs) == 0 || len(r.PolicyIDs) > 16 || !sort.StringsAreSorted(r.PolicyIDs) {
		return fail(CodeInvalid, "policy_ids 는 1~16개, 정렬된 목록이다")
	}
	for i, id := range r.PolicyIDs {
		if !idRe.MatchString(id) || (i > 0 && r.PolicyIDs[i-1] == id) {
			return fail(CodeInvalid, "policy_ids 형식 오류 또는 중복(%q)", id)
		}
	}
	if !common.IsHexAddress(r.Address) || common.HexToAddress(r.Address).Hex() != r.Address || common.HexToAddress(r.Address) == (common.Address{}) {
		return fail(CodeInvalid, "address 는 0 이 아닌 EIP-55 주소여야 한다")
	}
	t, err := time.Parse(TimeLayout, r.RequestedAt)
	if err != nil || t.UTC().Format(TimeLayout) != r.RequestedAt {
		return fail(CodeInvalid, "requested_at 형식 %s", TimeLayout)
	}
	skew := e.MaxSkew
	if skew == 0 {
		skew = 5 * time.Minute
	}
	if d := now.Sub(t); d > skew || d < -skew {
		return fail(CodeStale, "requested_at 이 서명 서버 시각과 %s 이상 차이 난다", skew)
	}
	return nil
}

// Execute 는 정책 변경을 검증하고 실행한다. 거부는 감사로그(POLICY_CHANGE_REJECTED)에 남는다.
func (e *Executor) Execute(ctx context.Context, r Request, caller string, now time.Time) (*Result, error) {
	res, admins, err := e.execute(ctx, r, now)
	if err != nil {
		var pe *Error
		code, msg := "POLICY_CHANGE_FAILED", err.Error()
		if errors.As(err, &pe) {
			code, msg = pe.Code, pe.Msg
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		_, _ = audit.AppendTx(ctx, e.DB, audit.Entry{Actor: caller, Action: "POLICY_CHANGE_REJECTED", Subject: r.ChangeID, Payload: map[string]any{
			"request_id": r.ChangeID, "type": r.Type, "policy_ids": r.PolicyIDs, "address": r.Address, "code": code, "reason": msg,
			"approvers": admins, "caller": caller,
		}})
		return nil, err
	}
	return res, nil
}

func (e *Executor) execute(ctx context.Context, r Request, now time.Time) (*Result, []string, error) {
	if err := e.validate(r, now); err != nil {
		return nil, nil, err
	}
	admins, err := adminsig.Verify(ctx, e.DB, e.AdminGroup, e.Approvals, r.Message(), r.Approvals)
	var f *adminsig.Failure
	if errors.As(err, &f) {
		code := map[adminsig.Kind]string{adminsig.KindDuplicate: CodeInvalid, adminsig.KindNotAdmin: CodeAdmin,
			adminsig.KindSignature: CodeSignature, adminsig.KindInsufficient: CodeInsufficient}[f.Kind]
		return nil, nil, fail(code, "%s", f.Msg)
	}
	if err != nil {
		return nil, nil, err
	}
	tx, err := e.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, admins, err
	}
	defer func() { _ = tx.Rollback() }()
	h := r.Hash()
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_changes (change_id, type, intent_hash, policy_ids, address) VALUES (?, ?, ?, ?, ?)`,
		r.ChangeID, r.Type, h[:], strings.Join(r.PolicyIDs, ","), r.Address); err != nil {
		var me *mysql.MySQLError
		if errors.As(err, &me) && me.Number == 1062 {
			return nil, admins, fail(CodeReplay, "change_id %s 는 이미 쓰였다", r.ChangeID)
		}
		return nil, admins, err
	}
	added := 0
	for _, id := range r.PolicyIDs {
		var body string
		err := tx.QueryRowContext(ctx, `SELECT body_json FROM policies WHERE policy_id = ? AND status = 'ACTIVE' FOR UPDATE`, id).Scan(&body)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, admins, fail(CodePolicy, "ACTIVE 정책 %s 가 없다", id)
		}
		if err != nil {
			return nil, admins, err
		}
		b, err := policy.ParseBody([]byte(body))
		if err != nil {
			return nil, admins, err
		}
		if !b.RecipientWhitelist {
			return nil, admins, fail(CodePolicy, "정책 %s 는 수신 화이트리스트를 쓰지 않는다", id)
		}
		res, err := tx.ExecContext(ctx, `INSERT IGNORE INTO whitelists (policy_id, account_address) VALUES (?, ?)`, id, r.Address)
		if err != nil {
			return nil, admins, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			added++
		}
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{Actor: "signerd", Action: "POLICY_WHITELIST_ADDED", Subject: r.Address, Payload: map[string]any{
		"request_id": r.ChangeID, "type": r.Type, "policy_ids": r.PolicyIDs, "address": r.Address, "count": added,
		"approvers": admins, "reason": r.Reason,
	}}); err != nil {
		return nil, admins, err
	}
	if err := tx.Commit(); err != nil {
		return nil, admins, err
	}
	return &Result{ChangeID: r.ChangeID, Type: r.Type, PolicyIDs: r.PolicyIDs, Address: r.Address, Added: added}, admins, nil
}
