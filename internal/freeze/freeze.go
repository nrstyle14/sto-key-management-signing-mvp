// Package freeze 는 동결과 해제다(설계서 7.3, FR-3.5, D-5).
//
//   - 동결: 보안관리자 1인이 서명한 요청을 서명 서버가 직접 받는다(업무 서버가 죽어 있어도 동작).
//   - 해제: 보안관리자 M명이 서명한 해제 요청.
//
// 서명 대상은 도메인 문자열과 정규화한 JSON 이다. freeze_id·release_id 는 한 번만 쓰이고,
// requested_at 은 서명 서버 시각과 허용 오차(기본 5분) 안이어야 한다(재전송 방지).
package freeze

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/oklog/ulid/v2"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
)

// 도메인 문자열
const (
	DomainFreeze  = "sto-freeze-v1"
	DomainRelease = "sto-freeze-release-v1"
	TimeLayout    = "2006-01-02T15:04:05Z"
)

// Scope 는 동결 범위다.
type Scope string

// 범위
const (
	ScopeKey         Scope = "KEY"
	ScopeInstitution Scope = "INSTITUTION"
	ScopeLedger      Scope = "LEDGER"
)

// 거부 코드
const (
	CodeInvalid      = "FREEZE_INVALID"
	CodeStale        = "FREEZE_STALE"
	CodeReplay       = "FREEZE_REPLAY"
	CodeTarget       = "FREEZE_TARGET_UNKNOWN"
	CodeExists       = "FREEZE_ALREADY_ACTIVE"
	CodeAdmin        = "FREEZE_NOT_SECURITY_ADMIN"
	CodeSignature    = "FREEZE_INVALID_SIGNATURE"
	CodeNotFound     = "FREEZE_NOT_FOUND"
	CodeReleased     = "FREEZE_ALREADY_RELEASED"
	CodeInsufficient = "FREEZE_RELEASE_INSUFFICIENT"
)

// Error 는 동결·해제 거부다.
type Error struct{ Code, Msg string }

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func fail(code, format string, a ...any) error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Request 는 동결 요청이다.
type Request struct {
	FreezeID    string `json:"freeze_id"`
	Scope       Scope  `json:"scope"`
	Target      string `json:"target"`
	Reason      string `json:"reason"`
	RequestedAt string `json:"requested_at"`
	AdminID     string `json:"admin_id"`
	Signature   string `json:"signature,omitempty"`
}

// ReleaseRequest 는 해제 요청이다.
type ReleaseRequest struct {
	FreezeID    string             `json:"freeze_id"`
	ReleaseID   string             `json:"release_id"`
	RequestedAt string             `json:"requested_at"`
	Approvals   []ReleaseSignature `json:"approvals"`
}

// ReleaseSignature 는 해제에 대한 보안관리자 서명 한 건이다.
type ReleaseSignature struct {
	AdminID   string `json:"admin_id"`
	Signature string `json:"signature"`
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func canonical(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// Message 는 동결 요청의 서명 대상 바이트다(서명 필드 제외).
func (r Request) Message() []byte {
	m := map[string]string{"freeze_id": r.FreezeID, "scope": string(r.Scope), "target": r.Target, "reason": r.Reason,
		"requested_at": r.RequestedAt, "admin_id": r.AdminID}
	return append([]byte(DomainFreeze), canonical(m)...)
}

// ReleaseMessage 는 해제 요청의 서명 대상 바이트다(승인자마다 같다).
func (r ReleaseRequest) ReleaseMessage() []byte {
	m := map[string]string{"freeze_id": r.FreezeID, "release_id": r.ReleaseID, "requested_at": r.RequestedAt}
	return append([]byte(DomainRelease), canonical(m)...)
}

// NewRequest 는 새 동결 요청을 만들고 서명한다(stoctl).
func NewRequest(scope Scope, target, reason, adminID string, priv ed25519.PrivateKey, now time.Time) Request {
	r := Request{FreezeID: ulid.Make().String(), Scope: scope, Target: target, Reason: reason,
		RequestedAt: now.UTC().Format(TimeLayout), AdminID: adminID}
	r.Signature = hex.EncodeToString(ed25519.Sign(priv, r.Message()))
	return r
}

// NewRelease 는 새 해제 요청을 만든다. 승인자마다 SignRelease 로 서명을 붙인다(stoctl).
func NewRelease(freezeID string, now time.Time) ReleaseRequest {
	return ReleaseRequest{FreezeID: freezeID, ReleaseID: ulid.Make().String(), RequestedAt: now.UTC().Format(TimeLayout)}
}

// SignRelease 는 해제 요청에 보안관리자 서명을 붙인다.
func (r *ReleaseRequest) SignRelease(adminID string, priv ed25519.PrivateKey) {
	r.Approvals = append(r.Approvals, ReleaseSignature{AdminID: adminID, Signature: hex.EncodeToString(ed25519.Sign(priv, r.ReleaseMessage()))})
}

// Config 는 서명 서버의 동결 설정이다.
type Config struct {
	AdminGroup       string        // 보안관리자 그룹
	ReleaseApprovals int           // 해제에 필요한 서로 다른 보안관리자 수(M)
	MaxSkew          time.Duration // requested_at 허용 오차
	// TargetExists 는 범위·대상이 실제로 있는지 확인한다.
	TargetExists func(ctx context.Context, scope Scope, target string) (bool, error)
}

func fresh(cfg Config, requestedAt string, now time.Time) error {
	t, err := time.Parse(TimeLayout, requestedAt)
	if err != nil || t.UTC().Format(TimeLayout) != requestedAt {
		return fail(CodeInvalid, "requested_at 형식 %s", TimeLayout)
	}
	skew := cfg.MaxSkew
	if skew == 0 {
		skew = 5 * time.Minute
	}
	if d := now.Sub(t); d > skew || d < -skew {
		return fail(CodeStale, "requested_at 이 서명 서버 시각과 %s 이상 차이 난다", skew)
	}
	return nil
}

// verifyAdmin 은 보안관리자(ACTIVE, SECURITY_ADMIN, 그룹 소속)의 서명을 확인한다.
func verifyAdmin(ctx context.Context, db *sql.DB, cfg Config, adminID, sigHex string, msg []byte) error {
	ap, err := approval.Lookup(ctx, db, adminID)
	if errors.Is(err, approval.ErrNotFound) {
		return fail(CodeAdmin, "등록되지 않은 승인자 %s", adminID)
	}
	if err != nil {
		return err
	}
	inGroup := false
	for _, g := range ap.Groups {
		if g == cfg.AdminGroup {
			inGroup = true
		}
	}
	if ap.Status != "ACTIVE" || ap.Role != "SECURITY_ADMIN" || !inGroup {
		return fail(CodeAdmin, "%s 는 활성 보안관리자가 아니다", adminID)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ap.PublicKey, msg, sig) {
		return fail(CodeSignature, "%s 의 서명이 요청과 맞지 않는다", adminID)
	}
	return nil
}

// Freeze 는 보안관리자 1인이 서명한 동결 요청을 검증하고 기록한다(감사 기록 포함).
func Freeze(ctx context.Context, db *sql.DB, cfg Config, r Request, caller string, now time.Time) error {
	if u, err := ulid.ParseStrict(r.FreezeID); err != nil || u.String() != r.FreezeID {
		return fail(CodeInvalid, "freeze_id 는 대문자 ULID 여야 한다")
	}
	switch r.Scope {
	case ScopeKey, ScopeInstitution, ScopeLedger:
	default:
		return fail(CodeInvalid, "scope 는 KEY, INSTITUTION, LEDGER 중 하나다")
	}
	if !idRe.MatchString(r.Target) || !idRe.MatchString(r.AdminID) || r.Reason == "" || len(r.Reason) > 500 {
		return fail(CodeInvalid, "target, admin_id, reason(1~500자) 형식 오류")
	}
	if err := fresh(cfg, r.RequestedAt, now); err != nil {
		return err
	}
	if err := verifyAdmin(ctx, db, cfg, r.AdminID, r.Signature, r.Message()); err != nil {
		return err
	}
	if ok, err := cfg.TargetExists(ctx, r.Scope, r.Target); err != nil {
		return err
	} else if !ok {
		return fail(CodeTarget, "%s %s 가 없다", r.Scope, r.Target)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM freezes WHERE scope = ? AND target = ? AND released_at IS NULL`, string(r.Scope), r.Target).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fail(CodeExists, "%s %s 는 이미 동결돼 있다", r.Scope, r.Target)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO freezes (freeze_id, scope, target, reason, frozen_by) VALUES (?, ?, ?, ?, ?)`,
		r.FreezeID, string(r.Scope), r.Target, r.Reason, r.AdminID); err != nil {
		var me *mysql.MySQLError
		if errors.As(err, &me) && me.Number == 1062 {
			return fail(CodeReplay, "freeze_id %s 는 이미 쓰였다", r.FreezeID)
		}
		return err
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{Actor: r.AdminID, Action: "FREEZE", Subject: r.FreezeID, Payload: map[string]any{
		"freeze_id": r.FreezeID, "scope": string(r.Scope), "target": r.Target, "reason": r.Reason, "approver_id": r.AdminID, "caller": caller,
	}}); err != nil {
		return err
	}
	return tx.Commit()
}

// Release 는 보안관리자 M명이 서명한 해제 요청을 검증하고 기록한다(감사 기록 포함).
func Release(ctx context.Context, db *sql.DB, cfg Config, r ReleaseRequest, caller string, now time.Time) error {
	if u, err := ulid.ParseStrict(r.ReleaseID); err != nil || u.String() != r.ReleaseID {
		return fail(CodeInvalid, "release_id 는 대문자 ULID 여야 한다")
	}
	if err := fresh(cfg, r.RequestedAt, now); err != nil {
		return err
	}
	seen := map[string]bool{}
	var admins []string
	for _, a := range r.Approvals {
		if seen[a.AdminID] {
			return fail(CodeInvalid, "보안관리자 %s 중복", a.AdminID)
		}
		seen[a.AdminID] = true
		if err := verifyAdmin(ctx, db, cfg, a.AdminID, a.Signature, r.ReleaseMessage()); err != nil {
			return err
		}
		admins = append(admins, a.AdminID)
	}
	if len(admins) < cfg.ReleaseApprovals {
		return fail(CodeInsufficient, "해제에는 보안관리자 %d명의 서명이 필요하다(받은 서명 %d건)", cfg.ReleaseApprovals, len(admins))
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var released sql.NullTime
	var scope, target string
	err = tx.QueryRowContext(ctx, `SELECT scope, target, released_at FROM freezes WHERE freeze_id = ? FOR UPDATE`, r.FreezeID).Scan(&scope, &target, &released)
	if errors.Is(err, sql.ErrNoRows) {
		return fail(CodeNotFound, "동결 %s 가 없다", r.FreezeID)
	}
	if err != nil {
		return err
	}
	if released.Valid {
		return fail(CodeReleased, "동결 %s 는 이미 해제됐다", r.FreezeID)
	}
	// release_id 재사용 방지: 다른 동결의 해제에 쓰인 값도 막는다.
	var used int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM freezes WHERE released_request_id = ?`, r.ReleaseID).Scan(&used); err != nil {
		return err
	}
	if used > 0 {
		return fail(CodeReplay, "release_id %s 는 이미 쓰였다", r.ReleaseID)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE freezes SET released_request_id = ?, released_at = CURRENT_TIMESTAMP(6) WHERE freeze_id = ? AND released_at IS NULL`,
		r.ReleaseID, r.FreezeID); err != nil {
		return err
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{Actor: caller, Action: "FREEZE_RELEASED", Subject: r.FreezeID, Payload: map[string]any{
		"freeze_id": r.FreezeID, "request_id": r.ReleaseID, "scope": scope, "target": target, "approvers": admins, "count": len(admins),
	}}); err != nil {
		return err
	}
	return tx.Commit()
}

// Entry 는 동결 목록 한 행이다.
type Entry struct {
	FreezeID   string     `json:"freeze_id"`
	Scope      string     `json:"scope"`
	Target     string     `json:"target"`
	Reason     string     `json:"reason"`
	FrozenBy   string     `json:"frozen_by"`
	FrozenAt   time.Time  `json:"frozen_at"`
	ReleasedAt *time.Time `json:"released_at,omitempty"`
}

// List 는 동결 목록이다(최근 순).
func List(ctx context.Context, db *sql.DB) ([]Entry, error) {
	rows, err := db.QueryContext(ctx, `SELECT freeze_id, scope, target, reason, frozen_by, frozen_at, released_at FROM freezes ORDER BY frozen_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		var rel sql.NullTime
		if err := rows.Scan(&e.FreezeID, &e.Scope, &e.Target, &e.Reason, &e.FrozenBy, &e.FrozenAt, &rel); err != nil {
			return nil, err
		}
		if rel.Valid {
			t := rel.Time.UTC()
			e.ReleasedAt = &t
		}
		e.FrozenAt = e.FrozenAt.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}
