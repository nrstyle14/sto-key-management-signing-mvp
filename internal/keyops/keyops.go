// Package keyops 는 승인된 키 작업(생성, 퇴역, 폐기)이다(설계서 9절, FR-5.1~5.3, FR-3.4, D-20).
//
// 키 작업은 보안관리자 M명이 서명한 요청을 서명 서버가 직접 받는다(POST /v1/key-ops, 호출자 stoctl).
// 서명 대상은 도메인 문자열 "sto-keyop-v1" 과 정규화한 JSON 이다. 다른 서명(업무 승인 "sto-approval-v1",
// 동결 "sto-freeze-v1")과 도메인이 달라 서로 재사용할 수 없다. op_id 는 한 번만 쓰이고(key_ops 기본 키),
// requested_at 은 서명 서버 시각과 허용 오차(기본 5분) 안이어야 한다.
//
// HSM 작업과 DB 는 원자적이지 않으므로 각 작업은 같은 op_id 로 다시 보내면 이어서 끝낼 수 있게 만든다:
//   - 생성: HSM 에 객체가 이미 있으면(앞선 시도가 등록 전에 멈춤) 그 공개키로 등록한다.
//   - 폐기: HSM 에 객체가 이미 없으면(앞선 시도가 상태 변경 전에 멈춤) 확인만 하고 상태를 바꾼다.
//
// 키 교체(D-20): 새 키는 PENDING 으로 만들고, 이전 키를 퇴역시키는 요청에 후속 키(successor)를 지정하면
// 같은 트랜잭션에서 이전 키 RETIRED, 새 키 ACTIVE 가 된다. 범위당 ACTIVE 키는 언제나 하나 이하다.
package keyops

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
	"math/big"
	"regexp"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/oklog/ulid/v2"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/adminsig"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/backup"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

// 도메인과 시각 형식
const (
	Domain     = "sto-keyop-v1"
	TimeLayout = "2006-01-02T15:04:05Z"
)

// Type 은 키 작업 종류다(signer.key_ops.type).
type Type string

// 키 작업 종류
const (
	TypeGenerate Type = "GENERATE"
	TypeRetire   Type = "RETIRE"
	TypeDestroy  Type = "DESTROY"
	// 백업·복구(T3.6, 설계서 6.3, D-21)
	TypeWrapInstall Type = "WRAP_INSTALL" // 래핑 키를 (원장, 기관) 토큰에 추출 불가 객체로 넣는다
	TypeBackup      Type = "BACKUP"       // 루트 키를 래핑해 백업 파일로 돌려준다
	TypeRestore     Type = "RESTORE"      // 백업 파일을 토큰에 복원한다(레지스트리에 있고 HSM 객체가 없는 키)
)

// 거부 코드
const (
	CodeInvalid      = "KEYOP_INVALID"
	CodeStale        = "KEYOP_STALE"
	CodeReplay       = "KEYOP_REPLAY"
	CodeAdmin        = "KEYOP_NOT_SECURITY_ADMIN"
	CodeSignature    = "KEYOP_INVALID_SIGNATURE"
	CodeInsufficient = "KEYOP_APPROVAL_INSUFFICIENT"
	CodeKeyNotFound  = "KEYOP_KEY_NOT_FOUND"
	CodeKeyState     = "KEYOP_KEY_STATE"
	CodeSuccessor    = "KEYOP_SUCCESSOR_INVALID"
	CodeHSM          = "KEYOP_HSM_FAILED"
	CodeNotDestroyed = "KEYOP_OBJECTS_REMAIN"
	CodeSecret       = "KEYOP_SECRET_MISMATCH"
	CodeBackup       = "KEYOP_BACKUP_INVALID"
	CodeRestore      = "KEYOP_RESTORE_MISMATCH"
)

// Error 는 키 작업 거부다.
type Error struct{ Code, Msg string }

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func fail(code, format string, a ...any) error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Request 는 키 작업 요청이다. 서명은 Approvals 를 뺀 나머지 필드의 Message 에 대한 것이다.
//   - GENERATE: LedgerID, InstitutionID, Purpose, KeyID(새 키 ID), RotatedFrom(교체 대상, 선택)
//   - RETIRE: KeyID, Successor(활성화할 PENDING 키, 선택)
//   - DESTROY: KeyID
//   - WRAP_INSTALL: LedgerID, InstitutionID(토큰), KeyID(래핑 키 ID), SecretSHA256, Secret
//   - BACKUP: KeyID(루트 키), WrapKeyID
//   - RESTORE: KeyID, WrapKeyID, BackupSHA256, Backup, (토큰에 래핑 키가 없으면) SecretSHA256·Secret
//
// Secret(래핑 키 값)과 Backup(백업 파일)은 서명 대상에 직접 넣지 않고 SHA-256 약속값으로 묶는다.
// Secret 은 감사로그·응답에 남기지 않는다.
type Request struct {
	OpID          string         `json:"op_id"`
	Type          Type           `json:"type"`
	LedgerID      string         `json:"ledger_id,omitempty"`
	InstitutionID string         `json:"institution_id,omitempty"`
	Purpose       signer.Purpose `json:"purpose,omitempty"`
	KeyID         string         `json:"key_id"`
	RotatedFrom   string         `json:"rotated_from,omitempty"`
	Successor     string         `json:"successor,omitempty"`
	WrapKeyID     string         `json:"wrap_key_id,omitempty"`
	SecretSHA256  string         `json:"secret_sha256,omitempty"`
	BackupSHA256  string         `json:"backup_sha256,omitempty"`
	Reason        string         `json:"reason"`
	RequestedAt   string         `json:"requested_at"`
	Approvals     []Signature    `json:"approvals"`
	Secret        string         `json:"secret,omitempty"` // 16진수 32바이트. 서명 대상 아님(SecretSHA256 로 묶음)
	Backup        *backup.File   `json:"backup,omitempty"` // 서명 대상 아님(BackupSHA256 로 묶음)
}

// Signature 는 보안관리자 서명 한 건이다.
type Signature = adminsig.Signature

// Result 는 실행 결과다.
type Result struct {
	OpID     string `json:"op_id"`
	Type     Type   `json:"type"`
	KeyID    string `json:"key_id"`
	Status   string `json:"status"` // 작업 뒤 키 상태
	Address  string `json:"address,omitempty"`
	Activate string `json:"activated,omitempty"` // RETIRE 로 활성화된 후속 키
	// ObjectsRemaining 은 폐기 뒤 HSM 에 남은 객체 수다(0 이어야 한다).
	ObjectsRemaining *int `json:"objects_remaining,omitempty"`
	// Backup 은 BACKUP 결과(래핑된 암호문, 공개 정보)다.
	Backup *backup.File `json:"backup,omitempty"`
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Message 는 서명 대상 바이트다(승인자마다 같다).
func (r Request) Message() []byte {
	m := map[string]string{"op_id": r.OpID, "type": string(r.Type), "ledger_id": r.LedgerID, "institution_id": r.InstitutionID,
		"purpose": string(r.Purpose), "key_id": r.KeyID, "rotated_from": r.RotatedFrom, "successor": r.Successor,
		"wrap_key_id": r.WrapKeyID, "secret_sha256": r.SecretSHA256, "backup_sha256": r.BackupSHA256,
		"reason": r.Reason, "requested_at": r.RequestedAt}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(m)
	return append([]byte(Domain), bytes.TrimRight(buf.Bytes(), "\n")...)
}

// Hash 는 SHA-256(Message) 다(key_ops.intent_hash).
func (r Request) Hash() [32]byte { return sha256.Sum256(r.Message()) }

// New 는 새 요청을 만든다(stoctl). 보안관리자마다 Sign 으로 서명을 붙인다.
func New(t Type, now time.Time) Request {
	return Request{OpID: ulid.Make().String(), Type: t, RequestedAt: now.UTC().Format(TimeLayout)}
}

// Sign 은 보안관리자 서명을 붙인다.
func (r *Request) Sign(adminID string, priv ed25519.PrivateKey) {
	r.Approvals = append(r.Approvals, Signature{AdminID: adminID, Signature: hex.EncodeToString(ed25519.Sign(priv, r.Message()))})
}

// HSM 은 키 작업에 쓰는 HSM 기능이다(signer/hsm.Signer 가 구현). 이 패키지는 internal/hsm 을 import 하지 않는다.
type HSM interface {
	Generate(ctx context.Context, spec signer.KeySpec) (signer.PublicKey, error)
	PublicKeyOf(ctx context.Context, tokenLabel, keyID string) (signer.PublicKey, error)
	DestroyIn(ctx context.Context, tokenLabel, keyID string) error
	ObjectCount(ctx context.Context, tokenLabel, keyID string) (int, error)
}

// Wrapper 는 백업·복구에 쓰는 HSM 기능이다(signer/hsm.Signer 가 구현).
type Wrapper interface {
	InjectWrappingKey(ctx context.Context, tokenLabel, wrapKeyID string, key []byte) error
	HasWrappingKey(ctx context.Context, tokenLabel, wrapKeyID string) (bool, error)
	WrapPrivateKey(ctx context.Context, tokenLabel, wrapKeyID, keyID string) ([]byte, error)
	UnwrapPrivateKey(ctx context.Context, tokenLabel, wrapKeyID, keyID string, wrapped, pub []byte) error
	SignDigest(ctx context.Context, keyID string, digest [32]byte) (*big.Int, *big.Int, error)
}

// Executor 는 서명 서버의 키 작업 실행기다.
type Executor struct {
	DB         *sql.DB
	HSM        HSM
	Wrap       Wrapper       // nil 이면 백업·복구 작업을 거부한다
	AdminGroup string        // 보안관리자 그룹
	Approvals  int           // 필요한 서로 다른 보안관리자 수(M)
	MaxSkew    time.Duration // requested_at 허용 오차(기본 5분)
}

func (e *Executor) validate(r Request, now time.Time) error {
	if u, err := ulid.ParseStrict(r.OpID); err != nil || u.String() != r.OpID {
		return fail(CodeInvalid, "op_id 는 대문자 ULID 여야 한다")
	}
	if !idRe.MatchString(r.KeyID) || r.Reason == "" || len(r.Reason) > 500 {
		return fail(CodeInvalid, "key_id 형식, reason(1~500자) 오류")
	}
	switch r.Type {
	case TypeGenerate:
		if !idRe.MatchString(r.LedgerID) || !idRe.MatchString(r.InstitutionID) {
			return fail(CodeInvalid, "생성에는 ledger_id, institution_id 가 필요하다")
		}
		if _, err := signer.ClassOf(r.Purpose); err != nil {
			return fail(CodeInvalid, "알 수 없는 용도 %q", r.Purpose)
		}
		if r.Successor != "" || (r.RotatedFrom != "" && !idRe.MatchString(r.RotatedFrom)) {
			return fail(CodeInvalid, "생성 요청의 successor 는 비어 있어야 한다")
		}
	case TypeRetire:
		if r.LedgerID != "" || r.InstitutionID != "" || r.Purpose != "" || r.RotatedFrom != "" || (r.Successor != "" && !idRe.MatchString(r.Successor)) {
			return fail(CodeInvalid, "퇴역 요청에는 key_id 와 successor 만 쓴다")
		}
	case TypeDestroy:
		if r.LedgerID != "" || r.InstitutionID != "" || r.Purpose != "" || r.RotatedFrom != "" || r.Successor != "" {
			return fail(CodeInvalid, "폐기 요청에는 key_id 만 쓴다")
		}
	case TypeWrapInstall:
		if !idRe.MatchString(r.LedgerID) || !idRe.MatchString(r.InstitutionID) || len(r.SecretSHA256) != 64 || r.Secret == "" {
			return fail(CodeInvalid, "래핑 키 주입에는 ledger_id, institution_id, secret_sha256, secret 이 필요하다")
		}
	case TypeBackup:
		if !idRe.MatchString(r.WrapKeyID) || r.Secret != "" || r.Backup != nil {
			return fail(CodeInvalid, "백업에는 key_id, wrap_key_id 만 쓴다")
		}
	case TypeRestore:
		if !idRe.MatchString(r.WrapKeyID) || r.Backup == nil || len(r.BackupSHA256) != 64 {
			return fail(CodeInvalid, "복원에는 wrap_key_id, backup, backup_sha256 이 필요하다")
		}
	default:
		return fail(CodeInvalid, "알 수 없는 작업 %q", r.Type)
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

// verifyApprovals 는 서로 다른 활성 보안관리자 M명의 서명을 확인하고 그 ID 목록을 돌려준다(adminsig).
func (e *Executor) verifyApprovals(ctx context.Context, r Request) ([]string, error) {
	ids, err := adminsig.Verify(ctx, e.DB, e.AdminGroup, e.Approvals, r.Message(), r.Approvals)
	var f *adminsig.Failure
	if errors.As(err, &f) {
		code := map[adminsig.Kind]string{adminsig.KindDuplicate: CodeInvalid, adminsig.KindNotAdmin: CodeAdmin,
			adminsig.KindSignature: CodeSignature, adminsig.KindInsufficient: CodeInsufficient}[f.Kind]
		return nil, fail(code, "%s", f.Msg)
	}
	return ids, err
}

// Execute 는 키 작업을 검증하고 실행한다. 거부와 실패는 감사로그(KEYOP_REJECTED)에 남는다.
func (e *Executor) Execute(ctx context.Context, r Request, caller string, now time.Time) (*Result, error) {
	res, admins, err := e.execute(ctx, r, now)
	if err != nil {
		var ke *Error
		code, msg := CodeHSM, err.Error()
		if errors.As(err, &ke) {
			code, msg = ke.Code, ke.Msg
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		_, _ = audit.AppendTx(ctx, e.DB, audit.Entry{Actor: caller, Action: "KEYOP_REJECTED", Subject: r.OpID, Payload: map[string]any{
			"request_id": r.OpID, "type": string(r.Type), "key_id": r.KeyID, "code": code, "reason": msg, "approvers": admins, "caller": caller,
		}})
		return nil, err
	}
	return res, nil
}

func (e *Executor) execute(ctx context.Context, r Request, now time.Time) (*Result, []string, error) {
	if err := e.validate(r, now); err != nil {
		return nil, nil, err
	}
	admins, err := e.verifyApprovals(ctx, r)
	if err != nil {
		return nil, nil, err
	}
	if err := e.reserve(ctx, r); err != nil {
		return nil, admins, err
	}
	var res *Result
	switch r.Type {
	case TypeGenerate:
		res, err = e.generate(ctx, r, admins)
	case TypeRetire:
		res, err = e.retire(ctx, r, admins)
	case TypeDestroy:
		res, err = e.destroy(ctx, r, admins)
	case TypeWrapInstall, TypeBackup, TypeRestore:
		if e.Wrap == nil {
			err = fail(CodeInvalid, "이 서명 서버는 백업·복구를 지원하지 않는다")
			break
		}
		switch r.Type {
		case TypeWrapInstall:
			res, err = e.wrapInstall(ctx, r, admins)
		case TypeBackup:
			res, err = e.backup(ctx, r, admins)
		default:
			res, err = e.restore(ctx, r, admins)
		}
	}
	if err != nil {
		_, _ = e.DB.ExecContext(ctx, `UPDATE key_ops SET result = 'FAILED', done_at = CURRENT_TIMESTAMP(6) WHERE request_id = ? AND result <> 'DONE'`, r.OpID)
		return nil, admins, err
	}
	return res, admins, nil
}

// reserve 는 op_id 를 key_ops 에 기록한다. 이미 끝난(DONE) op_id 는 재전송으로 거부하고,
// 끝나지 않은(PENDING·FAILED) op_id 는 같은 내용일 때만 이어서 실행한다.
func (e *Executor) reserve(ctx context.Context, r Request) error {
	h := r.Hash()
	_, err := e.DB.ExecContext(ctx, `INSERT INTO key_ops (request_id, type, intent_hash, key_id, result) VALUES (?, ?, ?, ?, 'PENDING')`,
		r.OpID, string(r.Type), h[:], r.KeyID)
	var me *mysql.MySQLError
	if err == nil {
		return nil
	}
	if !errors.As(err, &me) || me.Number != 1062 {
		return err
	}
	var result string
	var stored []byte
	if err := e.DB.QueryRowContext(ctx, `SELECT result, intent_hash FROM key_ops WHERE request_id = ?`, r.OpID).Scan(&result, &stored); err != nil {
		return err
	}
	if result == "DONE" || !bytes.Equal(stored, h[:]) {
		return fail(CodeReplay, "op_id %s 는 이미 쓰였다", r.OpID)
	}
	_, err = e.DB.ExecContext(ctx, `UPDATE key_ops SET result = 'PENDING' WHERE request_id = ?`, r.OpID)
	return err
}

func done(ctx context.Context, tx *sql.Tx, opID string) error {
	_, err := tx.ExecContext(ctx, `UPDATE key_ops SET result = 'DONE', done_at = CURRENT_TIMESTAMP(6) WHERE request_id = ?`, opID)
	return err
}

// generate 는 (원장, 기관) 토큰에 새 키를 만들고 레지스트리에 등록한다.
// 같은 범위에 ACTIVE 키가 없으면 ACTIVE, 있으면 PENDING 으로 등록한다(교체용, 퇴역 요청의 successor 로 활성화).
func (e *Executor) generate(ctx context.Context, r Request, admins []string) (*Result, error) {
	tok, err := keyreg.TokenFor(ctx, e.DB, r.LedgerID, r.InstitutionID)
	if err != nil {
		return nil, fail(CodeInvalid, "%v", err)
	}
	if existing, err := keyreg.Get(ctx, e.DB, r.KeyID); err == nil {
		return nil, fail(CodeKeyState, "키 %s 가 이미 레지스트리에 있다(%s)", r.KeyID, existing.Status)
	} else if !errors.Is(err, keyreg.ErrKeyNotFound) {
		return nil, err
	}
	if r.RotatedFrom != "" {
		old, err := keyreg.Get(ctx, e.DB, r.RotatedFrom)
		if err != nil {
			return nil, fail(CodeKeyNotFound, "교체 대상 %s: %v", r.RotatedFrom, err)
		}
		if old.LedgerID != r.LedgerID || old.InstitutionID != r.InstitutionID || old.Purpose != r.Purpose || old.Status != keyreg.StatusActive {
			return nil, fail(CodeKeyState, "교체 대상 %s 는 같은 범위의 ACTIVE 키가 아니다", r.RotatedFrom)
		}
	}
	// 이전 시도가 HSM 생성 뒤 등록 전에 멈췄으면 그 객체를 쓴다.
	n, err := e.HSM.ObjectCount(ctx, tok.Label, r.KeyID)
	if err != nil {
		return nil, fail(CodeHSM, "HSM 조회: %v", err)
	}
	var pub signer.PublicKey
	if n > 0 {
		if pub, err = e.HSM.PublicKeyOf(ctx, tok.Label, r.KeyID); err != nil {
			return nil, fail(CodeHSM, "HSM 에 남은 객체 확인: %v", err)
		}
	} else if pub, err = e.HSM.Generate(ctx, signer.KeySpec{KeyID: r.KeyID, TokenLabel: tok.Label, Purpose: r.Purpose}); err != nil {
		return nil, fail(CodeHSM, "HSM 생성: %v", err)
	}
	addr, err := pub.Address()
	if err != nil {
		return nil, err
	}
	tx, err := e.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	status := keyreg.StatusActive
	if _, err := keyreg.Lookup(ctx, tx, r.LedgerID, r.InstitutionID, r.Purpose); err == nil || errors.Is(err, keyreg.ErrAmbiguousKey) {
		status = keyreg.StatusPending
	} else if !errors.Is(err, keyreg.ErrNoActiveKey) {
		return nil, err
	}
	if r.RotatedFrom != "" {
		status = keyreg.StatusPending
	}
	if err := keyreg.RegisterKey(ctx, tx, keyreg.Key{KeyID: r.KeyID, TokenID: tok.TokenID, Purpose: r.Purpose, PublicKey: pub,
		RotatedFrom: r.RotatedFrom, Status: status}); err != nil {
		return nil, err
	}
	if err := done(ctx, tx, r.OpID); err != nil {
		return nil, err
	}
	class, _ := signer.ClassOf(r.Purpose)
	if _, err := audit.Append(ctx, tx, audit.Entry{Actor: "signerd", Action: "KEY_GENERATED", Subject: r.KeyID, Payload: map[string]any{
		"request_id": r.OpID, "key_id": r.KeyID, "token": tok.Label, "purpose": string(r.Purpose), "class": string(class),
		"address": addr.Hex(), "status": string(status), "approvers": admins, "reason": r.Reason, "target": r.RotatedFrom,
	}}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Result{OpID: r.OpID, Type: r.Type, KeyID: r.KeyID, Status: string(status), Address: addr.Hex()}, nil
}

// retire 는 ACTIVE(또는 PENDING) 키를 RETIRED 로 바꾼다. successor 가 있으면 같은 트랜잭션에서 그 PENDING 키를 ACTIVE 로 바꾼다.
func (e *Executor) retire(ctx context.Context, r Request, admins []string) (*Result, error) {
	tx, err := e.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	k, err := keyreg.Get(ctx, tx, r.KeyID)
	if errors.Is(err, keyreg.ErrKeyNotFound) {
		return nil, fail(CodeKeyNotFound, "키 %s 가 없다", r.KeyID)
	}
	if err != nil {
		return nil, err
	}
	if k.Status != keyreg.StatusActive && k.Status != keyreg.StatusPending {
		return nil, fail(CodeKeyState, "키 %s 는 %s 다(ACTIVE·PENDING 만 퇴역)", r.KeyID, k.Status)
	}
	if err := keyreg.SetStatus(ctx, tx, k.KeyID, k.Status, keyreg.StatusRetired); err != nil {
		return nil, fail(CodeKeyState, "%v", err)
	}
	res := &Result{OpID: r.OpID, Type: r.Type, KeyID: r.KeyID, Status: string(keyreg.StatusRetired), Address: k.Address.Hex()}
	if r.Successor != "" {
		s, err := keyreg.Get(ctx, tx, r.Successor)
		if err != nil {
			return nil, fail(CodeSuccessor, "후속 키 %s: %v", r.Successor, err)
		}
		if s.Status != keyreg.StatusPending || s.LedgerID != k.LedgerID || s.InstitutionID != k.InstitutionID || s.Purpose != k.Purpose || s.RotatedFrom != k.KeyID {
			return nil, fail(CodeSuccessor, "후속 키 %s 는 %s 를 교체하려고 만든 같은 범위의 PENDING 키가 아니다", r.Successor, k.KeyID)
		}
		if err := keyreg.SetStatus(ctx, tx, s.KeyID, keyreg.StatusPending, keyreg.StatusActive); err != nil {
			return nil, fail(CodeKeyState, "%v", err)
		}
		res.Activate = s.KeyID
		if _, err := audit.Append(ctx, tx, audit.Entry{Actor: "signerd", Action: "KEY_ACTIVATED", Subject: s.KeyID, Payload: map[string]any{
			"request_id": r.OpID, "key_id": s.KeyID, "address": s.Address.Hex(), "target": k.KeyID, "approvers": admins,
		}}); err != nil {
			return nil, err
		}
	}
	if err := done(ctx, tx, r.OpID); err != nil {
		return nil, err
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{Actor: "signerd", Action: "KEY_RETIRED", Subject: k.KeyID, Payload: map[string]any{
		"request_id": r.OpID, "key_id": k.KeyID, "address": k.Address.Hex(), "from_status": string(k.Status), "status": string(keyreg.StatusRetired),
		"target": r.Successor, "approvers": admins, "reason": r.Reason,
	}}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return res, nil
}

// destroy 는 RETIRED 키의 HSM 객체를 지우고, 남은 객체가 없는지 확인한 뒤 DESTROYED 로 바꾼다(폐기 증적).
func (e *Executor) destroy(ctx context.Context, r Request, admins []string) (*Result, error) {
	k, err := keyreg.Get(ctx, e.DB, r.KeyID)
	if errors.Is(err, keyreg.ErrKeyNotFound) {
		return nil, fail(CodeKeyNotFound, "키 %s 가 없다", r.KeyID)
	}
	if err != nil {
		return nil, err
	}
	if k.Status != keyreg.StatusRetired {
		return nil, fail(CodeKeyState, "키 %s 는 %s 다(RETIRED 키만 폐기)", r.KeyID, k.Status)
	}
	before, err := e.HSM.ObjectCount(ctx, k.TokenLabel, k.KeyID)
	if err != nil {
		return nil, fail(CodeHSM, "HSM 조회: %v", err)
	}
	if before > 0 {
		if err := e.HSM.DestroyIn(ctx, k.TokenLabel, k.KeyID); err != nil {
			return nil, fail(CodeHSM, "C_DestroyObject: %v", err)
		}
	}
	after, err := e.HSM.ObjectCount(ctx, k.TokenLabel, k.KeyID)
	if err != nil {
		return nil, fail(CodeHSM, "HSM 재조회: %v", err)
	}
	if after != 0 {
		return nil, fail(CodeNotDestroyed, "삭제 뒤에도 키 %s 객체 %d개가 남았다", k.KeyID, after)
	}
	tx, err := e.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := keyreg.SetStatus(ctx, tx, k.KeyID, keyreg.StatusRetired, keyreg.StatusDestroyed); err != nil {
		return nil, fail(CodeKeyState, "%v", err)
	}
	if err := done(ctx, tx, r.OpID); err != nil {
		return nil, err
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{Actor: "signerd", Action: "KEY_DESTROYED", Subject: k.KeyID, Payload: map[string]any{
		"request_id": r.OpID, "key_id": k.KeyID, "token": k.TokenLabel, "address": k.Address.Hex(), "purpose": string(k.Purpose),
		"objects_before": before, "objects_after": after, "status": string(keyreg.StatusDestroyed), "approvers": admins, "reason": r.Reason,
	}}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	zero := 0
	return &Result{OpID: r.OpID, Type: r.Type, KeyID: k.KeyID, Status: string(keyreg.StatusDestroyed), Address: k.Address.Hex(), ObjectsRemaining: &zero}, nil
}
