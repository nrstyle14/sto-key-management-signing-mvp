// Package keyreg 는 키 레지스트리와 키 상태를 다룬다(FR-2.3, 설계서 9절, 12.1).
//
// 서명에 쓸 키는 Lookup(원장, 기관, 용도)으로만 찾는다. 호출자가 key_id 나 토큰을 지정해 서명받는 경로는 없다(FR-2.1).
package keyreg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/store"
)

// Status 는 키 상태다(설계서 9절).
type Status string

// 키 상태
const (
	// StatusPending 은 교체용으로 만들었지만 아직 서명에 쓰지 않는 키다(T3.5, D-20).
	// 이전 키를 퇴역시키는 같은 트랜잭션에서 ACTIVE 가 된다. 범위당 ACTIVE 키는 계속 하나다.
	StatusPending   Status = "PENDING"
	StatusActive    Status = "ACTIVE"
	StatusFrozen    Status = "FROZEN"
	StatusRetired   Status = "RETIRED"
	StatusDestroyed Status = "DESTROYED"
)

// 허용되는 상태 전이: PENDING → ACTIVE, ACTIVE → FROZEN ↔ ACTIVE, ACTIVE → RETIRED → DESTROYED,
// PENDING → RETIRED(교체 취소). RETIRED·DESTROYED 에서 다시 쓰는 전이는 없다.
var transitions = map[Status][]Status{
	StatusPending: {StatusActive, StatusRetired},
	StatusActive:  {StatusFrozen, StatusRetired},
	StatusFrozen:  {StatusActive},
	StatusRetired: {StatusDestroyed},
}

// 오류
var (
	ErrNoActiveKey         = errors.New("keyreg: 해당 (원장, 기관, 용도)의 ACTIVE 키가 없다")
	ErrAmbiguousKey        = errors.New("keyreg: 해당 (원장, 기관, 용도)의 ACTIVE 키가 여러 개다")
	ErrKeyNotFound         = errors.New("keyreg: 키가 없다")
	ErrInvalidTransition   = errors.New("keyreg: 허용되지 않은 상태 전이")
	ErrStatusChanged       = errors.New("keyreg: 키 상태가 이미 바뀌었다")
	ErrClassMismatch       = errors.New("keyreg: 키 부류가 용도와 맞지 않는다")
	ErrAddressMismatch     = errors.New("keyreg: 주소가 공개키와 맞지 않는다")
	ErrAlreadyBootstrapped = errors.New("keyreg: 이미 초기화(bootstrap)됐다")
)

// Token 은 HSM 토큰 레지스트리 행이다.
type Token struct {
	TokenID       string
	Label         string
	LedgerID      string
	InstitutionID string
	Status        string
}

// Key 는 키 레지스트리 행과 토큰 정보다.
type Key struct {
	KeyID         string
	TokenID       string
	TokenLabel    string
	LedgerID      string
	InstitutionID string
	Purpose       signer.Purpose
	Class         signer.Class
	PublicKey     signer.PublicKey
	Address       common.Address
	Status        Status
	RotatedFrom   string
	CreatedAt     time.Time
	RetiredAt     *time.Time
	DestroyedAt   *time.Time
}

// RegisterToken 은 토큰을 등록한다.
func RegisterToken(ctx context.Context, db store.DBTX, t Token) error {
	if t.TokenID == "" || t.Label == "" || t.LedgerID == "" || t.InstitutionID == "" {
		return errors.New("keyreg: 토큰 필드가 비었다")
	}
	if t.Status == "" {
		t.Status = "ACTIVE"
	}
	_, err := db.ExecContext(ctx, `INSERT INTO hsm_tokens (token_id, label, ledger_id, institution_id, status) VALUES (?, ?, ?, ?, ?)`,
		t.TokenID, t.Label, t.LedgerID, t.InstitutionID, t.Status)
	if err != nil {
		return fmt.Errorf("keyreg: 토큰 등록(%s): %w", t.TokenID, err)
	}
	return nil
}

// RegisterKey 는 키를 등록한다(상태를 비우면 ACTIVE, 교체용은 PENDING 만 허용).
// 부류는 용도로 정해지고(D-3), 주소는 공개키에서 다시 계산해 대조한다.
func RegisterKey(ctx context.Context, db store.DBTX, k Key) error {
	if k.Status == "" {
		k.Status = StatusActive
	}
	if k.Status != StatusActive && k.Status != StatusPending {
		return fmt.Errorf("keyreg: 등록 상태는 ACTIVE 또는 PENDING 이다(%s)", k.Status)
	}
	if k.KeyID == "" || k.TokenID == "" {
		return errors.New("keyreg: key_id, token_id 가 필요하다")
	}
	class, err := signer.ClassOf(k.Purpose)
	if err != nil {
		return err
	}
	if k.Class == "" {
		k.Class = class
	}
	if k.Class != class {
		return fmt.Errorf("%w: %s 는 %s 여야 한다", ErrClassMismatch, k.Purpose, class)
	}
	addr, err := k.PublicKey.Address()
	if err != nil {
		return err
	}
	if k.Address != (common.Address{}) && k.Address != addr {
		return ErrAddressMismatch
	}
	var rotated any
	if k.RotatedFrom != "" {
		rotated = k.RotatedFrom
	}
	_, err = db.ExecContext(ctx, `INSERT INTO `+"`keys`"+` (key_id, token_id, purpose, class, public_key, address, status, rotated_from)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		k.KeyID, k.TokenID, string(k.Purpose), string(k.Class), []byte(k.PublicKey), addr.Hex(), string(k.Status), rotated)
	if err != nil {
		return fmt.Errorf("keyreg: 키 등록(%s): %w", k.KeyID, err)
	}
	return nil
}

const keySelect = `SELECT k.key_id, k.token_id, t.label, t.ledger_id, t.institution_id, k.purpose, k.class,
	k.public_key, k.address, k.status, COALESCE(k.rotated_from, ''), k.created_at, k.retired_at, k.destroyed_at
	FROM ` + "`keys`" + ` k JOIN hsm_tokens t ON t.token_id = k.token_id `

func scanKeys(rows *sql.Rows) ([]Key, error) {
	defer rows.Close()
	var out []Key
	for rows.Next() {
		var k Key
		var purpose, class, addr, status string
		var pub []byte
		var retired, destroyed sql.NullTime
		if err := rows.Scan(&k.KeyID, &k.TokenID, &k.TokenLabel, &k.LedgerID, &k.InstitutionID, &purpose, &class,
			&pub, &addr, &status, &k.RotatedFrom, &k.CreatedAt, &retired, &destroyed); err != nil {
			return nil, err
		}
		if retired.Valid {
			t := retired.Time.UTC()
			k.RetiredAt = &t
		}
		if destroyed.Valid {
			t := destroyed.Time.UTC()
			k.DestroyedAt = &t
		}
		k.Purpose, k.Class, k.Status = signer.Purpose(purpose), signer.Class(class), Status(status)
		k.PublicKey = signer.PublicKey(pub)
		if !common.IsHexAddress(addr) {
			return nil, fmt.Errorf("keyreg: 저장된 주소 형식 오류(%s)", k.KeyID)
		}
		k.Address = common.HexToAddress(addr)
		out = append(out, k)
	}
	return out, rows.Err()
}

// Lookup 은 (원장, 기관, 용도)의 ACTIVE 키를 돌려준다. 서명 키를 얻는 유일한 경로다.
// 토큰의 원장·기관으로 걸러서, 다른 기관이나 다른 용도의 키는 나오지 않는다.
func Lookup(ctx context.Context, db store.DBTX, ledgerID, institutionID string, purpose signer.Purpose) (*Key, error) {
	rows, err := db.QueryContext(ctx, keySelect+
		`WHERE t.ledger_id = ? AND t.institution_id = ? AND k.purpose = ? AND k.status = 'ACTIVE' AND t.status = 'ACTIVE'`,
		ledgerID, institutionID, string(purpose))
	if err != nil {
		return nil, fmt.Errorf("keyreg: 키 조회: %w", err)
	}
	keys, err := scanKeys(rows)
	if err != nil {
		return nil, err
	}
	switch len(keys) {
	case 0:
		return nil, ErrNoActiveKey
	case 1:
		return &keys[0], nil
	default:
		return nil, ErrAmbiguousKey
	}
}

// Get 은 key_id 로 키를 조회한다(관리·점검용. 서명 키 선택에는 쓰지 않는다).
func Get(ctx context.Context, db store.DBTX, keyID string) (*Key, error) {
	rows, err := db.QueryContext(ctx, keySelect+`WHERE k.key_id = ?`, keyID)
	if err != nil {
		return nil, fmt.Errorf("keyreg: 키 조회: %w", err)
	}
	keys, err := scanKeys(rows)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, ErrKeyNotFound
	}
	return &keys[0], nil
}

// ListByStatus 는 주어진 상태의 키 목록이다(기동 점검용).
func ListByStatus(ctx context.Context, db store.DBTX, statuses ...Status) ([]Key, error) {
	if len(statuses) == 0 {
		return nil, nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(statuses)), ",")
	args := make([]any, len(statuses))
	for i, s := range statuses {
		args[i] = string(s)
	}
	rows, err := db.QueryContext(ctx, keySelect+`WHERE k.status IN (`+ph+`) ORDER BY k.key_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("keyreg: 키 목록: %w", err)
	}
	return scanKeys(rows)
}

// TokenFor 는 (원장, 기관)의 ACTIVE 토큰이다(키 생성용).
func TokenFor(ctx context.Context, db store.DBTX, ledgerID, institutionID string) (*Token, error) {
	var t Token
	err := db.QueryRowContext(ctx, `SELECT token_id, label, ledger_id, institution_id, status FROM hsm_tokens
		WHERE ledger_id = ? AND institution_id = ? AND status = 'ACTIVE'`, ledgerID, institutionID).Scan(&t.TokenID, &t.Label, &t.LedgerID, &t.InstitutionID, &t.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("keyreg: (%s, %s) 의 ACTIVE 토큰이 없다", ledgerID, institutionID)
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// TokenLabelOf 는 key_id 가 든 토큰 라벨이다(signer/hsm 의 Resolver).
func TokenLabelOf(db store.DBTX) func(ctx context.Context, keyID string) (string, error) {
	return func(ctx context.Context, keyID string) (string, error) {
		k, err := Get(ctx, db, keyID)
		if err != nil {
			return "", err
		}
		return k.TokenLabel, nil
	}
}

// SetStatus 는 from → to 전이를 조건부 갱신으로 한다. 허용되지 않은 전이와 이미 바뀐 상태는 거부한다.
func SetStatus(ctx context.Context, db store.DBTX, keyID string, from, to Status) error {
	ok := false
	for _, s := range transitions[from] {
		if s == to {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("%w: %s → %s", ErrInvalidTransition, from, to)
	}
	col := ""
	switch to {
	case StatusRetired:
		col = ", retired_at = CURRENT_TIMESTAMP(6)"
	case StatusDestroyed:
		col = ", destroyed_at = CURRENT_TIMESTAMP(6)"
	}
	res, err := db.ExecContext(ctx, "UPDATE `keys` SET status = ?"+col+" WHERE key_id = ? AND status = ?", string(to), keyID, string(from))
	if err != nil {
		return fmt.Errorf("keyreg: 상태 변경: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("%w: %s (기대 %s)", ErrStatusChanged, keyID, from)
	}
	return nil
}
