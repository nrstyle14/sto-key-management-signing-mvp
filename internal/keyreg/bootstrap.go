package keyreg

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/policy"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

// BootstrapFile 은 signerd init --bootstrap 의 입력이다(설계서 7.2). 한 번만 적용한다.
// 승인자 공개키(T2.2)와 정책 본문(T2.3)은 M1 에서 최소 검증만 하고 그대로 저장한다.
type BootstrapFile struct {
	Tokens    []BootstrapToken    `yaml:"tokens"`
	Keys      []BootstrapKey      `yaml:"keys"`
	Approvers []BootstrapApprover `yaml:"approvers"`
	Policies  []BootstrapPolicy   `yaml:"policies"`
}

// BootstrapToken 은 등록할 토큰이다. 원장·기관은 signerd 설정의 같은 라벨 토큰에서 가져온다.
type BootstrapToken struct {
	Label string `yaml:"label"`
}

// BootstrapKey 는 HSM 에 만들 초기 키다.
type BootstrapKey struct {
	KeyID   string         `yaml:"key_id"`
	Token   string         `yaml:"token"`
	Purpose signer.Purpose `yaml:"purpose"`
}

// BootstrapApprover 는 승인자다. ed25519_pubkey 는 32바이트 16진수다.
type BootstrapApprover struct {
	ApproverID    string   `yaml:"approver_id"`
	Name          string   `yaml:"name"`
	InstitutionID string   `yaml:"institution_id"`
	Role          string   `yaml:"role"`
	Ed25519Pubkey string   `yaml:"ed25519_pubkey"`
	Groups        []string `yaml:"groups"`
}

// BootstrapPolicy 는 초기 정책이다(설계서 7.2). body 는 엄격한 형식(policy.Body)이고 whitelist 는 수신 계좌 주소다.
type BootstrapPolicy struct {
	PolicyID      string         `yaml:"policy_id"`
	LedgerID      string         `yaml:"ledger_id"`
	InstitutionID string         `yaml:"institution_id"`
	KeyPurpose    signer.Purpose `yaml:"key_purpose"`
	Body          *policy.Body   `yaml:"body"`
	Whitelist     []string       `yaml:"whitelist"`
}

// TokenScope 는 signerd 설정에 있는 토큰의 원장·기관이다.
type TokenScope struct {
	Label         string
	LedgerID      string
	InstitutionID string
}

// KeyMaker 는 부트스트랩이 쓰는 HSM 키 생성·삭제다.
type KeyMaker interface {
	Generate(ctx context.Context, spec signer.KeySpec) (signer.PublicKey, error)
	DestroyIn(ctx context.Context, tokenLabel, keyID string) error
}

var roles = map[string]bool{"DRAFTER": true, "APPROVER": true, "SECURITY_ADMIN": true}

// Validate 는 파일을 설정의 토큰 목록과 대조한다.
func (f *BootstrapFile) Validate(scopes map[string]TokenScope) error {
	var errs []error
	if len(f.Tokens) == 0 || len(f.Keys) == 0 {
		errs = append(errs, errors.New("tokens 와 keys 가 필요하다"))
	}
	listed := map[string]bool{}
	for _, t := range f.Tokens {
		if _, ok := scopes[t.Label]; !ok {
			errs = append(errs, fmt.Errorf("토큰 %q 가 signerd 설정에 없다", t.Label))
		}
		if listed[t.Label] {
			errs = append(errs, fmt.Errorf("토큰 %q 중복", t.Label))
		}
		listed[t.Label] = true
	}
	ids := map[string]bool{}
	for _, k := range f.Keys {
		if k.KeyID == "" || ids[k.KeyID] {
			errs = append(errs, fmt.Errorf("key_id %q 가 비었거나 중복이다", k.KeyID))
		}
		ids[k.KeyID] = true
		if !listed[k.Token] {
			errs = append(errs, fmt.Errorf("키 %s 의 토큰 %q 가 tokens 에 없다", k.KeyID, k.Token))
		}
		if _, err := signer.ClassOf(k.Purpose); err != nil {
			errs = append(errs, fmt.Errorf("키 %s: %w", k.KeyID, err))
		}
	}
	aids := map[string]bool{}
	for _, a := range f.Approvers {
		if a.ApproverID == "" || aids[a.ApproverID] || a.Name == "" || a.InstitutionID == "" {
			errs = append(errs, fmt.Errorf("승인자 %q: approver_id(중복 불가), name, institution_id 가 필요하다", a.ApproverID))
		}
		aids[a.ApproverID] = true
		if !roles[a.Role] {
			errs = append(errs, fmt.Errorf("승인자 %s: 알 수 없는 role %q", a.ApproverID, a.Role))
		}
		if b, err := hex.DecodeString(a.Ed25519Pubkey); err != nil || len(b) != 32 {
			errs = append(errs, fmt.Errorf("승인자 %s: ed25519_pubkey 는 32바이트 16진수여야 한다", a.ApproverID))
		}
	}
	pids := map[string]bool{}
	scopesSeen := map[string]bool{}
	for _, p := range f.Policies {
		if p.PolicyID == "" || pids[p.PolicyID] || p.LedgerID == "" || p.InstitutionID == "" || p.Body == nil {
			errs = append(errs, fmt.Errorf("정책 %q: policy_id(중복 불가), ledger_id, institution_id, body 가 필요하다", p.PolicyID))
		}
		pids[p.PolicyID] = true
		if _, err := signer.ClassOf(p.KeyPurpose); err != nil {
			errs = append(errs, fmt.Errorf("정책 %s: %w", p.PolicyID, err))
		}
		if p.Body != nil {
			if err := p.Body.Validate(); err != nil {
				errs = append(errs, fmt.Errorf("정책 %s 본문: %w", p.PolicyID, err))
			}
		}
		for _, w := range p.Whitelist {
			if !common.IsHexAddress(w) || common.HexToAddress(w).Hex() != w {
				errs = append(errs, fmt.Errorf("정책 %s 화이트리스트 %q 는 EIP-55 주소여야 한다", p.PolicyID, w))
			}
		}
		scope := p.LedgerID + "/" + p.InstitutionID + "/" + string(p.KeyPurpose)
		if scopesSeen[scope] {
			errs = append(errs, fmt.Errorf("정책 범위 %s 에 정책이 둘 이상이다", scope))
		}
		scopesSeen[scope] = true
	}
	return errors.Join(errs...)
}

// BootstrapResult 는 적용 결과 요약이다.
type BootstrapResult struct {
	Tokens, Keys, Approvers, Policies int
}

// IsBootstrapped 는 토큰이 하나라도 등록돼 있으면 true 다. HSM 에 접근하기 전에 확인하는 데 쓴다.
func IsBootstrapped(ctx context.Context, db *sql.DB) (bool, error) { return isBootstrapped(ctx, db) }

func isBootstrapped(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (bool, error) {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM hsm_tokens`).Scan(&n); err != nil {
		return false, fmt.Errorf("keyreg: 초기화 여부 확인: %w", err)
	}
	return n > 0, nil
}

// ApplyBootstrap 은 파일을 한 번만 적용한다. 이미 토큰이 등록돼 있으면 ErrAlreadyBootstrapped 다.
// HSM 키를 먼저 만들고 DB 기록은 한 트랜잭션으로 한다. 어느 단계든 실패하면 만든 HSM 키를 지운다.
func ApplyBootstrap(ctx context.Context, db *sql.DB, km KeyMaker, f *BootstrapFile, scopes map[string]TokenScope) (res BootstrapResult, err error) {
	if err := f.Validate(scopes); err != nil {
		return res, err
	}
	if done, err := isBootstrapped(ctx, db); err != nil {
		return res, err
	} else if done {
		return res, ErrAlreadyBootstrapped
	}

	var created []GeneratedKey
	defer func() {
		if err == nil {
			return
		}
		for _, g := range created {
			if derr := km.DestroyIn(context.WithoutCancel(ctx), g.Token, g.KeyID); derr != nil {
				err = errors.Join(err, fmt.Errorf("롤백 중 HSM 키 %s 삭제 실패: %w", g.KeyID, derr))
			}
		}
	}()
	for _, k := range f.Keys {
		pub, gerr := km.Generate(ctx, signer.KeySpec{KeyID: k.KeyID, TokenLabel: k.Token, Purpose: k.Purpose})
		if gerr != nil {
			return res, fmt.Errorf("HSM 키 생성(%s): %w", k.KeyID, gerr)
		}
		created = append(created, GeneratedKey{KeyID: k.KeyID, Token: k.Token, Purpose: k.Purpose, PublicKey: pub})
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	// 동시 실행을 막기 위해 트랜잭션 안에서 다시 확인한다(토큰 PK 충돌도 함께 막는다).
	if done, cerr := isBootstrapped(ctx, tx); cerr != nil {
		return res, cerr
	} else if done {
		return res, ErrAlreadyBootstrapped
	}
	if err = insertBootstrap(ctx, tx, f, created, scopes); err != nil {
		return res, err
	}
	// 초기 등록도 감사로그에 남긴다(설계서 7.2). 같은 트랜잭션이다.
	if _, err = audit.Append(ctx, tx, bootstrapAudit(f)); err != nil {
		return res, err
	}
	if err = tx.Commit(); err != nil {
		return res, fmt.Errorf("부트스트랩 커밋: %w", err)
	}
	return BootstrapResult{Tokens: len(f.Tokens), Keys: len(created), Approvers: len(f.Approvers), Policies: len(f.Policies)}, nil
}

func bootstrapAudit(f *BootstrapFile) audit.Entry {
	var toks, keys, apprs, pols []string
	for _, t := range f.Tokens {
		toks = append(toks, t.Label)
	}
	for _, k := range f.Keys {
		keys = append(keys, k.KeyID+":"+k.Token+":"+string(k.Purpose))
	}
	for _, a := range f.Approvers {
		apprs = append(apprs, a.ApproverID)
	}
	for _, p := range f.Policies {
		pols = append(pols, p.PolicyID)
	}
	return audit.Entry{Actor: "signerd-init", Action: "BOOTSTRAP", Subject: "registry", Payload: map[string]any{
		"tokens": nonNil(toks), "keys": nonNil(keys), "approvers": nonNil(apprs), "policies": nonNil(pols)}}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// GeneratedKey 는 HSM 에 만든 부트스트랩 키다.
type GeneratedKey struct {
	KeyID     string
	Token     string
	Purpose   signer.Purpose
	PublicKey signer.PublicKey
}

// insertBootstrap 은 토큰, 키, 승인자·그룹, 정책을 tx 안에서 기록한다.
func insertBootstrap(ctx context.Context, tx *sql.Tx, f *BootstrapFile, keys []GeneratedKey, scopes map[string]TokenScope) error {
	for _, t := range f.Tokens {
		s := scopes[t.Label]
		if err := RegisterToken(ctx, tx, Token{TokenID: t.Label, Label: t.Label, LedgerID: s.LedgerID, InstitutionID: s.InstitutionID}); err != nil {
			return err
		}
	}
	for _, g := range keys {
		if err := RegisterKey(ctx, tx, Key{KeyID: g.KeyID, TokenID: g.Token, Purpose: g.Purpose, PublicKey: g.PublicKey}); err != nil {
			return err
		}
	}
	for _, a := range f.Approvers {
		pub, _ := hex.DecodeString(a.Ed25519Pubkey)
		if _, err := tx.ExecContext(ctx, `INSERT INTO approvers (approver_id, name, institution_id, role, ed25519_pubkey, status) VALUES (?, ?, ?, ?, ?, 'ACTIVE')`,
			a.ApproverID, a.Name, a.InstitutionID, a.Role, pub); err != nil {
			return fmt.Errorf("승인자 등록(%s): %w", a.ApproverID, err)
		}
		for _, g := range a.Groups {
			if _, err := tx.ExecContext(ctx, `INSERT INTO approver_groups (group_id, approver_id) VALUES (?, ?)`, g, a.ApproverID); err != nil {
				return fmt.Errorf("승인자 그룹 등록(%s/%s): %w", g, a.ApproverID, err)
			}
		}
	}
	for _, p := range f.Policies {
		body, err := p.Body.Canonical()
		if err != nil {
			return fmt.Errorf("정책 %s 본문: %w", p.PolicyID, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO policies (policy_id, version, ledger_id, institution_id, key_purpose, body_json, status) VALUES (?, 1, ?, ?, ?, ?, 'ACTIVE')`,
			p.PolicyID, p.LedgerID, p.InstitutionID, string(p.KeyPurpose), string(body)); err != nil {
			return fmt.Errorf("정책 등록(%s): %w", p.PolicyID, err)
		}
		for _, w := range p.Whitelist {
			if _, err := tx.ExecContext(ctx, `INSERT INTO whitelists (policy_id, account_address) VALUES (?, ?)`, p.PolicyID, w); err != nil {
				return fmt.Errorf("화이트리스트 등록(%s/%s): %w", p.PolicyID, w, err)
			}
		}
	}
	return nil
}

// compactJSON 은 키를 정렬한 공백 없는 JSON 이다(HTML 이스케이프 없음).
func compactJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
