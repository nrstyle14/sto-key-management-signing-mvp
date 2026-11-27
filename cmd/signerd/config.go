package main

import (
	"errors"
	"fmt"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/config"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/store"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

// Config 는 signerd 설정이다(설계서 15절). PIN, DB 비밀번호는 파일 경로로만 받는다.
type Config struct {
	Listen         string             `yaml:"listen"`
	TLS            transport.TLSFiles `yaml:"tls"`
	AllowedCallers []string           `yaml:"allowed_callers"`
	DB             store.DBConfig     `yaml:"db"`
	HSM            HSMConfig          `yaml:"hsm"`
	Ledgers        []LedgerConfig     `yaml:"ledgers"`
	Signing        SigningConfig      `yaml:"signing"`
	Freeze         FreezeConfig       `yaml:"freeze"`
	Audit          AuditConfig        `yaml:"audit"`
}

// AuditConfig 는 감사 체크포인트 설정이다(설계서 8절, FR-4.3).
type AuditConfig struct {
	CheckpointInterval string `yaml:"checkpoint_interval"` // 예: "60s"
	CheckpointFile     string `yaml:"checkpoint_file"`     // DB 와 다른 위치(별도 볼륨)
	KeyLedger          string `yaml:"key_ledger"`          // AUDIT 키의 토큰 원장(global)
	KeyInstitution     string `yaml:"key_institution"`     // AUDIT 키의 토큰 기관(audit)
}

// FreezeConfig 는 동결 해제에 필요한 보안관리자 그룹과 서명 수(M)다(설계서 7.3, D-5).
type FreezeConfig struct {
	AdminGroup       string `yaml:"admin_group"`
	ReleaseApprovals int    `yaml:"release_approvals"`
}

// HSMConfig 는 PKCS#11 라이브러리와 토큰 목록이다. 토큰은 (원장, 기관) 단위다(설계서 6.1).
type HSMConfig struct {
	Library          string        `yaml:"library"`
	SessionsPerToken int           `yaml:"sessions_per_token"`
	Tokens           []TokenConfig `yaml:"tokens"`
}

// TokenConfig 는 토큰 하나의 설정이다. so_pin_file 은 토큰 초기화(init-tokens)에만 필요하다.
type TokenConfig struct {
	Label         string `yaml:"label"`
	LedgerID      string `yaml:"ledger_id"`
	InstitutionID string `yaml:"institution_id"`
	PINFile       string `yaml:"pin_file"`
	SOPINFile     string `yaml:"so_pin_file"`
}

// LedgerConfig 는 원장별 chainId 다. 서명 서버는 원장 노드에 접속하지 않고 설정값으로 대조한다.
type LedgerConfig struct {
	ID      string `yaml:"id"`
	ChainID uint64 `yaml:"chain_id"`
}

// SigningConfig 는 서명 공통 제한이다. 정책(T2.3)이 더 좁힐 수 있다.
type SigningConfig struct {
	MaxGasLimit uint64 `yaml:"max_gas_limit"`
}

func loadConfig(path string) (*Config, error) {
	var c Config
	if err := config.Load(path, &c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("설정 검증: %w", err)
	}
	if c.HSM.SessionsPerToken == 0 {
		c.HSM.SessionsPerToken = 4
	}
	return &c, nil
}

func (c *Config) validate() error {
	var errs []error
	if c.Listen == "" {
		errs = append(errs, errors.New("listen 이 필요하다"))
	}
	if err := c.TLS.Validate(); err != nil {
		errs = append(errs, err)
	}
	if len(c.AllowedCallers) == 0 {
		errs = append(errs, errors.New("allowed_callers 가 필요하다"))
	}
	if err := c.DB.Validate(); err != nil {
		errs = append(errs, err)
	}
	if c.HSM.Library == "" || len(c.HSM.Tokens) == 0 {
		errs = append(errs, errors.New("hsm.library 와 hsm.tokens 가 필요하다"))
	}
	labels, scopes := map[string]bool{}, map[string]bool{}
	for _, t := range c.HSM.Tokens {
		if t.Label == "" || t.LedgerID == "" || t.InstitutionID == "" || t.PINFile == "" {
			errs = append(errs, fmt.Errorf("토큰 %q: label, ledger_id, institution_id, pin_file 이 필요하다", t.Label))
		}
		if labels[t.Label] {
			errs = append(errs, fmt.Errorf("토큰 라벨 중복: %s", t.Label))
		}
		scope := t.LedgerID + "/" + t.InstitutionID
		if scopes[scope] {
			errs = append(errs, fmt.Errorf("(원장, 기관) 중복: %s", scope))
		}
		labels[t.Label], scopes[scope] = true, true
	}
	if len(c.Ledgers) == 0 {
		errs = append(errs, errors.New("ledgers 가 필요하다"))
	}
	for _, l := range c.Ledgers {
		if l.ID == "" || l.ChainID == 0 {
			errs = append(errs, errors.New("ledgers[].id, chain_id 가 필요하다"))
		}
	}
	if c.Freeze.AdminGroup == "" || c.Freeze.ReleaseApprovals < 2 {
		errs = append(errs, errors.New("freeze.admin_group 과 freeze.release_approvals(2 이상)가 필요하다"))
	}
	if c.Audit.KeyLedger == "" || c.Audit.KeyInstitution == "" {
		errs = append(errs, errors.New("audit.key_ledger, audit.key_institution 이 필요하다"))
	}
	if c.Signing.MaxGasLimit == 0 {
		errs = append(errs, errors.New("signing.max_gas_limit 이 필요하다"))
	}
	return errors.Join(errs...)
}

func (c *Config) chainID(ledgerID string) (uint64, bool) {
	for _, l := range c.Ledgers {
		if l.ID == ledgerID {
			return l.ChainID, true
		}
	}
	return 0, false
}
