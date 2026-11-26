package main

import (
	"errors"
	"fmt"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/config"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/store"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

// Config 는 apid 설정이다(설계서 15절). 비밀 값은 파일 경로로만 받는다.
type Config struct {
	Listen         string             `yaml:"listen"`
	TLS            transport.TLSFiles `yaml:"tls"`
	AllowedCallers []string           `yaml:"allowed_callers"`
	DB             store.DBConfig     `yaml:"db"`
	Ledger         LedgerConfig       `yaml:"ledger"`
	Signer         SignerConfig       `yaml:"signer"`
}

// LedgerConfig 는 원장 노드 접속 설정이다.
type LedgerConfig struct {
	ID      string `yaml:"id"`
	RPCURL  string `yaml:"rpc_url"`
	ChainID uint64 `yaml:"chain_id"`
}

// SignerConfig 는 서명 서버 접속 설정이다.
type SignerConfig struct {
	URL        string `yaml:"url"`
	ServerName string `yaml:"server_name"`
}

func loadConfig(path string) (*Config, error) {
	var c Config
	if err := config.Load(path, &c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("설정 검증: %w", err)
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
	if c.Ledger.ID == "" || c.Ledger.RPCURL == "" || c.Ledger.ChainID == 0 {
		errs = append(errs, errors.New("ledger.id, ledger.rpc_url, ledger.chain_id 가 필요하다"))
	}
	if c.Signer.URL == "" || c.Signer.ServerName == "" {
		errs = append(errs, errors.New("signer.url, signer.server_name 이 필요하다"))
	}
	return errors.Join(errs...)
}
