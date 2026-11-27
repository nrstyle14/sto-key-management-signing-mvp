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
	Listen string `yaml:"listen"`
	// WebListen 은 읽기 전용 웹(D-9, 평문 HTTP)의 주소다. 비우면 띄우지 않는다. compose 는 127.0.0.1 로만 연다.
	WebListen      string             `yaml:"web_listen"`
	TLS            transport.TLSFiles `yaml:"tls"`
	AllowedCallers []string           `yaml:"allowed_callers"`
	DB             store.DBConfig     `yaml:"db"`
	Ledger         LedgerConfig       `yaml:"ledger"`
	Signer         SignerConfig       `yaml:"signer"`
	Workflow       WorkflowConfig     `yaml:"workflow"`
	Recon          ReconConfig        `yaml:"recon"`
}

// ReconConfig 는 대사 배치 설정이다(설계서 11절, FR-7.2).
type ReconConfig struct {
	// Interval 은 전체 종목 대사 주기다(예: "10m"). 비우면 주기 실행을 하지 않는다(stoctl recon run 으로만).
	Interval string `yaml:"interval"`
	// AlarmWithin 은 같은 종목의 대사 불일치 알람을 다시 내지 않는 기간이다(비우면 24시간).
	AlarmWithin string `yaml:"alarm_within"`
}

// WorkflowConfig 는 작업자 주기와 미서명 tx 의 가스 한도다.
type WorkflowConfig struct {
	WorkerInterval string `yaml:"worker_interval"`  // 예: "1s"
	GasLimit       uint64 `yaml:"gas_limit"`        // 함수 호출 tx
	DeployGasLimit uint64 `yaml:"deploy_gas_limit"` // 종목 배포 tx
}

// LedgerConfig 는 원장 노드 접속 설정이다.
type LedgerConfig struct {
	ID      string `yaml:"id"`
	RPCURL  string `yaml:"rpc_url"`
	ChainID uint64 `yaml:"chain_id"`
	// ConfirmDepth 는 이벤트 수신의 확정 깊이다(QBFT 즉시 확정이라 기본 0, 설계서 10.4).
	ConfirmDepth uint64 `yaml:"confirm_depth"`
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
	if c.Workflow.GasLimit == 0 || c.Workflow.DeployGasLimit == 0 {
		errs = append(errs, errors.New("workflow.gas_limit, workflow.deploy_gas_limit 이 필요하다"))
	}
	if c.Signer.URL == "" || c.Signer.ServerName == "" {
		errs = append(errs, errors.New("signer.url, signer.server_name 이 필요하다"))
	}
	return errors.Join(errs...)
}
