package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/config"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/hsm"
)

// initTokens 는 설정의 토큰을 초기화한다. 이미 있는 토큰은 건너뛴다(다시 초기화하지 않는다).
// PIN 은 Docker secret 파일에서 읽는다. 환경 변수나 명령행 인자로 받지 않는다.
func initTokens(log *slog.Logger, cfg *Config) error {
	m, err := hsm.Open(cfg.HSM.Library)
	if err != nil {
		return err
	}
	defer m.Close()
	for _, t := range cfg.HSM.Tokens {
		so, err := config.ReadSecret(t.SOPINFile)
		if err != nil {
			return fmt.Errorf("토큰 %s SO PIN: %w", t.Label, err)
		}
		pin, err := config.ReadSecret(t.PINFile)
		if err != nil {
			return fmt.Errorf("토큰 %s PIN: %w", t.Label, err)
		}
		created, err := m.InitToken(t.Label, so, pin)
		if err != nil {
			return err
		}
		log.Info("토큰", "label", t.Label, "created", created)
	}
	return nil
}

// loginTokens 는 설정의 모든 토큰에 로그인한다. 토큰이 없거나 PIN 이 틀리면 실패한다(기동 점검).
func loginTokens(ctx context.Context, cfg *Config) (*hsm.Module, map[string]*hsm.Token, error) {
	m, err := hsm.Open(cfg.HSM.Library)
	if err != nil {
		return nil, nil, err
	}
	toks := map[string]*hsm.Token{}
	for _, t := range cfg.HSM.Tokens {
		pin, err := config.ReadSecret(t.PINFile)
		if err != nil {
			m.Close()
			return nil, nil, fmt.Errorf("토큰 %s PIN: %w", t.Label, err)
		}
		tok, err := m.Login(t.Label, pin, cfg.HSM.SessionsPerToken)
		if err != nil {
			m.Close()
			return nil, nil, err
		}
		if err := tok.Ping(ctx); err != nil {
			m.Close()
			return nil, nil, err
		}
		toks[t.Label] = tok
	}
	return m, toks, nil
}
