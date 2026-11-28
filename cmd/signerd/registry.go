package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/config"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/hsm"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
	signerhsm "github.com/da-infra/sto-key-management-signing-mvp/internal/signer/hsm"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/store"
)

// exitAlreadyBootstrapped 는 이미 초기화된 경우의 종료 코드다(make up 이 이 경우를 정상으로 본다).
const exitAlreadyBootstrapped = 3

func initCmd(log *slog.Logger, cfgPath *string) *cobra.Command {
	var file string
	c := &cobra.Command{
		Use:   "init",
		Short: "토큰, 초기 키, 승인자, 정책을 한 번만 등록(두 번째 실행은 거부)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := bootstrap(cmd.Context(), log, *cfgPath, file)
			if errors.Is(err, keyreg.ErrAlreadyBootstrapped) {
				log.Error("거부", "err", err)
				os.Exit(exitAlreadyBootstrapped)
			}
			return err
		},
	}
	c.Flags().StringVar(&file, "bootstrap", "", "부트스트랩 YAML 파일")
	_ = c.MarkFlagRequired("bootstrap")
	return c
}

func scopes(cfg *Config) map[string]keyreg.TokenScope {
	m := map[string]keyreg.TokenScope{}
	for _, t := range cfg.HSM.Tokens {
		m[t.Label] = keyreg.TokenScope{Label: t.Label, LedgerID: t.LedgerID, InstitutionID: t.InstitutionID}
	}
	return m
}

func bootstrap(ctx context.Context, log *slog.Logger, cfgPath, file string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	var f keyreg.BootstrapFile
	if err := config.Load(file, &f); err != nil {
		return err
	}
	db, err := store.Open(ctx, cfg.DB)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := store.CheckMigration(ctx, db, store.SignerSchemaVersion); err != nil {
		return err
	}
	// HSM 에 접근하기 전에 거부한다(실행 중인 signerd 와 토큰 볼륨을 동시에 쓰지 않게).
	if done, err := keyreg.IsBootstrapped(ctx, db); err != nil {
		return err
	} else if done {
		return keyreg.ErrAlreadyBootstrapped
	}
	mod, toks, err := loginTokens(ctx, cfg)
	if err != nil {
		return err
	}
	defer mod.Close()
	list := make([]*hsm.Token, 0, len(toks))
	for _, t := range toks {
		list = append(list, t)
	}
	s := signerhsm.New(list, keyreg.TokenLabelOf(db))
	res, err := keyreg.ApplyBootstrap(ctx, db, s, &f, scopes(cfg))
	if err != nil {
		return err
	}
	log.Info("부트스트랩 완료", "tokens", res.Tokens, "keys", res.Keys, "approvers", res.Approvers, "policies", res.Policies)
	return nil
}

// checkRegistry 는 레지스트리의 PENDING·ACTIVE·FROZEN 키가 설정된 토큰에 실제로 있고 공개키가 같은지 대조한다(설계서 15절).
func (a *app) checkRegistry(ctx context.Context) error {
	keys, err := keyreg.ListByStatus(ctx, a.db, keyreg.StatusPending, keyreg.StatusActive, keyreg.StatusFrozen)
	if err != nil {
		return err
	}
	mpcKeys := 0
	for _, k := range keys {
		if k.Backend == signer.BackendMPC {
			// MPC 키는 노드에 묻지 않는다(노드 장애로 동결·감사·HSM 키 서명이 막히지 않게, D-25). 서명 때 노드가 확인한다.
			mpcKeys++
			continue
		}
		pub, err := a.hsm.PublicKeyOf(ctx, k.TokenLabel, k.KeyID)
		if err != nil {
			return fmt.Errorf("키 %s: %w", k.KeyID, err)
		}
		if !bytes.Equal(pub, k.PublicKey) {
			return fmt.Errorf("키 %s: HSM 공개키가 레지스트리와 다르다", k.KeyID)
		}
	}
	a.log.Info("레지스트리 키 대조", "keys", len(keys)-mpcKeys)
	if mpcKeys > 0 {
		a.log.Warn("MPC 키는 기동 점검에서 노드에 묻지 않았다", "mpc_keys", mpcKeys, "nodes", len(a.cfg.MPC.Nodes))
	}
	return nil
}
