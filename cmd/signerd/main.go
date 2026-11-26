// Command signerd 는 서명 서버다. HSM(PKCS#11) 안의 키로 검사를 통과한 요청만 서명한다(FR-1).
// 원장 노드에 접속하지 않는다.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/hsm"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/server"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/store"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/version"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("svc", "signerd")
	var cfgPath string
	root := &cobra.Command{Use: "signerd", Short: "서명 서버", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().StringVar(&cfgPath, "config", "/etc/sto/signerd.yaml", "설정 파일")
	root.AddCommand(
		&cobra.Command{Use: "version", Run: func(*cobra.Command, []string) { fmt.Println(version.String("signerd")) }},
		&cobra.Command{Use: "serve", Short: "서버 실행", RunE: func(cmd *cobra.Command, _ []string) error {
			return serve(cmd.Context(), log, cfgPath)
		}},
		&cobra.Command{Use: "init-tokens", Short: "설정의 HSM 토큰 초기화(이미 있으면 건너뜀)", RunE: func(*cobra.Command, []string) error {
			cfg, err := loadConfig(cfgPath)
			if err != nil {
				return err
			}
			return initTokens(log, cfg)
		}},
		&cobra.Command{Use: "healthcheck", Short: "자기 /healthz 를 mTLS 로 확인(컨테이너 헬스체크용)", RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cfgPath)
			if err != nil {
				return err
			}
			return server.Probe(cmd.Context(), cfg.TLS, "localhost", "https://localhost"+cfg.Listen+"/healthz", nil)
		}},
		initCmd(log, &cfgPath),
	)
	if err := root.ExecuteContext(context.Background()); err != nil {
		log.Error("실패", "err", err)
		os.Exit(1)
	}
}

type app struct {
	cfg    *Config
	log    *slog.Logger
	db     *sql.DB
	tokens map[string]*hsm.Token
}

// serve 는 기동 점검(설정 → DB·마이그레이션 → HSM 토큰 로그인 → 레지스트리 키 대조)을 통과해야만 띄운다(설계서 15절).
func serve(ctx context.Context, log *slog.Logger, cfgPath string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	db, err := store.Open(ctx, cfg.DB)
	if err != nil {
		return fmt.Errorf("기동 점검(DB): %w", err)
	}
	defer db.Close()
	if err := store.CheckMigration(ctx, db, store.SignerSchemaVersion); err != nil {
		return fmt.Errorf("기동 점검(마이그레이션): %w", err)
	}
	mod, toks, err := loginTokens(ctx, cfg)
	if err != nil {
		return fmt.Errorf("기동 점검(HSM): %w", err)
	}
	defer mod.Close()
	a := &app{cfg: cfg, log: log, db: db, tokens: toks}
	if err := a.checkRegistry(ctx); err != nil {
		return fmt.Errorf("기동 점검(키 레지스트리): %w", err)
	}
	log.Info("기동 점검 통과", "tokens", len(toks))

	tlsCfg, err := transport.ServerTLSConfig(cfg.TLS, cfg.AllowedCallers)
	if err != nil {
		return err
	}
	return server.Run(ctx, log, cfg.Listen, tlsCfg, a.routes())
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", transport.RequireCaller([]string{"apid", "stoctl", "signerd"}, http.HandlerFunc(a.healthz)))
	registerSignRoutes(a, mux)
	return mux
}

// healthz 는 DB 와 HSM 토큰 세션 상태를 돌려준다. 하나라도 실패하면 503 이다.
func (a *app) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	res := map[string]any{"db": "ok"}
	ok := true
	if err := a.db.PingContext(ctx); err != nil {
		res["db"], ok = "error: "+err.Error(), false
	}
	toks := map[string]string{}
	for label, t := range a.tokens {
		toks[label] = "ok"
		if err := t.Ping(ctx); err != nil {
			toks[label], ok = "error: "+err.Error(), false
		}
	}
	res["hsm_tokens"] = toks
	status := http.StatusOK
	res["status"] = "ok"
	if !ok {
		status, res["status"] = http.StatusServiceUnavailable, "degraded"
	}
	transport.WriteJSON(w, status, res)
}
