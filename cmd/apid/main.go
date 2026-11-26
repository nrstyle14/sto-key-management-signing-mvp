// Command apid 는 업무 서버다. 키를 갖지 않고 서명은 서명 서버(signerd)에 mTLS 로 요청한다(FR-1.1).
// 이 패키지와 의존 패키지는 internal/hsm 을 import 하지 않는다(make lint 가 검사).
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/server"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/store"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/version"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("svc", "apid")
	var cfgPath string
	root := &cobra.Command{Use: "apid", Short: "업무 서버", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().StringVar(&cfgPath, "config", "/etc/sto/apid.yaml", "설정 파일")
	root.AddCommand(
		&cobra.Command{Use: "version", Run: func(*cobra.Command, []string) { fmt.Println(version.String("apid")) }},
		&cobra.Command{Use: "serve", Short: "서버 실행", RunE: func(cmd *cobra.Command, _ []string) error {
			return serve(cmd.Context(), log, cfgPath)
		}},
		&cobra.Command{Use: "healthcheck", Short: "자기 /healthz 를 mTLS 로 확인(컨테이너 헬스체크용)", RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := loadConfig(cfgPath)
			if err != nil {
				return err
			}
			return server.Probe(cmd.Context(), c.TLS, "localhost", "https://localhost"+c.Listen+"/healthz", nil)
		}},
	)
	if err := root.ExecuteContext(context.Background()); err != nil {
		log.Error("실패", "err", err)
		os.Exit(1)
	}
}

type app struct {
	cfg *Config
	db  *sql.DB
	eth *ethclient.Client
}

// serve 는 기동 점검(설정 → DB·마이그레이션 → RPC chainId)을 통과해야만 서버를 띄운다(설계서 15절).
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
	if err := store.CheckMigration(ctx, db, store.APISchemaVersion); err != nil {
		return fmt.Errorf("기동 점검(마이그레이션): %w", err)
	}
	eth, err := ethclient.DialContext(ctx, cfg.Ledger.RPCURL)
	if err != nil {
		return fmt.Errorf("기동 점검(RPC 연결): %w", err)
	}
	defer eth.Close()
	if err := checkChainID(ctx, eth, cfg.Ledger.ChainID); err != nil {
		return fmt.Errorf("기동 점검(RPC chainId): %w", err)
	}
	log.Info("기동 점검 통과", "ledger", cfg.Ledger.ID, "chain_id", cfg.Ledger.ChainID)

	a := &app{cfg: cfg, db: db, eth: eth}
	tlsCfg, err := transport.ServerTLSConfig(cfg.TLS, cfg.AllowedCallers)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", transport.RequireCaller([]string{"stoctl", "apid"}, http.HandlerFunc(a.healthz)))
	return server.Run(ctx, log, cfg.Listen, tlsCfg, mux)
}

func checkChainID(ctx context.Context, eth *ethclient.Client, want uint64) error {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	id, err := eth.ChainID(cctx)
	if err != nil {
		return err
	}
	if !id.IsUint64() || id.Uint64() != want {
		return fmt.Errorf("chainId %s, 기대 %d", id, want)
	}
	return nil
}

// healthz 는 DB, RPC, 서명 서버 상태를 돌려준다. 하나라도 실패하면 503 이다.
func (a *app) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	res := map[string]string{"db": "ok", "rpc": "ok", "signer": "ok"}
	ok := true
	if err := a.db.PingContext(ctx); err != nil {
		res["db"], ok = "error: "+err.Error(), false
	}
	if err := checkChainID(ctx, a.eth, a.cfg.Ledger.ChainID); err != nil {
		res["rpc"], ok = "error: "+err.Error(), false
	}
	if err := server.Probe(ctx, a.cfg.TLS, a.cfg.Signer.ServerName, a.cfg.Signer.URL+"/healthz", nil); err != nil {
		res["signer"], ok = "error: "+err.Error(), false
	}
	status := http.StatusOK
	res["status"] = "ok"
	if !ok {
		status, res["status"] = http.StatusServiceUnavailable, "degraded"
	}
	transport.WriteJSON(w, status, res)
}
