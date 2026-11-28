// Command apid 는 업무 서버다. 키를 갖지 않고 서명은 서명 서버(signerd)에 mTLS 로 요청한다(FR-1.1).
// 이 패키지와 의존 패키지는 internal/hsm 을 import 하지 않는다(make lint 가 검사).
package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/alarm"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger/besu"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/linked"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/recon"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/registry"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/server"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/store"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/version"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
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
	cfg    *Config
	db     *sql.DB
	eth    *ethclient.Client
	ledger *besu.Adapter
	signer *signerClient
	wf     *workflow.Service
	alarms *alarm.Recorder
	linked *linked.Service
	recon  *recon.Runner
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
	clientTLS, err := transport.ClientTLSConfig(cfg.TLS, cfg.Signer.ServerName)
	if err != nil {
		return err
	}
	a.signer = newSignerClient(transport.NewClient(clientTLS, 30*time.Second), cfg.Signer.URL)
	gas := cfg.Workflow.GasLimit
	led, err := besu.New(eth, besu.Config{ChainID: cfg.Ledger.ChainID, GasLimit: gas, DeployGasLimit: cfg.Workflow.DeployGasLimit})
	if err != nil {
		return err
	}
	a.ledger = led
	interval, err := time.ParseDuration(cfg.Workflow.WorkerInterval)
	if err != nil || interval <= 0 {
		interval = time.Second
	}
	a.wf = &workflow.Service{DB: db, Dir: a.signer, LedgerID: cfg.Ledger.ID, GasLimit: gas, DeployGasLimit: cfg.Workflow.DeployGasLimit,
		KnownCode: func(h common.Hash) bool { return h == besu.SecurityTokenCodeHash() }}
	a.linked = &linked.Service{DB: db, WF: a.wf, LedgerID: cfg.Ledger.ID}
	worker := &workflow.SignWorker{DB: db, LedgerID: cfg.Ledger.ID, Dir: a.signer, Signer: a.signer, Chain: led, Builder: led}
	a.hookAlarms(log, worker)
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	logw := func(msg string, args ...any) { log.Warn(msg, args...) }
	go worker.Run(wctx, interval, logw)
	go (&workflow.SubmitWorker{DB: db, LedgerID: cfg.Ledger.ID, Ledger: led}).Run(wctx, interval, logw)
	go (&workflow.ReceiptWorker{DB: db, LedgerID: cfg.Ledger.ID, Ledger: led}).Run(wctx, interval, logw)
	go (&registry.Worker{DB: db, LedgerID: cfg.Ledger.ID, Source: led, ConfirmDepth: cfg.Ledger.ConfirmDepth,
		Apply: func(ctx context.Context, tx *sql.Tx, ev ledger.Event) error {
			return linked.ApplyEvent(ctx, tx, cfg.Ledger.ID, ev)
		}}).Run(wctx, interval, logw)
	go a.pushAuditHead(wctx, interval, log)
	if fl := a.startFabric(wctx, interval, log, logw); fl != nil {
		defer fl.Close()
	}
	a.recon = &recon.Runner{DB: db, LedgerID: cfg.Ledger.ID, Chain: led, Alarms: a.alarms}
	if cfg.Recon.AlarmWithin != "" {
		if a.recon.AlarmWithin, err = time.ParseDuration(cfg.Recon.AlarmWithin); err != nil || a.recon.AlarmWithin <= 0 {
			return fmt.Errorf("recon.alarm_within %q", cfg.Recon.AlarmWithin)
		}
	}
	if cfg.Recon.Interval != "" {
		every, err := time.ParseDuration(cfg.Recon.Interval)
		if err != nil || every <= 0 {
			return fmt.Errorf("recon.interval %q", cfg.Recon.Interval)
		}
		go a.reconLoop(wctx, every, log)
	}

	if cfg.WebListen != "" {
		go serveWeb(wctx, log, cfg.WebListen, a.webHandler(log))
	}
	tlsCfg, err := transport.ServerTLSConfig(cfg.TLS, cfg.AllowedCallers)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	ops := []string{"stoctl"}
	mux.Handle("POST /v1/requests", transport.RequireCaller(ops, http.HandlerFunc(a.draft)))
	mux.Handle("POST /v1/requests/{id}/approvals", transport.RequireCaller(ops, http.HandlerFunc(a.addApproval)))
	mux.Handle("GET /v1/requests", transport.RequireCaller(ops, http.HandlerFunc(a.listRequests)))
	mux.Handle("GET /v1/alarms", transport.RequireCaller(ops, http.HandlerFunc(a.listAlarms)))
	mux.Handle("GET /v1/securities", transport.RequireCaller(ops, http.HandlerFunc(a.listSecurities)))
	mux.Handle("GET /v1/registry-events", transport.RequireCaller(ops, http.HandlerFunc(a.listRegistryEvents)))
	mux.Handle("POST /v1/accounts", transport.RequireCaller(ops, http.HandlerFunc(a.registerAccount)))
	mux.Handle("POST /v1/accounts/{no}/registrations", transport.RequireCaller(ops, http.HandlerFunc(a.addRegistration)))
	mux.Handle("GET /v1/accounts", transport.RequireCaller(ops, http.HandlerFunc(a.listAccounts)))
	mux.Handle("GET /v1/accounts/{no}", transport.RequireCaller(ops, http.HandlerFunc(a.getAccount)))
	mux.Handle("GET /v1/holdings", transport.RequireCaller(ops, http.HandlerFunc(a.listHoldings)))
	mux.Handle("POST /v1/recon/run", transport.RequireCaller(ops, http.HandlerFunc(a.runRecon)))
	mux.Handle("GET /v1/recon/runs", transport.RequireCaller(ops, http.HandlerFunc(a.listRecon)))
	mux.Handle("GET /v1/recon/runs/{id}", transport.RequireCaller(ops, http.HandlerFunc(a.getRecon)))
	mux.Handle("GET /v1/requests/{id}", transport.RequireCaller(ops, http.HandlerFunc(a.getRequest)))
	mux.Handle("GET /healthz", transport.RequireCaller([]string{"stoctl", "apid"}, http.HandlerFunc(a.healthz)))
	mux.Handle("GET /v1/audit/records", transport.RequireCaller([]string{"stoctl"}, transport.AuditRecordsHandler(db)))
	mux.Handle("GET /v1/audit/head", transport.RequireCaller([]string{"stoctl"}, transport.AuditHeadHandler(db)))
	return server.Run(ctx, log, cfg.Listen, tlsCfg, mux)
}

// pushAuditHead 는 api 감사 체인 머리가 바뀔 때마다 서명 서버에 알린다. 서명 서버가 응답하지 않으면 다음 주기에 다시 보낸다.
func (a *app) pushAuditHead(ctx context.Context, interval time.Duration, log *slog.Logger) {
	var lastSeq uint64
	pushed := false
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		seq, h, err := audit.HeadOf(ctx, a.db)
		if err == nil && (!pushed || seq != lastSeq) {
			if err := a.signer.PushAPIHead(ctx, seq, hex.EncodeToString(h[:])); err != nil {
				log.Warn("감사 머리 전달 실패", "err", err)
			} else {
				lastSeq, pushed = seq, true
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
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
