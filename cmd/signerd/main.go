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

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/hsm"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/policy"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/server"
	signerhsm "github.com/da-infra/sto-key-management-signing-mvp/internal/signer/hsm"
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
		rehearseCmd(),
	)
	if err := root.ExecuteContext(context.Background()); err != nil {
		log.Error("실패", "err", err)
		os.Exit(1)
	}
}

type app struct {
	cfg     *Config
	log     *slog.Logger
	db      *sql.DB
	tokens  map[string]*hsm.Token
	hsm     *signerhsm.Signer
	apiHead apiHead
	cp      *checkpointer
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
	list := make([]*hsm.Token, 0, len(toks))
	for _, t := range toks {
		list = append(list, t)
	}
	a.hsm = signerhsm.New(list, keyreg.TokenLabelOf(db))
	if err := a.checkRegistry(ctx); err != nil {
		return fmt.Errorf("기동 점검(키 레지스트리): %w", err)
	}
	log.Info("기동 점검 통과", "tokens", len(toks))
	a.cp = a.newCheckpointer()
	// api 감사 머리의 하한을 마지막 api 체크포인트로 정한다(재기동 뒤에도 역행 보고를 거부하기 위함).
	if seq, h, ok, err := audit.LastCheckpointSeq(ctx, db, "api"); err != nil {
		return fmt.Errorf("기동 점검(체크포인트): %w", err)
	} else if ok {
		a.apiHead.seq, a.apiHead.hash, a.apiHead.set = seq, h, true
	}
	if iv, err := time.ParseDuration(cfg.Audit.CheckpointInterval); err == nil && iv > 0 {
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		go a.cp.run(cctx, iv)
	}

	tlsCfg, err := transport.ServerTLSConfig(cfg.TLS, cfg.AllowedCallers)
	if err != nil {
		return err
	}
	return server.Run(ctx, log, cfg.Listen, tlsCfg, a.routes())
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", transport.RequireCaller([]string{"apid", "stoctl", "signerd"}, http.HandlerFunc(a.healthz)))
	mux.Handle("GET /v1/audit/records", transport.RequireCaller([]string{"stoctl", "apid"}, transport.AuditRecordsHandler(a.db)))
	mux.Handle("GET /v1/audit/head", transport.RequireCaller([]string{"stoctl", "apid"}, transport.AuditHeadHandler(a.db)))
	mux.Handle("POST /v1/audit/api-head", transport.RequireCaller([]string{"apid"}, http.HandlerFunc(a.postAPIHead)))
	mux.Handle("POST /v1/audit/checkpoints", transport.RequireCaller([]string{"stoctl"}, http.HandlerFunc(a.postCheckpoint)))
	mux.Handle("GET /v1/audit/checkpoints", transport.RequireCaller([]string{"stoctl", "apid"}, http.HandlerFunc(a.listCheckpoints)))
	mux.Handle("POST /v1/freezes", transport.RequireCaller([]string{"stoctl"}, http.HandlerFunc(a.postFreeze)))
	mux.Handle("POST /v1/freezes/{id}/release", transport.RequireCaller([]string{"stoctl"}, http.HandlerFunc(a.postRelease)))
	mux.Handle("GET /v1/freezes", transport.RequireCaller([]string{"stoctl", "apid"}, http.HandlerFunc(a.listFreezes)))
	mux.Handle("GET /v1/keys", transport.RequireCaller([]string{"stoctl", "apid"}, http.HandlerFunc(a.listKeys)))
	mux.Handle("GET /v1/policies", transport.RequireCaller([]string{"stoctl", "apid"}, http.HandlerFunc(a.listPolicies)))
	mux.Handle("GET /v1/approvers", transport.RequireCaller([]string{"stoctl", "apid"}, http.HandlerFunc(a.listApprovers)))
	mux.Handle("POST /v1/key-ops", transport.RequireCaller([]string{"stoctl"}, http.HandlerFunc(a.postKeyOp)))
	mux.Handle("POST /v1/policy-changes", transport.RequireCaller([]string{"stoctl"}, http.HandlerFunc(a.postPolicyChange)))
	registerSignRoutes(a, mux)
	return mux
}

// listApprovers 는 승인자 명부(공개키 포함)다. 업무 서버는 조회만 한다(설계서 7.2).
func (a *app) listApprovers(w http.ResponseWriter, r *http.Request) {
	list, err := approval.List(r.Context(), a.db)
	if err != nil {
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "승인자 조회 실패")
		return
	}
	transport.WriteJSON(w, http.StatusOK, map[string]any{"approvers": list})
}

// listKeys 는 키 레지스트리의 공개 정보다(개인키·PIN 없음). 동결(freezes)은 여기 반영되지 않고 서명 시 4단계에서 거부된다.
func (a *app) listKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := keyreg.ListByStatus(r.Context(), a.db, keyreg.StatusPending, keyreg.StatusActive, keyreg.StatusFrozen, keyreg.StatusRetired, keyreg.StatusDestroyed)
	if err != nil {
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "키 조회 실패")
		return
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{"key_id": k.KeyID, "ledger_id": k.LedgerID, "institution_id": k.InstitutionID,
			"purpose": string(k.Purpose), "class": string(k.Class), "address": k.Address.Hex(), "status": string(k.Status),
			"public_key": fmt.Sprintf("%x", []byte(k.PublicKey)), "token": k.TokenLabel, "rotated_from": k.RotatedFrom})
	}
	transport.WriteJSON(w, http.StatusOK, map[string]any{"keys": out})
}

// listPolicies 는 ACTIVE 정책 목록이다. 업무 서버는 사전 검사에만 쓰고, 최종 판단은 서명 서버가 한다.
func (a *app) listPolicies(w http.ResponseWriter, r *http.Request) {
	list, err := policy.ListActive(r.Context(), a.db)
	if err != nil {
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "정책 조회 실패")
		return
	}
	transport.WriteJSON(w, http.StatusOK, map[string]any{"policies": list})
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
