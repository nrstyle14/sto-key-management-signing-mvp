package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/recon"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

// POST /v1/recon/run {"issue_code"}: 대사 실행(설계서 11절). 비우면 전체 종목.
// 불일치가 있어도 200 이다(결과의 status 가 MISMATCH). 원장 조회 실패는 503 과 ERROR 실행 기록.
func (a *app) runRecon(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IssueCode string `json:"issue_code"`
	}
	if !decodeStrict(w, r, &in) {
		return
	}
	run, err := a.recon.Run(r.Context(), in.IssueCode)
	switch {
	case errors.Is(err, recon.ErrSecurityNotFound):
		transport.WriteError(w, http.StatusNotFound, "SECURITY_NOT_FOUND", err.Error())
	case err != nil && run != nil:
		transport.WriteJSON(w, http.StatusServiceUnavailable, run)
	case err != nil:
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "대사 실행 실패")
	default:
		transport.WriteJSON(w, http.StatusOK, run)
	}
}

// GET /v1/recon/runs?limit=
func (a *app) listRecon(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	runs, err := recon.List(r.Context(), a.db, limit)
	if err != nil {
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "대사 조회 실패")
		return
	}
	transport.WriteJSON(w, http.StatusOK, map[string]any{"runs": runs})
}

// GET /v1/recon/runs/{id}: 실행 하나와 불일치 상세. id 가 latest 면 가장 최근 실행.
func (a *app) getRecon(w http.ResponseWriter, r *http.Request) {
	var id uint64
	if s := r.PathValue("id"); s != "latest" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil || v == 0 {
			transport.WriteError(w, http.StatusBadRequest, transport.CodeBadRequest, "run_id 형식")
			return
		}
		id = v
	}
	run, err := recon.Get(r.Context(), a.db, id)
	if errors.Is(err, sql.ErrNoRows) {
		transport.WriteError(w, http.StatusNotFound, "RECON_NOT_FOUND", "대사 실행이 없다")
		return
	}
	if err != nil {
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "대사 조회 실패")
		return
	}
	transport.WriteJSON(w, http.StatusOK, run)
}

// reconLoop 는 전체 종목 대사를 주기마다 돈다(FR-7.2). 불일치는 알람으로 남는다(Runner).
func (a *app) reconLoop(ctx context.Context, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		run, err := a.recon.Run(ctx, "")
		if err != nil {
			log.Warn("대사 실패", "err", err)
			continue
		}
		log.Info("대사", "run_id", run.RunID, "status", run.Status, "diffs", run.DiffCount)
	}
}
