package main

import (
	"context"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/alarm"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/policy"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
)

// hookAlarms 는 알람 규칙(설계서 7.4)을 기안·서명 작업에 연결한다. 알람 기록 실패는 업무를 막지 않고 로그로 남긴다.
func (a *app) hookAlarms(log *slog.Logger, w *workflow.SignWorker) {
	rec := &alarm.Recorder{DB: a.db, Log: log, Rules: alarm.Defaults}
	a.alarms = rec
	a.wf.OnHighAmount = func(ctx context.Context, r *workflow.Request, p *policy.Policy) {
		in, err := intent.Parse(r.Intent)
		if err != nil {
			return
		}
		amt, ok := policy.Amount(in)
		max, ok2 := new(big.Int).SetString(p.Body.MaxAmount, 10)
		if !ok || !ok2 {
			return
		}
		if _, err := rec.HighAmount(ctx, r.RequestID, p.PolicyID, amt, max); err != nil {
			log.Error("알람 기록 실패", "rule", alarm.RuleHighAmount, "err", err)
		}
	}
	w.OnSigned = func(ctx context.Context, r *workflow.Request) {
		if _, err := rec.RepeatKey(ctx, r.LedgerID, r.SignerAddress); err != nil {
			log.Error("알람 기록 실패", "rule", alarm.RuleRepeatKey, "err", err)
		}
	}
	w.OnFailed = func(ctx context.Context, r *workflow.Request, _ string) {
		if _, err := rec.RejectRepeat(ctx, r.DrafterID); err != nil {
			log.Error("알람 기록 실패", "rule", alarm.RuleRejectRepeat, "err", err)
		}
	}
}

// GET /v1/alarms
func (a *app) listAlarms(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := alarm.List(r.Context(), a.db, limit)
	if err != nil {
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "알람 조회 실패")
		return
	}
	transport.WriteJSON(w, http.StatusOK, map[string]any{"alarms": list})
}
