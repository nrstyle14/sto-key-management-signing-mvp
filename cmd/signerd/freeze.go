package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/freeze"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

func (a *app) freezeConfig() freeze.Config {
	return freeze.Config{
		AdminGroup:       a.cfg.Freeze.AdminGroup,
		ReleaseApprovals: a.cfg.Freeze.ReleaseApprovals,
		TargetExists: func(ctx context.Context, scope freeze.Scope, target string) (bool, error) {
			switch scope {
			case freeze.ScopeKey:
				_, err := keyreg.Get(ctx, a.db, target)
				if errors.Is(err, keyreg.ErrKeyNotFound) {
					return false, nil
				}
				return err == nil, err
			case freeze.ScopeInstitution:
				var n int
				err := a.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM hsm_tokens WHERE institution_id = ?`, target).Scan(&n)
				return n > 0, err
			case freeze.ScopeLedger:
				_, ok := a.cfg.chainID(target)
				return ok, nil
			}
			return false, nil
		},
	}
}

func writeFreezeErr(w http.ResponseWriter, err error) {
	var fe *freeze.Error
	if errors.As(err, &fe) {
		status := http.StatusUnprocessableEntity
		switch fe.Code {
		case freeze.CodeNotFound:
			status = http.StatusNotFound
		case freeze.CodeExists, freeze.CodeReleased, freeze.CodeReplay:
			status = http.StatusConflict
		case freeze.CodeAdmin, freeze.CodeSignature, freeze.CodeInsufficient:
			status = http.StatusForbidden
		}
		transport.WriteError(w, status, fe.Code, fe.Msg)
		return
	}
	transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "내부 오류")
}

// POST /v1/freezes: 보안관리자 1인이 서명한 즉시 동결(설계서 7.3). 업무 서버를 거치지 않는다.
func (a *app) postFreeze(w http.ResponseWriter, r *http.Request) {
	var req freeze.Request
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		transport.WriteError(w, http.StatusBadRequest, transport.CodeBadRequest, err.Error())
		return
	}
	if err := freeze.Freeze(r.Context(), a.db, a.freezeConfig(), req, transport.Caller(r.Context()), time.Now()); err != nil {
		a.log.Warn("동결 거부", "err", err)
		writeFreezeErr(w, err)
		return
	}
	a.log.Warn("동결", "freeze_id", req.FreezeID, "scope", req.Scope, "target", req.Target, "admin", req.AdminID)
	transport.WriteJSON(w, http.StatusCreated, map[string]any{"freeze_id": req.FreezeID, "scope": req.Scope, "target": req.Target})
}

// POST /v1/freezes/{id}/release: 보안관리자 M명이 서명한 해제.
func (a *app) postRelease(w http.ResponseWriter, r *http.Request) {
	var req freeze.ReleaseRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		transport.WriteError(w, http.StatusBadRequest, transport.CodeBadRequest, err.Error())
		return
	}
	if req.FreezeID != r.PathValue("id") {
		transport.WriteError(w, http.StatusBadRequest, transport.CodeBadRequest, "경로와 본문의 freeze_id 가 다르다")
		return
	}
	if err := freeze.Release(r.Context(), a.db, a.freezeConfig(), req, transport.Caller(r.Context()), time.Now()); err != nil {
		a.log.Warn("동결 해제 거부", "err", err)
		writeFreezeErr(w, err)
		return
	}
	a.log.Warn("동결 해제", "freeze_id", req.FreezeID, "approvals", len(req.Approvals))
	transport.WriteJSON(w, http.StatusOK, map[string]any{"freeze_id": req.FreezeID, "released": true})
}

// GET /v1/freezes
func (a *app) listFreezes(w http.ResponseWriter, r *http.Request) {
	list, err := freeze.List(r.Context(), a.db)
	if err != nil {
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "동결 조회 실패")
		return
	}
	transport.WriteJSON(w, http.StatusOK, map[string]any{"freezes": list})
}
