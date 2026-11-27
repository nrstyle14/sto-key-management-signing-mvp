package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyops"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

// POST /v1/key-ops: 보안관리자 M명이 서명한 키 작업(생성·퇴역·폐기, 설계서 9절·13.1, D-20). 호출자는 stoctl.
func (a *app) postKeyOp(w http.ResponseWriter, r *http.Request) {
	var req keyops.Request
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		transport.WriteError(w, http.StatusBadRequest, transport.CodeBadRequest, "요청 본문: "+err.Error())
		return
	}
	ex := &keyops.Executor{DB: a.db, HSM: a.hsm, Wrap: a.hsm, AdminGroup: a.cfg.KeyOps.AdminGroup, Approvals: a.cfg.KeyOps.Approvals}
	res, err := ex.Execute(r.Context(), req, transport.Caller(r.Context()), time.Now().UTC())
	if err != nil {
		var ke *keyops.Error
		if errors.As(err, &ke) {
			status := http.StatusUnprocessableEntity
			switch ke.Code {
			case keyops.CodeReplay:
				status = http.StatusConflict
			case keyops.CodeAdmin, keyops.CodeSignature, keyops.CodeInsufficient:
				status = http.StatusForbidden
			case keyops.CodeKeyNotFound:
				status = http.StatusNotFound
			case keyops.CodeHSM, keyops.CodeNotDestroyed:
				status = http.StatusServiceUnavailable
			}
			a.log.Warn("키 작업 거부", "op_id", req.OpID, "type", req.Type, "code", ke.Code, "msg", ke.Msg)
			transport.WriteError(w, status, ke.Code, ke.Msg)
			return
		}
		a.log.Error("키 작업 오류", "op_id", req.OpID, "err", err)
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "내부 오류")
		return
	}
	a.log.Info("키 작업", "op_id", res.OpID, "type", res.Type, "key_id", res.KeyID, "status", res.Status)
	transport.WriteJSON(w, http.StatusOK, res)
}
