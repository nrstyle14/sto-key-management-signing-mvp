package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/policychange"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

// POST /v1/policy-changes: 보안관리자 M명이 서명한 정책 변경(지금은 화이트리스트 추가, 설계서 7.2·13.1, D-22). 호출자는 stoctl.
// 승인 조건(그룹, M)은 키 작업 설정(key_ops)을 그대로 쓴다.
func (a *app) postPolicyChange(w http.ResponseWriter, r *http.Request) {
	var req policychange.Request
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		transport.WriteError(w, http.StatusBadRequest, transport.CodeBadRequest, "요청 본문: "+err.Error())
		return
	}
	ex := &policychange.Executor{DB: a.db, AdminGroup: a.cfg.KeyOps.AdminGroup, Approvals: a.cfg.KeyOps.Approvals}
	res, err := ex.Execute(r.Context(), req, transport.Caller(r.Context()), time.Now().UTC())
	if err != nil {
		var pe *policychange.Error
		if errors.As(err, &pe) {
			status := http.StatusUnprocessableEntity
			switch pe.Code {
			case policychange.CodeReplay:
				status = http.StatusConflict
			case policychange.CodeAdmin, policychange.CodeSignature, policychange.CodeInsufficient:
				status = http.StatusForbidden
			}
			a.log.Warn("정책 변경 거부", "change_id", req.ChangeID, "code", pe.Code, "msg", pe.Msg)
			transport.WriteError(w, status, pe.Code, pe.Msg)
			return
		}
		a.log.Error("정책 변경 오류", "change_id", req.ChangeID, "err", err)
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "내부 오류")
		return
	}
	a.log.Info("정책 변경", "change_id", res.ChangeID, "type", res.Type, "address", res.Address, "added", res.Added)
	transport.WriteJSON(w, http.StatusOK, res)
}
