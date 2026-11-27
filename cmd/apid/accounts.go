package main

import (
	"net/http"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/linked"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

// POST /v1/accounts: 연계장부 계좌 등록과 원장 계좌 등록 요청 기안(설계서 11절, D-22)
func (a *app) registerAccount(w http.ResponseWriter, r *http.Request) {
	var in linked.RegisterInput
	if !decodeStrict(w, r, &in) {
		return
	}
	acc, req, err := a.linked.Register(r.Context(), in)
	if err != nil {
		writeWorkflowErr(w, err)
		return
	}
	transport.WriteJSON(w, http.StatusCreated, map[string]any{"account": acc, "request": req})
}

// POST /v1/accounts/{no}/registrations: 기존 계좌를 다른 종목에 등록하는 요청 기안
func (a *app) addRegistration(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IssueCode string `json:"issue_code"`
		DrafterID string `json:"drafter_id"`
	}
	if !decodeStrict(w, r, &in) {
		return
	}
	req, err := a.linked.AddRegistration(r.Context(), r.PathValue("no"), in.IssueCode, in.DrafterID)
	if err != nil {
		writeWorkflowErr(w, err)
		return
	}
	transport.WriteJSON(w, http.StatusCreated, req)
}

// GET /v1/accounts?institution=
func (a *app) listAccounts(w http.ResponseWriter, r *http.Request) {
	out, err := linked.List(r.Context(), a.db, r.URL.Query().Get("institution"))
	if err != nil {
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "계좌 조회 실패")
		return
	}
	transport.WriteJSON(w, http.StatusOK, map[string]any{"accounts": out})
}

// GET /v1/accounts/{no}
func (a *app) getAccount(w http.ResponseWriter, r *http.Request) {
	acc, err := a.linked.Get(r.Context(), r.PathValue("no"))
	if err != nil {
		writeWorkflowErr(w, err)
		return
	}
	transport.WriteJSON(w, http.StatusOK, acc)
}

// GET /v1/holdings?security=&account=
func (a *app) listHoldings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	out, err := linked.Holdings(r.Context(), a.db, q.Get("security"), q.Get("account"))
	if err != nil {
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "보유 수량 조회 실패")
		return
	}
	transport.WriteJSON(w, http.StatusOK, map[string]any{"holdings": out})
}
