package main

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
)

func decodeStrict(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		transport.WriteError(w, http.StatusBadRequest, transport.CodeBadRequest, "요청 본문: "+err.Error())
		return false
	}
	return true
}

func writeWorkflowErr(w http.ResponseWriter, err error) {
	status, code, msg := workflow.HTTPStatus(err)
	transport.WriteError(w, status, code, msg)
}

// POST /v1/requests: 기안
func (a *app) draft(w http.ResponseWriter, r *http.Request) {
	var in workflow.DraftInput
	if !decodeStrict(w, r, &in) {
		return
	}
	req, err := a.wf.Draft(r.Context(), in)
	if err != nil {
		writeWorkflowErr(w, err)
		return
	}
	transport.WriteJSON(w, http.StatusCreated, req)
}

// POST /v1/requests/{id}/approvals: 승인·반려(승인자 서명 포함)
func (a *app) addApproval(w http.ResponseWriter, r *http.Request) {
	var in approval.Approval
	if !decodeStrict(w, r, &in) {
		return
	}
	req, err := a.wf.AddApproval(r.Context(), r.PathValue("id"), in)
	if err != nil {
		writeWorkflowErr(w, err)
		return
	}
	transport.WriteJSON(w, http.StatusOK, req)
}

// GET /v1/requests/{id}
func (a *app) getRequest(w http.ResponseWriter, r *http.Request) {
	req, err := a.wf.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeWorkflowErr(w, err)
		return
	}
	transport.WriteJSON(w, http.StatusOK, req)
}

// GET /v1/requests?status=&limit=
func (a *app) listRequests(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := a.wf.List(r.Context(), r.URL.Query().Get("status"), limit)
	if err != nil {
		writeWorkflowErr(w, err)
		return
	}
	transport.WriteJSON(w, http.StatusOK, map[string]any{"requests": list})
}
