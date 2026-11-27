package main

import (
	"net/http"
	"strconv"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/registry"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

// GET /v1/registry-events?contract=&after=&limit=: 보존된 원장 이벤트(설계서 10.4)
func (a *app) listRegistryEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	after, _ := strconv.ParseUint(q.Get("after"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	evs, err := registry.List(r.Context(), a.db, a.cfg.Ledger.ID, q.Get("contract"), after, limit)
	if err != nil {
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "이벤트 조회 실패")
		return
	}
	transport.WriteJSON(w, http.StatusOK, map[string]any{"events": evs})
}

// Security 는 종목(설계서 12.2 securities)이다. 배포 요청이 확정되면 등록된다(T3.3).
type Security struct {
	IssueCode         string `json:"issue_code"`
	Name              string `json:"name"`
	LedgerID          string `json:"ledger_id"`
	ContractAddress   string `json:"contract_address"`
	CirculationStatus string `json:"circulation_status"`
}

// GET /v1/securities
func (a *app) listSecurities(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.QueryContext(r.Context(), `SELECT issue_code, name, ledger_id, COALESCE(contract_address, ''), circulation_status
		FROM securities WHERE ledger_id = ? ORDER BY issue_code`, a.cfg.Ledger.ID)
	if err != nil {
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "종목 조회 실패")
		return
	}
	defer rows.Close()
	out := []Security{}
	for rows.Next() {
		var s Security
		if err := rows.Scan(&s.IssueCode, &s.Name, &s.LedgerID, &s.ContractAddress, &s.CirculationStatus); err != nil {
			transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "종목 조회 실패")
			return
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "종목 조회 실패")
		return
	}
	transport.WriteJSON(w, http.StatusOK, map[string]any{"securities": out})
}
