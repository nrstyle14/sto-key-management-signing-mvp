package transport

import (
	"database/sql"
	"net/http"
	"strconv"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
)

// AuditRecordsHandler 는 GET /v1/audit/records?from=&limit= 이다(설계서 13.1). 검증은 호출자가 한다.
func AuditRecordsHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		from, err := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
		if err != nil || from == 0 {
			from = 1
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		recs, err := audit.Load(r.Context(), db, from, limit)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, CodeInternal, "감사 기록 조회 실패")
			return
		}
		if recs == nil {
			recs = []audit.Record{}
		}
		WriteJSON(w, http.StatusOK, map[string]any{"records": recs})
	})
}

// AuditHeadHandler 는 GET /v1/audit/head 다. audit_log 의 마지막 레코드를 돌려준다.
func AuditHeadHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seq, h, err := audit.HeadOf(r.Context(), db)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, CodeInternal, "감사 머리 조회 실패")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"seq": seq, "hash": h})
	})
}
