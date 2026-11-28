package mpcnode

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/mpcwire"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

// Handler 는 노드 API(설계서 6.4 MPC 서명기)다. 호출자 확인(mTLS CN)은 감싸는 쪽(cmd/mpcd)이 한다.
//
//	POST /v1/sessions, POST /v1/sessions/{id}/inbox, GET /v1/sessions/{id}/outbox?wait=,
//	GET /v1/sessions/{id}, POST /v1/sessions/{id}/commit, POST /v1/sessions/{id}/abort,
//	GET /v1/keys/{id}, DELETE /v1/keys/{id}
func Handler(n *Node, log *slog.Logger) http.Handler {
	a := &api{n: n, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions", a.start)
	mux.HandleFunc("POST /v1/sessions/{id}/inbox", a.inbox)
	mux.HandleFunc("GET /v1/sessions/{id}/outbox", a.outbox)
	mux.HandleFunc("GET /v1/sessions/{id}", a.status)
	mux.HandleFunc("POST /v1/sessions/{id}/commit", a.commit)
	mux.HandleFunc("POST /v1/sessions/{id}/abort", a.abort)
	mux.HandleFunc("GET /v1/keys/{id}", a.keyInfo)
	mux.HandleFunc("DELETE /v1/keys/{id}", a.destroy)
	return mux
}

type api struct {
	n   *Node
	log *slog.Logger
}

func decode(w http.ResponseWriter, r *http.Request, out any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		transport.WriteError(w, http.StatusBadRequest, transport.CodeBadRequest, "요청 본문: "+err.Error())
		return false
	}
	return true
}

func (a *api) start(w http.ResponseWriter, r *http.Request) {
	var req mpcwire.StartRequest
	if !decode(w, r, &req) {
		return
	}
	if err := a.n.Start(req.Header); err != nil {
		a.log.Warn("세션 시작 거부", "session", req.Header.SessionID, "kind", req.Header.Kind, "key", req.Header.KeyID, "err", err)
		transport.WriteError(w, http.StatusUnprocessableEntity, "MPC_SESSION_REJECTED", err.Error())
		return
	}
	a.log.Info("세션 시작", "session", req.Header.SessionID, "kind", req.Header.Kind, "key", req.Header.KeyID, "participants", req.Header.Participants)
	transport.WriteJSON(w, http.StatusOK, map[string]string{"session_id": req.Header.SessionID})
}

func (a *api) inbox(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Envelopes []mpcwire.Envelope `json:"envelopes"`
	}
	if !decode(w, r, &req) {
		return
	}
	for _, e := range req.Envelopes {
		if e.SessionID != r.PathValue("id") {
			transport.WriteError(w, http.StatusBadRequest, transport.CodeBadRequest, "다른 세션의 봉투")
			return
		}
		if err := a.n.Deliver(e); err != nil {
			a.log.Warn("봉투 거부", "session", e.SessionID, "from", e.From, "seq", e.Seq, "err", err)
			transport.WriteError(w, http.StatusUnprocessableEntity, "MPC_ENVELOPE_REJECTED", err.Error())
			return
		}
	}
	transport.WriteJSON(w, http.StatusOK, map[string]int{"accepted": len(req.Envelopes)})
}

// outbox 는 보낼 봉투가 생기거나 상태가 RUNNING 이 아니게 될 때까지 최대 wait 밀리초 기다린다(롱 폴링).
func (a *api) outbox(w http.ResponseWriter, r *http.Request) {
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	if wait <= 0 || wait > 5000 {
		wait = 1000
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Millisecond)
	for {
		ob, err := a.n.Outbox(r.PathValue("id"))
		if err != nil {
			transport.WriteError(w, http.StatusNotFound, "MPC_SESSION_NOT_FOUND", err.Error())
			return
		}
		if len(ob.Envelopes) > 0 || ob.State != mpcwire.StateRunning || time.Now().After(deadline) {
			transport.WriteJSON(w, http.StatusOK, ob)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (a *api) status(w http.ResponseWriter, r *http.Request) {
	st, err := a.n.Status(r.PathValue("id"))
	if err != nil {
		transport.WriteError(w, http.StatusNotFound, "MPC_SESSION_NOT_FOUND", err.Error())
		return
	}
	transport.WriteJSON(w, http.StatusOK, st)
}

func (a *api) commit(w http.ResponseWriter, r *http.Request) {
	st, err := a.n.Commit(r.PathValue("id"))
	if err != nil {
		transport.WriteError(w, http.StatusConflict, "MPC_COMMIT_REJECTED", err.Error())
		return
	}
	a.log.Info("키 조각 확정", "session", st.SessionID)
	transport.WriteJSON(w, http.StatusOK, st)
}

func (a *api) abort(w http.ResponseWriter, r *http.Request) {
	if err := a.n.Abort(r.PathValue("id")); err != nil {
		transport.WriteError(w, http.StatusNotFound, "MPC_SESSION_NOT_FOUND", err.Error())
		return
	}
	transport.WriteJSON(w, http.StatusOK, map[string]string{"state": mpcwire.StateFailed})
}

func (a *api) keyInfo(w http.ResponseWriter, r *http.Request) {
	info, err := a.n.KeyInfo(r.PathValue("id"))
	if err != nil {
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "조각 조회 실패")
		a.log.Error("조각 조회", "key", r.PathValue("id"), "err", err)
		return
	}
	transport.WriteJSON(w, http.StatusOK, info)
}

func (a *api) destroy(w http.ResponseWriter, r *http.Request) {
	remaining, err := a.n.Destroy(r.PathValue("id"))
	if err != nil {
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "조각 삭제 실패")
		a.log.Error("조각 삭제", "key", r.PathValue("id"), "err", err)
		return
	}
	a.log.Info("키 조각 삭제", "key", r.PathValue("id"), "remaining", remaining)
	transport.WriteJSON(w, http.StatusOK, map[string]any{"key_id": r.PathValue("id"), "remaining": remaining})
}
