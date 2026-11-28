package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/signsvc"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

// signTxCallers 는 POST /v1/sign/tx 를 호출할 수 있는 CN 이다. 업무 서버만 허용한다.
var signTxCallers = []string{"apid"}

// registerSignRoutes 는 POST /v1/sign/tx 를 연다(설계서 5.3 의 1~9단계, 13.1).
func registerSignRoutes(a *app, mux *http.ServeMux) {
	chains := map[string]uint64{}
	for _, l := range a.cfg.Ledgers {
		if !l.IsFabric() {
			chains[l.ID] = l.ChainID
		}
	}
	svc := &signsvc.Service{
		DB:        a.db,
		Signer:    a.router,
		Chains:    chains,
		MaxGas:    a.cfg.Signing.MaxGasLimit,
		Callers:   signTxCallers,
		FabricMSP: a.fabricMSP,
		OnAuditError: func(err error) {
			a.log.Error("거부 감사 기록 실패", "err", err)
		},
	}
	// 경로 미들웨어는 핸드셰이크에서 허용된 모든 CN 을 통과시키고, 호출자 검사는 서비스의 1단계가 한다.
	// 그래야 1단계 거부(업무 서버가 아닌 호출자)도 다른 거부와 같이 감사로그에 남는다.
	mux.Handle("POST /v1/sign/tx", transport.RequireCaller(a.cfg.AllowedCallers, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req signsvc.Request
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			transport.WriteError(w, http.StatusBadRequest, transport.CodeBadRequest, "요청 본문: "+err.Error())
			return
		}
		res, err := svc.SignTx(r.Context(), transport.Caller(r.Context()), req)
		if err != nil {
			var rj *signsvc.Rejection
			if errors.As(err, &rj) {
				a.log.Warn("서명 거부", "step", rj.Step, "code", rj.Code, "msg", rj.Msg)
				transport.WriteJSON(w, statusOf(rj), rj)
				return
			}
			a.log.Error("서명 처리 오류", "err", err)
			transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "내부 오류")
			return
		}
		a.log.Info("서명", "request_id", res.RequestID, "key_id", res.KeyID, "tx_hash", res.TxHash)
		transport.WriteJSON(w, http.StatusOK, res)
	})))
	// Fabric 원문 서명(설계서 10.5, D-26). 호출자 검사는 위와 같이 서비스의 1단계가 한다.
	mux.Handle("POST /v1/sign/fabric", transport.RequireCaller(a.cfg.AllowedCallers, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req signsvc.FabricRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			transport.WriteError(w, http.StatusBadRequest, transport.CodeBadRequest, "요청 본문: "+err.Error())
			return
		}
		res, err := svc.SignFabric(r.Context(), transport.Caller(r.Context()), req)
		if err != nil {
			var rj *signsvc.Rejection
			if errors.As(err, &rj) {
				a.log.Warn("Fabric 서명 거부", "kind", req.Kind, "step", rj.Step, "code", rj.Code, "msg", rj.Msg)
				transport.WriteJSON(w, statusOf(rj), rj)
				return
			}
			a.log.Error("Fabric 서명 처리 오류", "err", err)
			transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "내부 오류")
			return
		}
		a.log.Info("Fabric 서명", "request_id", res.RequestID, "kind", res.Kind, "key_id", res.KeyID, "tx_id", res.TxID)
		transport.WriteJSON(w, http.StatusOK, res)
	})))
}

func statusOf(r *signsvc.Rejection) int {
	switch r.Code {
	case signsvc.CodeCallerNotAllowed:
		return http.StatusForbidden
	case signsvc.CodeRequestConflict:
		return http.StatusConflict
	case signsvc.CodeSignFailed:
		return http.StatusServiceUnavailable
	case signsvc.CodeStoreFailed:
		return http.StatusInternalServerError
	}
	return http.StatusUnprocessableEntity
}
