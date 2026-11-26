//go:build signtx_m1

package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/hsm"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	signerhsm "github.com/da-infra/sto-key-management-signing-mvp/internal/signer/hsm"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signsvc"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

// signTxCallers 는 POST /v1/sign/tx 를 호출할 수 있는 CN 이다. 업무 서버만 허용한다.
var signTxCallers = []string{"apid"}

// registerSignRoutes 는 통합 시험용 빌드(signtx_m1)에서만 서명 API 를 연다(작업지시서 T1.5).
// 이 단계의 서명 API 는 설계서 5.3 의 5·6단계(정책, 승인)가 아직 없다. T2.4 에서 채우고 태그를 없앤다.
func registerSignRoutes(a *app, mux *http.ServeMux) {
	toks := make([]*hsm.Token, 0, len(a.tokens))
	for _, t := range a.tokens {
		toks = append(toks, t)
	}
	chains := map[string]uint64{}
	for _, l := range a.cfg.Ledgers {
		chains[l.ID] = l.ChainID
	}
	svc := &signsvc.Service{
		DB:      a.db,
		Signer:  signerhsm.New(toks, keyreg.TokenLabelOf(a.db)),
		Chains:  chains,
		MaxGas:  a.cfg.Signing.MaxGasLimit,
		Callers: signTxCallers,
	}
	a.log.Warn("서명 API 활성(통합 시험용 빌드 signtx_m1: 정책·승인 검사 미구현)")
	mux.Handle("POST /v1/sign/tx", transport.RequireCaller(signTxCallers, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				// TODO(T2.4): 모든 거부를 감사로그에 사유와 함께 남긴다.
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
