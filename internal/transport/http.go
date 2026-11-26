package transport

import (
	"context"
	"encoding/json"
	"net/http"
)

type callerKey struct{}

// Caller 는 요청한 쪽의 클라이언트 인증서 CN 을 돌려준다. RequireCaller 를 거친 요청에만 값이 있다.
func Caller(ctx context.Context) string {
	v, _ := ctx.Value(callerKey{}).(string)
	return v
}

// ErrorBody 는 오류 응답 형식이다(설계서 13절).
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// 공통 오류 코드
const (
	CodeCallerNotAllowed = "CALLER_NOT_ALLOWED"
	CodeBadRequest       = "BAD_REQUEST"
	CodeInternal         = "INTERNAL"
	CodeUnavailable      = "UNAVAILABLE"
)

// WriteJSON 은 JSON 응답을 쓴다.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError 는 {"code","message"} 형식의 오류 응답을 쓴다.
func WriteError(w http.ResponseWriter, status int, code, msg string) {
	WriteJSON(w, status, ErrorBody{Code: code, Message: msg})
}

// RequireCaller 는 검증된 클라이언트 인증서 CN 이 allowed 에 있을 때만 next 를 부른다.
// 서버 TLS 설정의 허용 목록(핸드셰이크)보다 좁은 경로별 허용 목록에 쓴다.
func RequireCaller(allowed []string, next http.Handler) http.Handler {
	allow := toSet(allowed)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			WriteError(w, http.StatusForbidden, CodeCallerNotAllowed, "mTLS 연결이 아니다")
			return
		}
		cn, err := verifiedCN(*r.TLS)
		if err != nil || !allow[cn] {
			WriteError(w, http.StatusForbidden, CodeCallerNotAllowed, "이 경로를 호출할 수 없는 호출자다")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, cn)))
	})
}
