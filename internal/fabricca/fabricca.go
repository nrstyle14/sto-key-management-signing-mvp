// Package fabricca 는 Fabric CA REST 클라이언트다(설계서 10.5, D-26). stoctl 이 쓴다.
//
// fabric-ca 의 Go 클라이언트(lib.Client)는 자체 BCCSP 로 HSM 에 직접 붙어 "서명 서버만 HSM" 규칙과 충돌하므로
// REST 를 직접 부른다. 신원 키의 CSR·토큰 서명은 서명 서버 키 작업으로 받는다. registrar 키만 파일이다(한계).
// 토큰 형식(fabric-ca v1.5.22 util.GenECDSAToken): base64(인증서 PEM) + "." + base64(DER 서명),
// 서명 대상 SHA-256(메서드 "." base64(uri) "." base64(본문) "." base64(인증서 PEM)).
package fabricca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

// Client 는 CA 주소다(예: http://127.0.0.1:7054).
type Client struct {
	URL  string
	HTTP *http.Client
}

// New 는 클라이언트를 만든다.
func New(url string) *Client { return &Client{URL: url, HTTP: &http.Client{Timeout: 30 * time.Second}} }

type response struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

// Do 는 요청을 보낸다. auth 는 본문 바이트를 받아 Authorization 을 정한다(Basic 또는 토큰).
func (c *Client) Do(method, uri string, body []byte, auth func(*http.Request, []byte) error) (json.RawMessage, error) {
	req, err := http.NewRequest(method, c.URL+uri, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := auth(req, body); err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var r response
	_ = json.Unmarshal(raw, &r)
	if !r.Success {
		msg := string(raw)
		if len(r.Errors) > 0 {
			msg = fmt.Sprintf("%d %s", r.Errors[0].Code, r.Errors[0].Message)
		}
		return nil, &HTTPError{Method: method, URI: uri, Status: resp.StatusCode, Msg: msg}
	}
	return r.Result, nil
}

// HTTPError 는 CA 가 실패로 응답한 요청이다.
type HTTPError struct {
	Method, URI string
	Status      int
	Msg         string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("fabric-ca %s %s: HTTP %d %s", e.Method, e.URI, e.Status, e.Msg)
}

// Basic 은 enroll 용 Basic 인증이다.
func Basic(user, secret string) func(*http.Request, []byte) error {
	return func(r *http.Request, _ []byte) error { r.SetBasicAuth(user, secret); return nil }
}

// TokenPayload 는 토큰 서명 대상 문자열이다.
func TokenPayload(method, uri string, body, certPEM []byte) string {
	b64 := base64.StdEncoding.EncodeToString
	return method + "." + b64([]byte(uri)) + "." + b64(body) + "." + b64(certPEM)
}

// SoftwareToken 은 소프트웨어 키(registrar)로 만드는 토큰 인증이다.
func SoftwareToken(k *ecdsa.PrivateKey, certPEM []byte) func(*http.Request, []byte) error {
	return func(r *http.Request, body []byte) error {
		d := sha256.Sum256([]byte(TokenPayload(r.Method, r.URL.Path, body, certPEM)))
		// Fabric CA 는 high-S 서명을 거부한다(로그 "Invalid S. Must be smaller than half the order"). Go 의
		// ecdsa.SignASN1 은 약 절반이 high-S 이므로 low-S 로 맞춘다.
		rr, ss, err := ecdsa.Sign(rand.Reader, k, d[:])
		if err != nil {
			return err
		}
		sig, err := signer.P256DER(rr, ss)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", base64.StdEncoding.EncodeToString(certPEM)+"."+base64.StdEncoding.EncodeToString(sig))
		return nil
	}
}

// FixedToken 은 서명 서버가 미리 만든 토큰이다(신원 키 재발급, 본문이 같아야 한다).
func FixedToken(token string) func(*http.Request, []byte) error {
	return func(r *http.Request, _ []byte) error { r.Header.Set("Authorization", token); return nil }
}

// CertFrom 은 enroll·reenroll 결과의 인증서 PEM 이다.
func CertFrom(res json.RawMessage) ([]byte, error) {
	var v struct{ Cert string }
	if err := json.Unmarshal(res, &v); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(v.Cert)
}

// EnrollBody 는 enroll·reenroll 본문이다.
func EnrollBody(csrPEM string) []byte {
	b, _ := json.Marshal(map[string]any{"certificate_request": csrPEM})
	return b
}

// SoftwareCSR 은 소프트웨어 키 CSR 이다(registrar).
func SoftwareCSR(k *ecdsa.PrivateKey, cn string) (string, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// CRLFrom 은 revoke(gencrl) 결과의 CRL PEM 이다.
func CRLFrom(res json.RawMessage) ([]byte, error) {
	var v struct{ CRL string }
	if err := json.Unmarshal(res, &v); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(v.CRL)
}
