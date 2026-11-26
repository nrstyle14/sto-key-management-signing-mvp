//go:build integration && !signtx_m1

// 통합 테스트: make up 으로 뜬 signerd, apid 의 mTLS·헬스(T1.1)와 기본 빌드에 서명 API 가 없음(T1.5).
package test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func getJSON(t *testing.T, c *http.Client, url string) (int, map[string]any) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func TestSignerdHealthzOverMTLS(t *testing.T) {
	code, body := getJSON(t, mtlsClient(t, "stoctl", "localhost"), signerdURL+"/healthz")
	if code != 200 || body["status"] != "ok" || body["db"] != "ok" {
		t.Fatalf("signerd /healthz: %d %v", code, body)
	}
	toks, _ := body["hsm_tokens"].(map[string]any)
	if len(toks) != 4 {
		t.Fatalf("HSM 토큰 4개 기대: %v", toks)
	}
}

func TestApidHealthzOverMTLS(t *testing.T) {
	code, body := getJSON(t, mtlsClient(t, "stoctl", "localhost"), apidURL+"/healthz")
	if code != 200 || body["db"] != "ok" || body["rpc"] != "ok" || body["signer"] != "ok" {
		t.Fatalf("apid /healthz: %d %v", code, body)
	}
}

func TestServersRejectNoClientCert(t *testing.T) {
	for _, u := range []string{signerdURL, apidURL} {
		if resp, err := noCertClient(t, "localhost").Get(u + "/healthz"); err == nil {
			resp.Body.Close()
			t.Fatalf("%s: 클라이언트 인증서 없는 호출이 허용됐다(%d)", u, resp.StatusCode)
		}
	}
}

// 기본 빌드의 signerd 에는 서명 API 가 없다(정책·승인 검사가 생기는 T2.4 전까지).
func TestDefaultBuildHasNoSignAPI(t *testing.T) {
	resp, err := mtlsClient(t, "apid", "localhost").Post(signerdURL+"/v1/sign/tx", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("기본 빌드에서 /v1/sign/tx 상태 %d (기대 404)", resp.StatusCode)
	}
}
