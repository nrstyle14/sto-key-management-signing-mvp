//go:build integration

// 통합 테스트: make up 으로 뜬 signerd, apid 의 mTLS·헬스(T1.1).
package test

import (
	"encoding/json"
	"net/http"
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
