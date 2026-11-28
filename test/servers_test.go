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
	// 설정된 토큰(Besu 기관 3, 감사 1, Fabric 기관 A 1, D-26)이 모두 있고 세션이 정상이어야 한다.
	for _, label := range []string{"besu-local.platform", "besu-local.inst-a", "besu-local.inst-b", "audit", "fabric-local.inst-a"} {
		if toks[label] != "ok" {
			t.Fatalf("HSM 토큰 %s 상태 %v (전체 %v)", label, toks[label], toks)
		}
	}
	if len(toks) != 5 {
		t.Fatalf("HSM 토큰 5개 기대: %v", toks)
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
