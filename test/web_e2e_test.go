//go:build integration

// 종단 시험(T4.3): 읽기 전용 웹(별도 포트, D-9)이 뜨고 요청의 상태 변화가 보인다. 쓰기 경로가 없다.
package test

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
)

const webURL = "http://127.0.0.1:9080"

func webPage(t *testing.T) string {
	t.Helper()
	resp, err := http.Get(webURL + "/")
	if err != nil {
		t.Fatalf("읽기 전용 웹: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("GET / → %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	return string(b)
}

// rowStatus 는 화면의 요청 표에서 그 요청 행의 상태 배지를 찾는다.
func rowStatus(page, id string) string {
	m := regexp.MustCompile(`<code>` + id + `</code>.*?<span class="b ([A-Z_]+)">`).FindStringSubmatch(page)
	if m == nil {
		return ""
	}
	return m[1]
}

func TestReadOnlyWebShowsStateChanges(t *testing.T) {
	page := webPage(t)
	for _, h := range []string{"감사 체인 머리", "대사", "업무 요청", "키 레지스트리", "동결", "알람"} {
		if !strings.Contains(page, h) {
			t.Fatalf("화면에 %q 절이 없다", h)
		}
	}
	// 기안 → 화면에 PENDING_APPROVAL, 반려 → REJECTED
	r := draftIssue(t, "10")
	if s := rowStatus(webPage(t), r.RequestID); s != string(workflow.StatusPendingApproval) {
		t.Fatalf("기안 뒤 화면 상태 %q", s)
	}
	if code, _ := approveVia(t, r, "apr-a-02", approval.Reject); code != 200 {
		t.Fatalf("반려 HTTP %d", code)
	}
	if s := rowStatus(webPage(t), r.RequestID); s != string(workflow.StatusRejected) {
		t.Fatalf("반려 뒤 화면 상태 %q", s)
	}
	// 쓰기·API 경로 없음: GET / 외에는 405·404
	for _, c := range []struct{ method, path string }{{"POST", "/"}, {"PUT", "/"}, {"DELETE", "/"}, {"GET", "/v1/requests"}, {"POST", "/v1/requests"}, {"GET", "/v1/accounts"}} {
		req, _ := http.NewRequest(c.method, webURL+c.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s %s → %d (쓰기·API 경로가 열려 있다)", c.method, c.path, resp.StatusCode)
		}
	}
	if strings.Contains(page, "holder_name") || strings.Contains(page, "시험권리자") {
		t.Fatal("화면에 권리자 이름이 있다")
	}
}
