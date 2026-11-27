//go:build integration

// 종단 시험(T2.6): 업무 서버를 내린 상태에서 보안관리자 1인 서명 동결이 성공하고, 동결된 키의 서명 요청이 거부되며,
// 1인 서명 해제는 거부되고 2인 서명 해제는 성공한다. 정리 단계에서 apid 를 다시 띄우고 동결을 반드시 푼다.
package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/freeze"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signsvc"
)

func signerPost(t *testing.T, cn, path string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := mtlsClient(t, cn, "localhost").Post(signerdURL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func release(t *testing.T, freezeID string, admins ...string) (int, map[string]any) {
	t.Helper()
	rel := freeze.NewRelease(freezeID, time.Now())
	for _, a := range admins {
		k := approverKey(t, a)
		rel.SignRelease(a, k)
		clear(k)
	}
	return signerPost(t, "stoctl", "/v1/freezes/"+freezeID+"/release", rel)
}

func TestFreezeWhileApidDownAndReleaseNeedsTwo(t *testing.T) {
	target, _ := activeKey(t, "inst-b", "TRANSFER")
	compose(t, "stop", "apid")
	var freezeID string
	t.Cleanup(func() {
		if freezeID != "" {
			release(t, freezeID, "sec-01", "sec-02") // 이미 풀렸으면 409, 무시
		}
		compose(t, "up", "-d", "--wait", "apid")
	})

	// 업무 서버가 내려간 상태에서 보안관리자 1인 서명으로 즉시 동결(서명 서버 직접 호출)
	k := approverKey(t, "sec-01")
	req := freeze.NewRequest(freeze.ScopeKey, target, "도난 의심(시험)", "sec-01", k, time.Now())
	clear(k)
	if code, body := signerPost(t, "stoctl", "/v1/freezes", req); code != http.StatusCreated {
		t.Fatalf("동결 실패: %d %v", code, body)
	}
	freezeID = req.FreezeID
	// 같은 동결 요청 재전송은 거부
	if code, _ := signerPost(t, "stoctl", "/v1/freezes", req); code != http.StatusConflict {
		t.Fatalf("동결 재전송: %d", code)
	}

	// 동결된 키로의 서명 요청(승인 2건 포함)은 4단계에서 거부
	in := transferIntent(t)
	h, _ := in.Hash()
	sreq := buildReq(t, in, 20261124, 0, approverSign(t, "apr-b-02", h, approval.Approve), approverSign(t, "apr-b-03", h, approval.Approve))
	code, body := postSign(t, mtlsClient(t, "apid", "localhost"), sreq)
	var rj signsvc.Rejection
	_ = json.Unmarshal(body, &rj)
	if code != http.StatusUnprocessableEntity || rj.Step != 4 || rj.Code != signsvc.CodeKeyFrozen {
		t.Fatalf("동결된 키 서명: %d %s", code, body)
	}

	// 1인 서명 해제는 거부
	if code, body := release(t, freezeID, "sec-01"); code != http.StatusForbidden || body["code"] != freeze.CodeInsufficient {
		t.Fatalf("1인 해제: %d %v", code, body)
	}
	// 2인 서명 해제는 성공
	if code, body := release(t, freezeID, "sec-01", "sec-02"); code != http.StatusOK {
		t.Fatalf("2인 해제: %d %v", code, body)
	}
	// 해제 후에는 서명된다
	in2 := transferIntent(t)
	h2, _ := in2.Hash()
	sreq2 := buildReq(t, in2, 20261124, 0, approverSign(t, "apr-b-02", h2, approval.Approve), approverSign(t, "apr-b-03", h2, approval.Approve))
	if code, body := postSign(t, mtlsClient(t, "apid", "localhost"), sreq2); code != 200 {
		t.Fatalf("해제 후 서명: %d %s", code, body)
	}
	// 동결·해제가 감사로그에 남았다
	var n int
	if err := signerDB(t).QueryRow("SELECT COUNT(*) FROM audit_log WHERE subject = ? AND action IN ('FREEZE', 'FREEZE_RELEASED')", freezeID).Scan(&n); err != nil || n != 2 {
		t.Fatalf("동결·해제 감사 기록 %d (%v)", n, err)
	}
}
