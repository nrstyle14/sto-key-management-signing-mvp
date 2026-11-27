//go:build integration

// 종단 시험(T2.5): 서명 서버를 내린 동안 요청이 APPROVED 에 머물다가, 다시 올리면 SIGNED 로 진행된다(NFR-4).
// 실제 apid·signerd 를 쓴다. signerd 는 시험 중 멈췄다가 정리 단계에서 반드시 다시 띄운다.
package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
)

func compose(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("docker", append([]string{"compose", "-f", filepath.Join(repoRoot(t), "deploy", "docker-compose.yml")}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker compose %v: %v\n%s", args, err, out)
	}
}

func apidCall(t *testing.T, method, path string, in, out any) int {
	t.Helper()
	var body *bytes.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	} else {
		body = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, apidURL+path, body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := mtlsClient(t, "stoctl", "localhost").Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	if out != nil && resp.StatusCode/100 == 2 {
		if err := json.Unmarshal(buf.Bytes(), out); err != nil {
			t.Fatal(err)
		}
	}
	if resp.StatusCode/100 != 2 {
		t.Logf("%s %s → %d %s", method, path, resp.StatusCode, buf.String())
	}
	return resp.StatusCode
}

func draftIssue(t *testing.T, amount string) workflow.Request {
	t.Helper()
	var r workflow.Request
	code := apidCall(t, "POST", "/v1/requests", workflow.DraftInput{InstitutionID: "inst-a", KeyPurpose: "ISSUE",
		Contract: common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3").Hex(), Function: "issue(address,uint256)",
		Args: []string{common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").Hex(), amount}, DrafterID: "apr-a-01"}, &r)
	if code != http.StatusCreated || r.Status != workflow.StatusPendingApproval {
		t.Fatalf("기안 실패: %d %+v", code, r)
	}
	return r
}

func approveVia(t *testing.T, r workflow.Request, id string, d approval.Decision) (int, workflow.Request) {
	t.Helper()
	in, err := intent.Parse(r.Intent)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := in.Hash()
	var out workflow.Request
	code := apidCall(t, "POST", "/v1/requests/"+r.RequestID+"/approvals", approverSign(t, id, h, d), &out)
	return code, out
}

func requestStatus(t *testing.T, id string) workflow.Request {
	t.Helper()
	var r workflow.Request
	if code := apidCall(t, "GET", "/v1/requests/"+id, nil, &r); code != 200 {
		t.Fatalf("조회 %d", code)
	}
	return r
}

func waitStatus(t *testing.T, id string, want workflow.Status, timeout time.Duration) workflow.Request {
	t.Helper()
	return waitStatusIn(t, id, []workflow.Status{want}, timeout)
}

// waitStatusIn 은 요청이 wants 중 하나가 될 때까지 기다린다.
func waitStatusIn(t *testing.T, id string, wants []workflow.Status, timeout time.Duration) workflow.Request {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		r := requestStatus(t, id)
		for _, w := range wants {
			if r.Status == w {
				return r
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s 상태 %s (기대 %v, %s 대기)", id, r.Status, wants, timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func TestRequestWaitsWhileSignerDownThenSigns(t *testing.T) {
	r := draftIssue(t, "10") // 업무 서버가 서명 서버 명부를 캐시한다
	compose(t, "stop", "signerd")
	t.Cleanup(func() { compose(t, "up", "-d", "--wait", "signerd") })

	if code, _ := approveVia(t, r, "apr-a-02", approval.Approve); code != 200 {
		t.Fatalf("서명 서버 장애 중 승인 1: %d", code)
	}
	code, got := approveVia(t, r, "apr-a-03", approval.Approve)
	if code != 200 || got.Status != workflow.StatusApproved {
		t.Fatalf("서명 서버 장애 중 승인 2: %d %s", code, got.Status)
	}
	time.Sleep(4 * time.Second) // 작업자 주기(1초)를 여러 번 지난다
	if s := requestStatus(t, r.RequestID).Status; s != workflow.StatusApproved {
		t.Fatalf("서명 서버 장애 중 상태 %s (기대 APPROVED)", s)
	}

	compose(t, "up", "-d", "--wait", "signerd")
	// 서명 뒤에는 업무 서버가 곧바로 원장에 제출한다(T3.2 이후). 서명 이후 상태면 된다.
	done := waitStatusIn(t, r.RequestID, []workflow.Status{workflow.StatusSigned, workflow.StatusSubmitted, workflow.StatusConfirmed}, 30*time.Second)
	signed := new(types.Transaction)
	if err := signed.UnmarshalBinary(common.FromHex(done.RawTx)); err != nil {
		t.Fatal(err)
	}
	from, err := types.Sender(types.LatestSignerForChainID(signed.ChainId()), signed)
	_, issueAddr := activeKey(t, "inst-a", "ISSUE")
	if err != nil || from != issueAddr || done.Nonce == nil || *done.Nonce != signed.Nonce() {
		t.Fatalf("서명된 tx: from=%s nonce=%v err=%v", from, done.Nonce, err)
	}
	t.Log(fmt.Sprintf("서명 서버 복구 후 SIGNED: request=%s tx=%s nonce=%d", done.RequestID, done.TxHash, *done.Nonce))
}

// 업무 API 의 거부(자기 승인, 한도 초과)와 반려.
func TestRequestAPIRejections(t *testing.T) {
	var e map[string]any
	code := apidCall(t, "POST", "/v1/requests", workflow.DraftInput{InstitutionID: "inst-a", KeyPurpose: "ISSUE",
		Contract: common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3").Hex(), Function: "issue(address,uint256)",
		Args: []string{common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").Hex(), "100001"}, DrafterID: "apr-a-01"}, &e)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("한도 초과 기안: %d", code)
	}
	r := draftIssue(t, "5")
	if code, _ := approveVia(t, r, "apr-a-01", approval.Approve); code != http.StatusUnprocessableEntity {
		t.Fatalf("자기 승인: %d", code)
	}
	if code, got := approveVia(t, r, "apr-a-02", approval.Reject); code != 200 || got.Status != workflow.StatusRejected {
		t.Fatalf("반려: %d %s", code, got.Status)
	}
}

// 기안 수량이 정책 한도의 80% 이상이면 업무 서버가 고액 알람을 남긴다(설계서 7.4).
func TestHighAmountAlarmViaApid(t *testing.T) {
	r := draftIssue(t, "80000")
	var v struct {
		Alarms []struct {
			Rule    string `json:"rule"`
			Subject string `json:"subject"`
		} `json:"alarms"`
	}
	if code := apidCall(t, "GET", "/v1/alarms?limit=50", nil, &v); code != 200 {
		t.Fatalf("알람 조회 %d", code)
	}
	for _, a := range v.Alarms {
		if a.Rule == "HIGH_AMOUNT" && a.Subject == r.RequestID {
			return
		}
	}
	t.Fatalf("요청 %s 의 HIGH_AMOUNT 알람이 없다: %+v", r.RequestID, v.Alarms)
}
