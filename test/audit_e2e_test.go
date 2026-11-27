//go:build integration

// 종단 시험(T2.7): 실행 중인 signerd 가 두 체인의 머리를 HSM AUDIT 키로 서명한 체크포인트를 만들고,
// stoctl audit verify 가 체인과 체크포인트 서명을 모두 확인한다. 체크포인트 파일(별도 볼륨)에도 남는다.
// (체크포인트 사이 구간 재작성 탐지는 internal/audit 의 시험이 실제 체인을 건드리지 않고 확인한다.)
package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
)

func triggerCheckpoint(t *testing.T) []audit.Checkpoint {
	t.Helper()
	resp, err := mtlsClient(t, "stoctl", "localhost").Post(signerdURL+"/v1/audit/checkpoints", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var v struct {
		Created []audit.Checkpoint `json:"created"`
	}
	if resp.StatusCode != 200 {
		t.Fatalf("체크포인트 요청 %d", resp.StatusCode)
	}
	_ = json.NewDecoder(resp.Body).Decode(&v)
	return v.Created
}

func TestCheckpointsAndVerify(t *testing.T) {
	// 양쪽 체인에 새 기록을 만든다(기안 1건 → api, 거부 1건 → signer).
	draftIssue(t, "3")
	in := transferIntent(t)
	if code, _ := postSign(t, mtlsClient(t, "apid", "localhost"), buildReq(t, in, 20261124, 0)); code != http.StatusUnprocessableEntity {
		t.Fatalf("승인 없는 서명 요청: %d", code)
	}
	// apid 가 머리를 알리는 주기(1초)를 기다리며 두 체인 체크포인트가 생길 때까지 요청한다.
	got := map[string]audit.Checkpoint{}
	deadline := time.Now().Add(15 * time.Second)
	for len(got) < 2 && time.Now().Before(deadline) {
		for _, cp := range triggerCheckpoint(t) {
			got[cp.Chain] = cp
		}
		time.Sleep(time.Second)
	}
	if _, ok := got["signer"]; !ok {
		t.Fatal("signer 체인 체크포인트가 생기지 않았다")
	}
	if _, ok := got["api"]; !ok {
		t.Fatal("api 체인 체크포인트가 생기지 않았다(apid 의 머리 전달)")
	}
	for _, cp := range got {
		if cp.KeyID != "key-audit-1" || len(cp.Signature) != 130 {
			t.Fatalf("체크포인트: %+v", cp)
		}
	}

	out, err := exec.Command("go", "run", filepath.Join(repoRoot(t), "cmd", "stoctl"), "--certs", filepath.Join(repoRoot(t), "deploy", "certs"),
		"audit", "verify").CombinedOutput()
	if err != nil {
		t.Fatalf("stoctl audit verify 실패: %v\n%s", err, out)
	}
	for _, want := range []string{"signer 체인: 정상", "api    체인: 정상", "signer 체크포인트:", "api    체크포인트:"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("검증 출력에 %q 가 없다:\n%s", want, out)
		}
	}
	if strings.Contains(string(out), "실패") {
		t.Fatalf("검증 실패 항목:\n%s", out)
	}
	t.Logf("\n%s", out)

	// 체크포인트 파일(별도 볼륨)
	fileOut, err := exec.Command("docker", "compose", "-f", filepath.Join(repoRoot(t), "deploy", "docker-compose.yml"), "exec", "-T", "signerd",
		"sh", "-c", "wc -l < /var/lib/sto/checkpoints/checkpoints.jsonl").CombinedOutput()
	if err != nil || strings.TrimSpace(string(fileOut)) == "0" {
		t.Fatalf("체크포인트 파일: %v %s", err, fileOut)
	}

	// api 머리가 뒤로 가는 보고는 거부된다.
	b, _ := json.Marshal(map[string]any{"seq": 1, "hash": strings.Repeat("00", 32)})
	resp, err := mtlsClient(t, "apid", "localhost").Post(signerdURL+"/v1/audit/api-head", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("머리 역행 보고: %d", resp.StatusCode)
	}
}

// 체크포인트는 요청 없이도 주기(audit.checkpoint_interval=20s)마다 만들어진다(FR-4.3 "주기적으로").
func TestPeriodicCheckpoint(t *testing.T) {
	count := func() int {
		resp, err := mtlsClient(t, "stoctl", "localhost").Get(signerdURL + "/v1/audit/checkpoints")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var v struct {
			Checkpoints []audit.Checkpoint `json:"checkpoints"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&v)
		return len(v.Checkpoints)
	}
	before := count()
	draftIssue(t, "4") // api 체인이 바뀐다(apid 가 머리를 알린다)
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if count() > before {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("45초 동안 주기 체크포인트가 생기지 않았다(전 %d 건)", before)
}
