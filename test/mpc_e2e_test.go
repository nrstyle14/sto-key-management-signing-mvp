//go:build integration

// 종단 시험(T5.1, D-25): 같은 요청 흐름을 HSM 서명기와 MPC 서명기로 각각 처리한다(서명기만 바꿈).
//
//	① 새 종목에서 기관 B 대체 키(HSM)로 계좌 등록 요청 → 승인 2건 → 서명 → Besu 확정
//	② stoctl key rotate --backend mpc 로 기관 B 대체 키를 MPC 키(mpcd 3개, 2-of-3)로 교체
//	③ 같은 흐름(같은 함수) → MPC 서명 → Besu 확정, 원장 송신자 = MPC 키 주소
//	④ mpcd-1 정지: 남은 2개 노드로 서명·확정
//	⑤ mpcd-2 도 정지: 서명 서버 8단계 HSM_SIGN_FAILED 거부(signatures 기록 없음), 요청은 APPROVED 유지 → 노드 재기동 뒤 같은 요청 확정
//
// 끝난 뒤 기관 B 대체 키는 MPC 키로 남는다(이후 시험·시연의 기관 B 서명은 MPC 로 한다).
package test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
)

// registerViaInstB 는 기관 B 대체 키로 새 주소를 원장에 등록하는 요청을 기안·승인하고 끝 상태를 기다린다.
func registerViaInstB(t *testing.T, stoctl string, contract common.Address) workflow.Request {
	t.Helper()
	var a common.Address
	_, _ = rand.Read(a[:])
	return draftVia(t, stoctl, "inst-b", "TRANSFER", contract.Hex(), "registerAccount(address,string)", a.Hex()+",inst-b", "apr-b-01", "apr-b-02", "apr-b-03")
}

func activeKeyLine(t *testing.T, stoctl, inst, purpose string) (keyID, addr, backend string) {
	t.Helper()
	for _, line := range strings.Split(stoctlRun(t, stoctl, "key", "list"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 7 && f[1] == "besu-local" && f[2] == inst && f[3] == purpose && f[4] == "ACTIVE" {
			return f[0], f[5], f[6]
		}
	}
	t.Fatalf("%s/%s ACTIVE 키가 없다", inst, purpose)
	return
}

// txSender 는 확정된 tx 의 원장 송신자다.
func txSender(t *testing.T, hash string) common.Address {
	t.Helper()
	ctx := context.Background()
	eth, err := ethclient.DialContext(ctx, besuRPC)
	if err != nil {
		t.Fatal(err)
	}
	defer eth.Close()
	tx, _, err := eth.TransactionByHash(ctx, common.HexToHash(hash))
	if err != nil {
		t.Fatal(err)
	}
	from, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
	if err != nil {
		t.Fatal(err)
	}
	return from
}

func TestSameRequestFlowHSMThenMPC(t *testing.T) {
	stoctl := buildStoctl(t)
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	code := "KRMP" + strings.ToUpper(hex.EncodeToString(b))
	out := runScript(t, stoctl, "bootstrap-security.sh", code, "MPC 시험 "+code)
	m := regexp.MustCompile(`CONTRACT=(0x[0-9a-fA-F]{40})`).FindStringSubmatch(out)
	if m == nil {
		t.Fatal("배포 스크립트 출력에 CONTRACT= 가 없다")
	}
	contract := common.HexToAddress(m[1])

	// ① 지금의 기관 B 대체 키로(앞선 실행이 남긴 MPC 키일 수 있어, 먼저 HSM 키로 맞춘다)
	if _, _, backend := activeKeyLine(t, stoctl, "inst-b", "TRANSFER"); backend != "HSM" {
		t.Logf("기관 B 대체 키가 %s 다. HSM 키로 교체한 뒤 시작한다", backend)
		stoctlRun(t, stoctl, "key", "rotate", "--institution", "inst-b", "--purpose", "TRANSFER", "--drafter", "sec-01",
			"--approver", "sec-02", "--approver", "sec-03", "--backend", "hsm", "--reason", "MPC 시험 준비")
	}
	hsmKey, hsmAddr, _ := activeKeyLine(t, stoctl, "inst-b", "TRANSFER")
	r := registerViaInstB(t, stoctl, contract)
	if r.Status != workflow.StatusConfirmed || !strings.EqualFold(r.SignerAddress, hsmAddr) || txSender(t, r.TxHash) != common.HexToAddress(hsmAddr) {
		t.Fatalf("HSM 서명 흐름: %s %s 서명자 %s (기대 %s %s)", r.Status, r.Error, r.SignerAddress, hsmKey, hsmAddr)
	}

	// ② 서명기만 바꾼다
	t0 := time.Now()
	out = stoctlRun(t, stoctl, "key", "rotate", "--institution", "inst-b", "--purpose", "TRANSFER", "--drafter", "sec-01",
		"--approver", "sec-02", "--approver", "sec-03", "--backend", "mpc", "--reason", "MPC 서명기로 교체(T5.1)")
	t.Logf("HSM → MPC 교체 %s", time.Since(t0).Round(time.Second))
	mpcKey, mpcAddr, backend := activeKeyLine(t, stoctl, "inst-b", "TRANSFER")
	if backend != "MPC" || mpcKey == hsmKey {
		t.Fatalf("교체 뒤 키 %s %s\n%s", mpcKey, backend, out)
	}

	// ③ 같은 흐름을 MPC 로
	t1 := time.Now()
	r = registerViaInstB(t, stoctl, contract)
	if r.Status != workflow.StatusConfirmed || !strings.EqualFold(r.SignerAddress, mpcAddr) || txSender(t, r.TxHash) != common.HexToAddress(mpcAddr) {
		t.Fatalf("MPC 서명 흐름: %s %s 서명자 %s (기대 %s)", r.Status, r.Error, r.SignerAddress, mpcAddr)
	}
	t.Logf("MPC 서명 요청 기안~확정 %s", time.Since(t1).Round(time.Millisecond))
	var n int
	if err := signerDB(t).QueryRow(`SELECT COUNT(*) FROM signatures WHERE request_id = ? AND key_id = ?`, r.RequestID, mpcKey).Scan(&n); err != nil || n != 1 {
		t.Fatalf("MPC 서명 기록 %d %v", n, err)
	}

	// ④ 노드 1개 정지: 2-of-3 이라 서명된다
	t.Cleanup(func() { compose(t, "up", "-d", "--wait", "mpcd-1", "mpcd-2") })
	compose(t, "stop", "mpcd-1")
	r = registerViaInstB(t, stoctl, contract)
	if r.Status != workflow.StatusConfirmed || !strings.EqualFold(r.SignerAddress, mpcAddr) {
		t.Fatalf("노드 1개 정지 중 서명: %s %s", r.Status, r.Error)
	}

	// ⑤ 노드 2개 정지: 서명 서버가 8단계 HSM_SIGN_FAILED 로 거부하고(서명 기록 없음), 업무 서버는 HSM 장애와 같이
	// 일시 오류로 보고 APPROVED 를 유지한다. 노드가 돌아오면 같은 요청이 서명·확정된다.
	compose(t, "stop", "mpcd-2")
	var a common.Address
	_, _ = rand.Read(a[:])
	draftOut := stoctlRun(t, stoctl, "request", "draft", "--institution", "inst-b", "--purpose", "TRANSFER", "--contract", contract.Hex(),
		"--function", "registerAccount(address,string)", "--args", a.Hex()+",inst-b", "--drafter", "apr-b-01")
	var req workflow.Request
	if err := json.Unmarshal([]byte(draftOut), &req); err != nil {
		t.Fatalf("기안 응답: %v\n%s", err, draftOut)
	}
	approveRequest(t, stoctl, req.RequestID, "apr-b-02", "apr-b-03")
	sdb := signerDB(t)
	deadline := time.Now().Add(60 * time.Second)
	var payload string
	for sdb.QueryRow(`SELECT payload_json FROM audit_log WHERE action = 'SIGN_REJECTED' AND subject = ? ORDER BY seq LIMIT 1`, req.RequestID).Scan(&payload) != nil {
		if time.Now().After(deadline) {
			t.Fatal("노드 2개 정지 중 서명 거부 감사 기록이 없다")
		}
		time.Sleep(500 * time.Millisecond)
	}
	var p map[string]any
	_ = json.Unmarshal([]byte(payload), &p)
	if p["code"] != "HSM_SIGN_FAILED" {
		t.Fatalf("거부 감사 기록 %s", payload)
	}
	if st := requestStatus(t, req.RequestID); st.Status != workflow.StatusApproved {
		t.Fatalf("노드 2개 정지 중 요청 상태 %s(기대 APPROVED) %s", st.Status, st.Error)
	}
	if err := sdb.QueryRow(`SELECT COUNT(*) FROM signatures WHERE request_id = ?`, req.RequestID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("거부된 동안의 서명 기록 %d %v", n, err)
	}
	compose(t, "up", "-d", "--wait", "mpcd-1", "mpcd-2")
	r = waitStatusIn(t, req.RequestID, []workflow.Status{workflow.StatusConfirmed, workflow.StatusFailed}, 120*time.Second)
	if r.Status != workflow.StatusConfirmed || !strings.EqualFold(r.SignerAddress, mpcAddr) {
		t.Fatalf("노드 재기동 뒤 같은 요청: %s %s", r.Status, r.Error)
	}
}
