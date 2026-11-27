//go:build integration

// 종단 시험(T3.5): 기관 A 발행 키 교체와 이전 키 폐기. 실제 signerd(SoftHSM2), apid, Besu 를 쓴다.
//  1. 종목 배포·역할 부여, 계좌 등록·발행(scripts)
//  2. stoctl key rotate --until revoke: 새 키 생성(PENDING) → 새 키 역할 부여 → 이전 키 역할 회수
//  3. 컨트랙트 쪽 거부: 이전 키는 아직 서명 서버에서 ACTIVE 지만 역할이 없어 발행 tx 가 revert(FAILED)
//  4. 교체 마무리: 이전 키 퇴역 + 새 키 활성화(한 트랜잭션)
//  5. 새 키로 발행 성공(서명자 = 새 키 주소)
//  6. 서명 서버 쪽 거부: 이전 키 주소로 준비된 서명 요청은 4단계 KEY_ADDRESS_MISMATCH
//  7. 이전 키 폐기: HSM 객체가 없어졌는지 확인, 폐기 증적이 감사로그에 있다
package test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/oklog/ulid/v2"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signsvc"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
)

func stoctlRun(t *testing.T, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("stoctl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// draftIssueVia 는 stoctl 로 기관 A 발행을 기안·승인하고 끝 상태를 기다린다.
func draftIssueVia(t *testing.T, bin, contract, amount string) workflow.Request {
	t.Helper()
	out := stoctlRun(t, bin, "request", "draft", "--institution", "inst-a", "--purpose", "ISSUE", "--contract", contract,
		"--function", "issue(address,uint256)", "--args", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8,"+amount, "--drafter", "apr-a-01")
	var r workflow.Request
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("기안 응답: %v\n%s", err, out)
	}
	for _, a := range []string{"apr-a-02", "apr-a-03"} {
		stoctlRun(t, bin, "request", "approve", r.RequestID, "--key", "deploy/approvers/"+a+".json", "--password-file", "deploy/secrets/approver_"+a+"_password")
	}
	return waitStatusIn(t, r.RequestID, []workflow.Status{workflow.StatusConfirmed, workflow.StatusFailed}, 90*time.Second)
}

func TestRotateIssueKeyAndDestroyOld(t *testing.T) {
	bin := buildStoctl(t)
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	code := "KRRT" + strings.ToUpper(hex.EncodeToString(b))
	out := runScript(t, bin, "bootstrap-security.sh", code, "교체 시험 "+code)
	contract := regexp.MustCompile(`CONTRACT=(0x[0-9a-fA-F]{40})`).FindStringSubmatch(out)[1]
	runScript(t, bin, "flow-issue-transfer.sh", contract, "500", "100")

	oldID, oldAddr := activeKey(t, "inst-a", "ISSUE")
	sec := []string{"--approver", "sec-02", "--approver", "sec-03"}

	// 2. 교체를 이전 역할 회수까지 진행하고 멈춘다.
	args := append([]string{"key", "rotate", "--institution", "inst-a", "--purpose", "ISSUE", "--drafter", "sec-01",
		"--security", code, "--until", "revoke", "--reason", "정기 교체(시험)"}, sec...)
	out = stoctlRun(t, bin, args...)
	t.Logf("rotate --until revoke:\n%s", out)
	m := regexp.MustCompile(`--resume (key-inst-a-issue-[a-z0-9]+)@revoke`).FindStringSubmatch(out)
	if m == nil {
		t.Fatal("교체 출력에 새 키 ID 가 없다")
	}
	newID := m[1]
	if id, _ := activeKey(t, "inst-a", "ISSUE"); id != oldID {
		t.Fatalf("퇴역 전 ACTIVE 키 %s (기대 이전 키 %s)", id, oldID)
	}

	// 3. 컨트랙트 쪽 거부: 서명 서버는 이전 키로 서명하지만 역할이 회수돼 revert 된다.
	r := draftIssueVia(t, bin, contract, "7")
	if r.Status != workflow.StatusFailed || !strings.HasPrefix(r.Error, workflow.CodeLedgerReverted) || r.SignerAddress != oldAddr.Hex() {
		t.Fatalf("역할 회수 뒤 이전 키 발행: %s %s (서명자 %s)", r.Status, r.Error, r.SignerAddress)
	}

	// 4. 교체 마무리
	out = stoctlRun(t, bin, append([]string{"key", "rotate", "--institution", "inst-a", "--purpose", "ISSUE", "--drafter", "sec-01",
		"--security", code, "--resume", newID + "@revoke"}, sec...)...)
	t.Logf("rotate --resume:\n%s", out)
	id, newAddr := activeKey(t, "inst-a", "ISSUE")
	if id != newID {
		t.Fatalf("교체 뒤 ACTIVE 키 %s (기대 %s)", id, newID)
	}

	// 5. 새 키로 발행 성공
	r = draftIssueVia(t, bin, contract, "11")
	if r.Status != workflow.StatusConfirmed || r.SignerAddress != newAddr.Hex() {
		t.Fatalf("새 키 발행: %s %s (서명자 %s, 기대 %s)", r.Status, r.Error, r.SignerAddress, newAddr.Hex())
	}

	// 6. 서명 서버 쪽 거부: 이전 키 주소로 준비된 요청(승인 2건)
	ctx := context.Background()
	eth, err := ethclient.DialContext(ctx, besuRPC)
	if err != nil {
		t.Fatal(err)
	}
	defer eth.Close()
	in := &intent.Intent{RequestID: ulid.Make().String(), Type: intent.TypeTX, LedgerID: "besu-local", InstitutionID: "inst-a",
		KeyPurpose: signer.PurposeIssue, Contract: common.HexToAddress(contract).Hex(), Function: "issue(address,uint256)",
		Args: []string{"0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "5"}, DrafterID: "apr-a-01",
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(intent.TimeLayout)}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	nonce, _ := eth.PendingNonceAt(ctx, oldAddr)
	h, _ := in.Hash()
	req := buildReq(t, in, 20261124, nonce, approverSign(t, "apr-a-02", h, approval.Approve), approverSign(t, "apr-a-03", h, approval.Approve))
	req.SignerAddress = oldAddr.Hex()
	code2, body := postSign(t, mtlsClient(t, "apid", "localhost"), req)
	var rj signsvc.Rejection
	_ = json.Unmarshal(body, &rj)
	if code2 != http.StatusUnprocessableEntity || rj.Step != 4 || rj.Code != signsvc.CodeKeyMismatch || !strings.Contains(rj.Msg, "RETIRED") {
		t.Fatalf("이전 키 주소 서명 요청: %d %s", code2, body)
	}

	// 7. 이전 키 폐기와 증적
	out = stoctlRun(t, bin, append([]string{"key", "destroy", "--key", oldID, "--reason", "교체 완료 후 폐기(시험)"}, sec...)...)
	if !strings.Contains(out, `"status": "DESTROYED"`) || !strings.Contains(out, `"objects_remaining": 0`) {
		t.Fatalf("폐기 결과:\n%s", out)
	}
	stoctlRun(t, bin, "audit", "trail", oldID, "--require", "signer:KEY_RETIRED,signer:KEY_DESTROYED")
	stoctlRun(t, bin, "audit", "trail", newID, "--require", "signer:KEY_GENERATED,signer:KEY_ACTIVATED")
	var payload string
	if err := signerDB(t).QueryRow(`SELECT payload_json FROM audit_log WHERE action = 'KEY_DESTROYED' AND subject = ?`, oldID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, `"objects_after":0`) {
		t.Fatalf("폐기 증적: %s", payload)
	}
	// 폐기된 키는 다시 폐기·퇴역할 수 없다(서명 서버 거부, 감사 기록).
	cmd := exec.Command(bin, append([]string{"key", "destroy", "--key", oldID, "--reason", "재시도(시험)"}, sec...)...)
	cmd.Dir = repoRoot(t)
	if o, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(o), "KEYOP_KEY_STATE") {
		t.Fatalf("폐기된 키 재폐기: %v %s", err, o)
	}
	// 새 키로 서명된 발행 tx 의 송신자를 원장에서 확인한다.
	tx, _, err := eth.TransactionByHash(ctx, common.HexToHash(r.TxHash))
	if err != nil {
		t.Fatal(err)
	}
	from, _ := types.Sender(types.LatestSignerForChainID(big.NewInt(20261124)), tx)
	if from != newAddr {
		t.Fatalf("원장의 송신자 %s (기대 새 키 %s)", from.Hex(), newAddr.Hex())
	}
	t.Logf("교체: %s(%s) → %s(%s), 이전 키 폐기", oldID, oldAddr.Hex(), newID, newAddr.Hex())
}
