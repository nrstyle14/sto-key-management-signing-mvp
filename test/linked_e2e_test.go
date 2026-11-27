//go:build integration

// 종단 시험(T4.1): 연계장부 계좌 등록부터 발행·계좌대체 후 보유 수량 반영까지. 서명은 실제 signerd(SoftHSM2 키),
// 확정은 Besu, 보유 수량은 업무 서버의 이벤트 수신이 갱신한다. 실행할 때마다 새 종목 코드·계좌번호를 쓴다.
//
//	종목 배포 → 계좌 A(inst-a)·B(inst-b) 등록(무작위 주소, 원장 등록 요청 기안)
//	→ 화이트리스트 추가 전 발행 기안은 POLICY_RECIPIENT_NOT_WHITELISTED
//	→ 보안관리자 2명 서명 화이트리스트 추가 → 등록 요청 승인·확정 → 계좌 ACTIVE
//	→ A 발행 700 → A→B 계좌대체 200 → 보유 수량 A 500, B 200 = 원장 balanceOf
package test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger/besu"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/linked"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
)

type registered struct {
	AccountNo      string `json:"account_no"`
	OnchainAddress string `json:"onchain_address"`
	Status         string `json:"status"`
	RequestID      string `json:"request_id"`
}

// approveRequest 는 stoctl 로 요청을 승인한다(승인자 키 파일).
func approveRequest(t *testing.T, bin, id string, approvers ...string) {
	t.Helper()
	for _, a := range approvers {
		stoctlRun(t, bin, "request", "approve", id, "--key", "deploy/approvers/"+a+".json", "--password-file", "deploy/secrets/approver_"+a+"_password")
	}
}

// draftVia 는 stoctl 로 기안하고 승인 2건을 붙인 뒤 끝 상태를 기다린다.
func draftVia(t *testing.T, bin, inst, purpose, contract, fn, args, drafter string, approvers ...string) workflow.Request {
	t.Helper()
	out := stoctlRun(t, bin, "request", "draft", "--institution", inst, "--purpose", purpose, "--contract", contract,
		"--function", fn, "--args", args, "--drafter", drafter)
	var r workflow.Request
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("기안 응답: %v\n%s", err, out)
	}
	approveRequest(t, bin, r.RequestID, approvers...)
	return waitStatusIn(t, r.RequestID, []workflow.Status{workflow.StatusConfirmed, workflow.StatusFailed}, 90*time.Second)
}

func waitAccount(t *testing.T, no string, ok func(linked.Account) bool, timeout time.Duration) linked.Account {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var a linked.Account
		if code := apidCall(t, "GET", "/v1/accounts/"+no, nil, &a); code != 200 {
			t.Fatalf("계좌 조회 HTTP %d", code)
		}
		if ok(a) {
			return a
		}
		if time.Now().After(deadline) {
			t.Fatalf("계좌 %s 가 기대 상태가 되지 않았다: %+v", no, a)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func qtyOf(a linked.Account, code string) string {
	for _, h := range a.Holdings {
		if h.IssueCode == code {
			return h.Quantity
		}
	}
	return "0"
}

// linkedState 는 linkedFlow 가 만든 상태다.
type linkedState struct {
	stoctl, code string
	contract     common.Address
	a, b         registered
}

func TestLinkedAccountRegisterIssueHoldings(t *testing.T) { linkedFlow(t) }

// linkedFlow 는 종목 배포부터 계좌 등록·발행·대체·보유 수량 확인까지(T4.1)를 수행한다.
func linkedFlow(t *testing.T) linkedState {
	t.Helper()
	stoctl := buildStoctl(t)
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	sfx := strings.ToUpper(hex.EncodeToString(b))
	code := "KRLK" + sfx

	out := runScript(t, stoctl, "bootstrap-security.sh", code, "연계장부 시험 "+code)
	m := regexp.MustCompile(`CONTRACT=(0x[0-9a-fA-F]{40})`).FindStringSubmatch(out)
	if m == nil {
		t.Fatal("배포 스크립트 출력에 CONTRACT= 가 없다")
	}
	contract := common.HexToAddress(m[1])

	register := func(no, inst, holder, drafter string) registered {
		t.Helper()
		out := stoctlRun(t, stoctl, "account", "register", "--account-no", no, "--institution", inst, "--holder", holder,
			"--security", code, "--drafter", drafter)
		var r registered
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatalf("계좌 등록 응답: %v\n%s", err, out)
		}
		if r.Status != linked.StatusPending || r.RequestID == "" {
			t.Fatalf("계좌 등록 %+v", r)
		}
		return r
	}
	accA := register("LK-A-"+sfx, "inst-a", "시험권리자A"+sfx, "apr-a-01")
	accB := register("LK-B-"+sfx, "inst-b", "시험권리자B"+sfx, "apr-b-01")

	// 화이트리스트에 추가하기 전에는 새 주소로 발행을 기안할 수 없다(업무 서버 사전 검사)
	cmd := exec.Command(stoctl, "request", "draft", "--institution", "inst-a", "--purpose", "ISSUE", "--contract", contract.Hex(),
		"--function", "issue(address,uint256)", "--args", accA.OnchainAddress+",700", "--drafter", "apr-a-01")
	cmd.Dir = repoRoot(t)
	if o, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(o), "POLICY_RECIPIENT_NOT_WHITELISTED") {
		t.Fatalf("화이트리스트 전 발행 기안: %v\n%s", err, o)
	}

	for _, acc := range []registered{accA, accB} {
		stoctlRun(t, stoctl, "policy", "whitelist-add", "--account", acc.AccountNo, "--approver", "sec-02", "--approver", "sec-03")
	}
	approveRequest(t, stoctl, accA.RequestID, "apr-a-02", "apr-a-03")
	approveRequest(t, stoctl, accB.RequestID, "apr-b-02", "apr-b-03")
	for _, id := range []string{accA.RequestID, accB.RequestID} {
		if r := waitStatusIn(t, id, []workflow.Status{workflow.StatusConfirmed, workflow.StatusFailed}, 90*time.Second); r.Status != workflow.StatusConfirmed {
			t.Fatalf("계좌 등록 요청 %s: %s %s", id, r.Status, r.Error)
		}
	}
	active := func(a linked.Account) bool { return a.Status == linked.StatusActive }
	waitAccount(t, accA.AccountNo, active, 30*time.Second)
	waitAccount(t, accB.AccountNo, active, 30*time.Second)

	// 원장의 계좌 등록 이벤트에는 주소와 기관 ID 만 있다(권리자 이름·계좌번호 없음)
	for _, e := range storedEvents(t, contract) {
		if e.Event != "AccountRegistered" {
			continue
		}
		raw, _ := json.Marshal(e.Payload)
		if strings.Contains(string(raw), "시험권리자") || strings.Contains(string(raw), "LK-") {
			t.Fatalf("원장 이벤트에 실명·계좌번호가 있다: %s", raw)
		}
	}

	if r := draftVia(t, stoctl, "inst-a", "ISSUE", contract.Hex(), "issue(address,uint256)", accA.OnchainAddress+",700", "apr-a-01", "apr-a-02", "apr-a-03"); r.Status != workflow.StatusConfirmed {
		t.Fatalf("발행: %s %s", r.Status, r.Error)
	}
	if r := draftVia(t, stoctl, "inst-a", "TRANSFER", contract.Hex(), "transferByAgent(address,address,uint256)",
		accA.OnchainAddress+","+accB.OnchainAddress+",200", "apr-a-01", "apr-a-02", "apr-a-03"); r.Status != workflow.StatusConfirmed {
		t.Fatalf("계좌대체: %s %s", r.Status, r.Error)
	}

	ctx := context.Background()
	eth, err := ethclient.DialContext(ctx, besuRPC)
	if err != nil {
		t.Fatal(err)
	}
	defer eth.Close()
	led, err := besu.New(eth, besu.Config{ChainID: 20261124, GasLimit: 300000, DeployGasLimit: 3000000})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		acc  registered
		want string
	}{{accA, "500"}, {accB, "200"}} {
		a := waitAccount(t, c.acc.AccountNo, func(a linked.Account) bool { return qtyOf(a, code) == c.want }, 30*time.Second)
		bal, err := led.BalanceOf(ctx, contract, common.HexToAddress(c.acc.OnchainAddress))
		if err != nil {
			t.Fatal(err)
		}
		if bal.Sign() == 0 || bal.String() != qtyOf(a, code) {
			t.Fatalf("계좌 %s: 연계장부 %s, 원장 balanceOf %s", a.AccountNo, qtyOf(a, code), bal)
		}
	}
	return linkedState{stoctl: stoctl, code: code, contract: contract, a: accA, b: accB}
}

// TestReconDetectsTamperedHolding 은 T4.2 완료 기준이다: 연계장부 수량을 임의로 바꾸면 대사가 그 계좌와 차이를
// 정확히 보고한다(계좌 잔고·이벤트 재생 차이는 그 계좌만, 총발행량 차이는 바꾼 만큼). 원장은 실제 Besu 다.
func TestReconDetectsTamperedHolding(t *testing.T) {
	st := linkedFlow(t)
	db := openAs(t, "api_app", "api")
	recon := func() reconRun {
		t.Helper()
		cmd := exec.Command(st.stoctl, "recon", "run", "--security", st.code, "--json")
		cmd.Dir = repoRoot(t)
		out, err := cmd.Output()
		var ee *exec.ExitError
		if err != nil && !(errors.As(err, &ee) && ee.ExitCode() == 3) {
			t.Fatalf("recon run: %v\n%s", err, out)
		}
		var r reconRun
		if err := json.Unmarshal(out, &r); err != nil {
			t.Fatalf("recon 응답: %v\n%s", err, out)
		}
		return r
	}
	if r := recon(); r.Status != "OK" || r.DiffCount != 0 {
		t.Fatalf("변경 전 대사: %+v", r)
	}
	// 연계장부 B 수량 200 → 213 (착오기재 흉내)
	if _, err := db.Exec(`UPDATE holdings SET quantity = quantity + 13 WHERE account_no = ? AND issue_code = ?`, st.b.AccountNo, st.code); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`UPDATE holdings SET quantity = quantity - 13 WHERE account_no = ? AND issue_code = ?`, st.b.AccountNo, st.code)
	})
	r := recon()
	var got []string
	for _, d := range r.Diffs {
		got = append(got, d.Kind+"/"+d.AccountNo+"/"+d.Expected+"/"+d.Actual)
	}
	want := []string{"BALANCE/" + st.b.AccountNo + "/200/213", "TOTAL_SUPPLY//700/713", "EVENT_REPLAY/" + st.b.AccountNo + "/200/213"}
	if r.Status != "MISMATCH" || strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("변경 뒤 대사 %s: %v (기대 %v)", r.Status, got, want)
	}
	var alarms int
	if err := db.QueryRow(`SELECT COUNT(*) FROM alarms WHERE rule = 'TOTAL_MISMATCH' AND subject = ?`, st.code).Scan(&alarms); err != nil || alarms != 1 {
		t.Fatalf("대사 불일치 알람 %d %v", alarms, err)
	}
	// stoctl recon show 로 같은 결과를 다시 볼 수 있다
	out := stoctlRun(t, st.stoctl, "recon", "show", strconv.FormatUint(r.RunID, 10))
	if !strings.Contains(out, "MISMATCH") || !strings.Contains(out, st.b.AccountNo) {
		t.Fatalf("recon show:\n%s", out)
	}
}

type reconRun struct {
	RunID     uint64 `json:"run_id"`
	Status    string `json:"status"`
	DiffCount int    `json:"diff_count"`
	Diffs     []struct {
		Kind      string `json:"kind"`
		AccountNo string `json:"account_no"`
		Expected  string `json:"expected"`
		Actual    string `json:"actual"`
	} `json:"diffs"`
}
