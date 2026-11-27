//go:build integration

// 종단 시험(T3.3·T3.4): 스크립트 한 번으로 종목 배포와 역할 부여, stoctl 로 계좌 등록 → 발행 → 계좌대체,
// 그리고 업무 서버를 강제 종료(SIGKILL)했다 살려도 보존된 원장 이벤트가 빠지거나 중복되지 않는다.
// 서명은 모두 실제 signerd(SoftHSM2 키)를 거친다. 실행할 때마다 새 종목 코드를 쓴다.
package test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/registry"
)

// buildStoctl 은 현재 소스로 stoctl 을 임시 디렉터리에 빌드한다.
func buildStoctl(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "stoctl")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/stoctl")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("stoctl 빌드: %v\n%s", err, out)
	}
	return bin
}

func runScript(t *testing.T, stoctl string, script string, args ...string) string {
	t.Helper()
	cmd := exec.Command(filepath.Join(repoRoot(t), "scripts", script), args...)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "STOCTL="+stoctl)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", script, err, out)
	}
	t.Logf("%s:\n%s", script, out)
	return string(out)
}

func storedEvents(t *testing.T, contract common.Address) []registry.Event {
	t.Helper()
	var all []registry.Event
	after := uint64(0)
	for {
		var v struct {
			Events []registry.Event `json:"events"`
		}
		q := url.Values{"contract": {contract.Hex()}, "after": {strconv.FormatUint(after, 10)}, "limit": {"1000"}}
		if code := apidCall(t, "GET", "/v1/registry-events?"+q.Encode(), nil, &v); code != 200 {
			t.Fatalf("이벤트 조회 %d", code)
		}
		all = append(all, v.Events...)
		if len(v.Events) < 1000 {
			return all
		}
		after = v.Events[len(v.Events)-1].ID
	}
}

func TestSecurityBootstrapFlowAndRegistryRestart(t *testing.T) {
	stoctl := buildStoctl(t)
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	code := "KRIT" + strings.ToUpper(hex.EncodeToString(b))

	out := runScript(t, stoctl, "bootstrap-security.sh", code, "시험 종목 "+code)
	m := regexp.MustCompile(`CONTRACT=(0x[0-9a-fA-F]{40})`).FindStringSubmatch(out)
	if m == nil {
		t.Fatal("배포 스크립트 출력에 CONTRACT= 가 없다")
	}
	contract := common.HexToAddress(m[1])
	runScript(t, stoctl, "flow-issue-transfer.sh", contract.Hex(), "1000", "300")

	// 업무 서버를 강제 종료했다 살린다(수신 작업자 포함). 그 사이에 쌓인 블록도 따라잡아야 한다.
	compose(t, "kill", "-s", "SIGKILL", "apid")
	time.Sleep(3 * time.Second)
	compose(t, "up", "-d", "--wait", "apid")

	ctx := context.Background()
	eth, err := ethclient.DialContext(ctx, besuRPC)
	if err != nil {
		t.Fatal(err)
	}
	defer eth.Close()
	head, err := eth.BlockNumber(ctx)
	if err != nil {
		t.Fatal(err)
	}
	logs, err := eth.FilterLogs(ctx, ethereum.FilterQuery{FromBlock: big.NewInt(0), ToBlock: new(big.Int).SetUint64(head), Addresses: []common.Address{contract}})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	var evs []registry.Event
	for {
		evs = storedEvents(t, contract)
		var upto int
		for _, e := range evs {
			if e.BlockNumber <= head {
				upto++
			}
		}
		if upto >= len(logs) || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	seen := map[string]bool{}
	names := map[string]int{}
	for _, e := range evs {
		k := e.TxHash + "/" + strconv.Itoa(int(e.LogIndex))
		if seen[k] {
			t.Fatalf("중복 저장된 이벤트 %s", k)
		}
		seen[k] = true
		names[e.Event]++
	}
	for _, l := range logs {
		if !seen[l.TxHash.Hex()+"/"+strconv.Itoa(int(l.Index))] {
			t.Fatalf("빠진 이벤트: 블록 %d tx %s 로그 %d", l.BlockNumber, l.TxHash.Hex(), l.Index)
		}
	}
	if names["Issued"] != 1 || names["Transferred"] != 1 || names["AccountRegistered"] != 2 || names["RoleGranted"] != 5 || names["AgentInstitutionSet"] != 3 {
		t.Fatalf("이벤트 건수 %v", names)
	}
	t.Logf("종목 %s(%s): 원장 로그 %d건 = 보존 %d건(중복 없음), apid 강제 종료·재기동 후", code, contract.Hex(), len(logs), len(evs))
}
