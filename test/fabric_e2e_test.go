//go:build integration && fabric

// 종단 시험(T5.2, D-26 ⑧ 완료 기준). make up(볼륨을 지운 환경, Fabric 범위 부트스트랩) → make up-fabric 뒤 make it-fabric.
//
//	① HSM P-256 신원 키 생성·발급(stoctl fabric enroll: FABRIC_CSR → CA enroll → FABRIC_INSTALL_CERT)
//	② 승인된 FABRIC_TX 요청 → 서명 3종(PROPOSAL·TRANSACTION·COMMIT) → 체인코드 확정, 원장 기록의 등록 신원 = HSM 신원
//	③ 재발급(stoctl fabric reenroll: 새 키, 이전 인증서 토큰) → 새 신원으로 확정
//	④ 이전 신원 폐기(stoctl fabric revoke: CA 폐기 → 채널 설정 갱신 → 기록)
//	⑤ 현재 신원을 CA 폐기·채널 설정 갱신만 한 상태: 서명 서버는 서명하지만 원장(peer)이 거부 → FAILED(FABRIC_ENDORSE_FAILED)
//	⑥ 서명 서버에 폐기를 기록한 뒤: 서명 서버 4단계 FABRIC_IDENTITY_NOT_AVAILABLE 로 거부
package test

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/fabricca"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
)

const fabricCC = "sto-channel/sectoken"

// fabricAdmin 은 도구 컨테이너에서 InstAMSP 관리자 신원으로 peer 명령을 실행한다.
func fabricAdmin(t *testing.T, args ...string) string {
	t.Helper()
	org := "/w/generated/crypto-config/peerOrganizations/insta.example.com"
	base := []string{"compose", "-f", filepath.Join(repoRoot(t), "deploy", "docker-compose.yml"), "--profile", "fabric", "exec", "-T",
		"-e", "CORE_PEER_LOCALMSPID=InstAMSP", "-e", "CORE_PEER_MSPCONFIGPATH=" + org + "/users/Admin@insta.example.com/msp",
		"-e", "CORE_PEER_ADDRESS=peer0.insta.example.com:7051", "-e", "CORE_PEER_TLS_ENABLED=true",
		"-e", "CORE_PEER_TLS_ROOTCERT_FILE=" + org + "/peers/peer0.insta.example.com/tls/ca.crt", "fabric-tools"}
	out, err := exec.Command("docker", append(base, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("peer %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// fabricState 는 기관 A TRANSFER 의 Fabric ACTIVE 키와 그 신원 상태다.
func fabricState(t *testing.T, stoctl string) (active string, identity map[string]string) {
	t.Helper()
	for _, line := range strings.Split(stoctlRun(t, stoctl, "key", "list"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 5 && f[1] == "fabric-local" && f[2] == "inst-a" && f[3] == "TRANSFER" && f[4] == "ACTIVE" {
			active = f[0]
		}
	}
	identity = map[string]string{}
	for _, line := range strings.Split(stoctlRun(t, stoctl, "fabric", "list"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 5 {
			identity[f[0]] = f[4]
		}
	}
	return
}

var sec = []string{"--approver", "sec-02", "--approver", "sec-03"}

// freshFabricIdentity 는 유효한 신원이 있는 ACTIVE Fabric 키를 준비한다(앞선 실행이 폐기한 키면 새 키로 교체).
func freshFabricIdentity(t *testing.T, stoctl string) string {
	t.Helper()
	active, ids := fabricState(t, stoctl)
	gen := func(extra ...string) string {
		out := stoctlRun(t, stoctl, append(append([]string{"key", "generate", "--ledger", "fabric-local", "--institution", "inst-a", "--purpose", "TRANSFER",
			"--reason", "Fabric 시험 신원"}, extra...), sec...)...)
		var r struct {
			KeyID string `json:"key_id"`
		}
		if err := json.Unmarshal([]byte(out[strings.Index(out, "{"):]), &r); err != nil {
			t.Fatalf("key generate: %v\n%s", err, out)
		}
		return r.KeyID
	}
	enroll := func(k string) {
		stoctlRun(t, stoctl, append([]string{"fabric", "enroll", "--key", k}, sec...)...)
	}
	switch {
	case active == "":
		k := gen()
		enroll(k)
		return k
	case ids[active] == "ENROLLED":
		return active
	case ids[active] == "":
		enroll(active)
		return active
	default: // 앞선 실행이 폐기한 키: 새 키로 교체
		k := gen("--rotated-from", active)
		enroll(k)
		stoctlRun(t, stoctl, append([]string{"key", "retire", "--key", active, "--successor", k, "--reason", "폐기된 Fabric 신원 교체"}, sec...)...)
		return k
	}
}

// fabricRequest 는 승인된 FABRIC_TX 요청(계좌 등록)을 끝 상태까지 처리한다.
func fabricRequest(t *testing.T, stoctl, acct string) workflow.Request {
	t.Helper()
	out := stoctlRun(t, stoctl, "request", "draft", "--type", "FABRIC_TX", "--institution", "inst-a", "--purpose", "TRANSFER",
		"--contract", fabricCC, "--function", "RegisterAccount", "--args", acct, "--drafter", "apr-a-01")
	var r workflow.Request
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("기안: %v\n%s", err, out)
	}
	approveRequest(t, stoctl, r.RequestID, "apr-a-02", "apr-a-03")
	return waitStatusIn(t, r.RequestID, []workflow.Status{workflow.StatusConfirmed, workflow.StatusFailed}, 120*time.Second)
}

func signedKinds(t *testing.T, requestID string) map[string]string {
	t.Helper()
	rows, err := signerDB(t).Query(`SELECT kind, key_id FROM signatures WHERE request_id = ?`, requestID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, key string
		_ = rows.Scan(&k, &key)
		out[k] = key
	}
	return out
}

func randAcct() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "acct-" + hex.EncodeToString(b)
}

// caRevokeOnly 는 CA 폐기와 채널 설정 갱신만 한다(서명 서버 기록 전, 원장 쪽 효력 확인용). registrar 자격은 stoctl 이 만든 파일.
func caRevokeOnly(t *testing.T, stoctl, keyID string) {
	t.Helper()
	serial, aki := "", ""
	cl := mtlsClient(t, "stoctl", "localhost")
	resp, err := cl.Get(signerdURL + "/v1/fabric/identities")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Identities []struct {
			KeyID  string `json:"key_id"`
			Serial string `json:"serial"`
			AKI    string `json:"aki"`
		} `json:"identities"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&v)
	resp.Body.Close()
	for _, i := range v.Identities {
		if i.KeyID == keyID {
			serial, aki = i.Serial, i.AKI
		}
	}
	if serial == "" {
		t.Fatalf("키 %s 신원이 없다", keyID)
	}
	dir := filepath.Join(repoRoot(t), "deploy", "fabric", "generated")
	kb, err := os.ReadFile(filepath.Join(dir, "registrar", "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := os.ReadFile(filepath.Join(dir, "registrar", "cert.pem"))
	b, _ := pem.Decode(kb)
	rk, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"serial": serial, "aki": aki, "reason": "keycompromise", "gencrl": true})
	out, err := fabricca.New("http://127.0.0.1:7054").Do("POST", "/api/v1/revoke", body, fabricca.SoftwareToken(rk, cert))
	if err != nil {
		t.Fatal(err)
	}
	crl, err := fabricca.CRLFrom(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "crl"), 0o755); err != nil {
		t.Fatal(err)
	}
	rel := filepath.Join("deploy", "fabric", "generated", "crl", serial+".pem")
	if err := os.WriteFile(filepath.Join(repoRoot(t), rel), crl, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(repoRoot(t), "scripts", "fabric-crl-update.sh"), rel)
	cmd.Dir = repoRoot(t)
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("채널 설정 갱신: %v\n%s", err, o)
	}
}

func TestFabricIdentityLifecycle(t *testing.T) {
	stoctl := buildStoctl(t)

	// ① 신원
	k1 := freshFabricIdentity(t, stoctl)
	t.Logf("신원 키 %s", k1)

	// ② 승인된 요청 → 서명 3종 → 확정
	acct := randAcct()
	r := fabricRequest(t, stoctl, acct)
	if r.Status != workflow.StatusConfirmed {
		t.Fatalf("Fabric 요청: %s %s", r.Status, r.Error)
	}
	kinds := signedKinds(t, r.RequestID)
	if kinds["PROPOSAL"] != k1 || kinds["TRANSACTION"] != k1 || kinds["COMMIT"] != k1 || len(kinds) != 3 {
		t.Fatalf("서명 종류 %v", kinds)
	}
	var n int
	_ = signerDB(t).QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'SIGN_FABRIC' AND subject = ?`, r.RequestID).Scan(&n)
	if n != 3 {
		t.Fatalf("SIGN_FABRIC 감사 기록 %d건", n)
	}
	q := fabricAdmin(t, "peer", "chaincode", "query", "-C", "sto-channel", "-n", "sectoken", "-c", `{"Args":["GetAccount","`+acct+`"]}`)
	var rec struct {
		MSPID string `json:"msp_id"`
		Agent string `json:"agent"`
		TxID  string `json:"tx_id"`
	}
	if err := json.Unmarshal([]byte(q[strings.Index(q, "{"):]), &rec); err != nil || rec.MSPID != "InstAMSP" || rec.Agent == "" {
		t.Fatalf("원장 기록 %q %v", q, err)
	}
	t.Logf("② 확정: 요청 %s, 원장 기록 등록 신원 %s(%s), tx %s", r.RequestID, rec.Agent, rec.MSPID, rec.TxID)

	// ③ 재발급
	out := stoctlRun(t, stoctl, append([]string{"fabric", "reenroll", "--key", k1}, sec...)...)
	var re struct {
		NewKey string `json:"new_key"`
	}
	if err := json.Unmarshal([]byte(out[strings.Index(out, "{"):]), &re); err != nil || re.NewKey == "" {
		t.Fatalf("reenroll: %v\n%s", err, out)
	}
	k2 := re.NewKey
	r = fabricRequest(t, stoctl, randAcct())
	if r.Status != workflow.StatusConfirmed || signedKinds(t, r.RequestID)["PROPOSAL"] != k2 {
		t.Fatalf("재발급 뒤 요청: %s %s %v", r.Status, r.Error, signedKinds(t, r.RequestID))
	}
	t.Logf("③ 재발급: 새 키 %s 로 확정", k2)

	// ④ 이전 신원 폐기
	stoctlRun(t, stoctl, append([]string{"fabric", "revoke", "--key", k1, "--reason", "superseded"}, sec...)...)
	if _, ids := fabricState(t, stoctl); ids[k1] != "REVOKED" {
		t.Fatalf("이전 신원 상태 %s", ids[k1])
	}

	// ⑤ 원장 쪽 폐기: CA 폐기 + 채널 설정 갱신만(서명 서버 기록 전) → peer 가 거부
	caRevokeOnly(t, stoctl, k2)
	r = fabricRequest(t, stoctl, randAcct())
	if r.Status != workflow.StatusFailed || !strings.Contains(r.Error, workflow.CodeFabricEndorse) {
		t.Fatalf("원장 쪽 폐기 뒤 요청: %s %s", r.Status, r.Error)
	}
	t.Logf("⑤ 원장 거부: %s", r.Error)

	// ⑥ 서명 서버 기록(이미 CA 폐기됨 → 현재 CRL 로 이어 간다) → 서명 서버 4단계 거부
	stoctlRun(t, stoctl, append([]string{"fabric", "revoke", "--key", k2}, sec...)...)
	r = fabricRequest(t, stoctl, randAcct())
	if r.Status != workflow.StatusFailed || !strings.Contains(r.Error, "FABRIC_IDENTITY_NOT_AVAILABLE") {
		t.Fatalf("폐기 기록 뒤 요청: %s %s", r.Status, r.Error)
	}
	_ = signerDB(t).QueryRow(`SELECT COUNT(*) FROM signatures WHERE request_id = ?`, r.RequestID).Scan(&n)
	if n != 0 {
		t.Fatalf("거부된 요청의 서명 기록 %d", n)
	}
	t.Logf("⑥ 서명 서버 거부: %s", r.Error)
}
