//go:build integration && signtx_m1

// 종단 시험(M1 완료 기준): 서명 서버(signtx_m1 빌드)가 HSM 키로 서명한 트랜잭션이 Besu 에서 확정된다.
// scripts/it-signtx.sh 가 signerd 를 시험용 빌드로 바꿔 띄운 뒤 실행하고, 끝나면 기본 빌드로 되돌린다.
package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"database/sql"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/go-sql-driver/mysql"
	"github.com/oklog/ulid/v2"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/evmtx"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signsvc"
)

func keyAddress(t *testing.T, keyID string) common.Address {
	t.Helper()
	pw, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "secrets", "signer_app_password"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr, cfg.DBName = "signer_app", strings.TrimSpace(string(pw)), "tcp", "127.0.0.1:3306", "signer"
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var addr string
	if err := db.QueryRow("SELECT address FROM `keys` WHERE key_id = ? AND status = 'ACTIVE'", keyID).Scan(&addr); err != nil {
		t.Fatalf("레지스트리에서 %s 조회(make up 부트스트랩 필요): %v", keyID, err)
	}
	return common.HexToAddress(addr)
}

func postSign(t *testing.T, c *http.Client, req signsvc.Request) (int, []byte) {
	t.Helper()
	b, _ := json.Marshal(req)
	resp, err := c.Post(signerdURL+"/v1/sign/tx", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

func TestSignTxConfirmedOnBesu(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	addr := keyAddress(t, "key-inst-a-issue-1")
	eth, err := ethclient.DialContext(ctx, besuRPC)
	if err != nil {
		t.Fatal(err)
	}
	defer eth.Close()
	chainID, _ := eth.ChainID(ctx)
	nonce, err := eth.PendingNonceAt(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}

	in := &intent.Intent{
		RequestID: ulid.Make().String(), Type: intent.TypeTX, LedgerID: "besu-local", InstitutionID: "inst-a", KeyPurpose: "ISSUE",
		// M3 전이라 컨트랙트가 없다. 코드가 없는 주소로의 호출도 EVM 에서 성공(status 1)한다.
		Contract: common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3").Hex(), Function: "issue(address,uint256)",
		Args:      []string{common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").Hex(), "1000"},
		DrafterID: "apr-a-01", ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Format(intent.TimeLayout),
	}
	canon, _ := in.Canonical()
	h, _ := in.Hash()
	data, _ := in.Calldata()
	raw, _ := evmtx.EncodeUnsigned(evmtx.NewUnsigned(chainID, nonce, in.ContractAddress(), data, 100000))
	req := signsvc.Request{Intent: canon, IntentHash: hex.EncodeToString(h[:]), UnsignedTx: "0x" + hex.EncodeToString(raw)}

	// 업무 서버 인증서만 서명 API 를 호출할 수 있다.
	if code, body := postSign(t, mtlsClient(t, "stoctl", "localhost"), req); code != http.StatusForbidden {
		t.Fatalf("stoctl 인증서로 서명 API 호출: %d %s", code, body)
	}
	apid := mtlsClient(t, "apid", "localhost")
	code, body := postSign(t, apid, req)
	if code != 200 {
		t.Fatalf("서명 실패: %d %s", code, body)
	}
	var res signsvc.Response
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	if res.Address != addr.Hex() || res.KeyID != "key-inst-a-issue-1" {
		t.Fatalf("응답 키 불일치: %+v", res)
	}
	// 재호출은 같은 결과(다시 서명하지 않음)
	if code2, body2 := postSign(t, apid, req); code2 != 200 || !bytes.Equal(body2, body) {
		t.Fatalf("재호출 결과가 다르다: %d %s", code2, body2)
	}

	signed := new(types.Transaction)
	if err := signed.UnmarshalBinary(common.FromHex(res.SignedTx)); err != nil {
		t.Fatal(err)
	}
	if err := eth.SendTransaction(ctx, signed); err != nil {
		t.Fatalf("제출: %v", err)
	}
	var rcpt *types.Receipt
	for rcpt == nil {
		if rcpt, _ = eth.TransactionReceipt(ctx, signed.Hash()); rcpt == nil {
			select {
			case <-ctx.Done():
				t.Fatal("영수증 시간 초과")
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
	from, _ := types.Sender(types.LatestSignerForChainID(chainID), signed)
	if rcpt.Status != types.ReceiptStatusSuccessful || from != addr || rcpt.TxHash.Hex() != res.TxHash {
		t.Fatalf("status=%d from=%s", rcpt.Status, from)
	}
	t.Logf("HSM 서명 tx 확정: tx=%s block=%s from=%s key=%s", res.TxHash, rcpt.BlockNumber, addr.Hex(), res.KeyID)
	if rcpt.BlockNumber.Cmp(big.NewInt(0)) <= 0 {
		t.Fatal("블록 번호 없음")
	}

	// 승인된 intent 와 다른 calldata 는 HTTP 경로에서도 7단계로 거부된다.
	in2 := *in
	in2.RequestID = ulid.Make().String()
	canon2, _ := in2.Canonical()
	h2, _ := in2.Hash()
	alt := in2
	alt.Args = []string{in.Args[0], "999999"}
	altData, _ := alt.Calldata()
	raw2, _ := evmtx.EncodeUnsigned(evmtx.NewUnsigned(chainID, nonce+1, in.ContractAddress(), altData, 100000))
	code, body = postSign(t, apid, signsvc.Request{Intent: canon2, IntentHash: hex.EncodeToString(h2[:]), UnsignedTx: "0x" + hex.EncodeToString(raw2)})
	var rj signsvc.Rejection
	_ = json.Unmarshal(body, &rj)
	if code != http.StatusUnprocessableEntity || rj.Step != 7 || rj.Code != evmtx.CodeTxCalldataMismatch {
		t.Fatalf("calldata 바꿔치기: %d %s", code, body)
	}
}
