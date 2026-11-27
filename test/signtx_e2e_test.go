//go:build integration

// 종단 시험: 기안자·승인자 서명이 붙은 요청을 서명 서버가 1~9단계로 검사해 HSM 키로 서명하고,
// 그 트랜잭션이 Besu 에서 확정된다(M1 완료 기준 + T2.4). 업무 서버 시험과 nonce 가 섞이지 않도록
// 기관 B 의 TRANSFER 키를 쓴다.
package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/oklog/ulid/v2"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/evmtx"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/policy"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signsvc"
)

func keyAddress(t *testing.T, keyID string) common.Address {
	t.Helper()
	var addr string
	if err := signerDB(t).QueryRow("SELECT address FROM `keys` WHERE key_id = ? AND status = 'ACTIVE'", keyID).Scan(&addr); err != nil {
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

func transferIntent(t *testing.T) *intent.Intent {
	in := &intent.Intent{
		RequestID: ulid.Make().String(), Type: intent.TypeTX, LedgerID: "besu-local", InstitutionID: "inst-b", KeyPurpose: "TRANSFER",
		// M3 전이라 컨트랙트가 없다. 코드가 없는 주소로의 호출도 EVM 에서 성공(status 1)한다.
		Contract: common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3").Hex(), Function: "transferByAgent(address,address,uint256)",
		Args: []string{common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC").Hex(),
			common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").Hex(), "10"},
		DrafterID: "apr-b-01", ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Format(intent.TimeLayout),
	}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	return in
}

func buildReq(t *testing.T, in *intent.Intent, chainID int64, nonce uint64, approvals ...approval.Approval) signsvc.Request {
	canon, _ := in.Canonical()
	data, _ := in.Calldata()
	raw, _ := evmtx.EncodeUnsigned(evmtx.NewUnsigned(bigInt(chainID), nonce, in.ContractAddress(), data, 100000))
	h, _ := in.Hash()
	return signsvc.Request{Intent: canon, IntentHash: hex.EncodeToString(h[:]), Approvals: approvals, UnsignedTx: "0x" + hex.EncodeToString(raw)}
}

func TestSignTxWithApprovalsConfirmedOnBesu(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	addr := keyAddress(t, "key-inst-b-transfer-1")
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
	in := transferIntent(t)
	h, _ := in.Hash()
	req := buildReq(t, in, chainID.Int64(), nonce,
		approverSign(t, "apr-b-02", h, approval.Approve), approverSign(t, "apr-b-03", h, approval.Approve))

	// 업무 서버 인증서만 서명 API 를 호출할 수 있다. 이 거부(1단계)도 감사로그에 남는다.
	if code, body := postSign(t, mtlsClient(t, "stoctl", "localhost"), req); code != http.StatusForbidden {
		t.Fatalf("stoctl 인증서로 서명 API 호출: %d %s", code, body)
	}
	var rejected int
	if err := signerDB(t).QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'SIGN_REJECTED' AND subject = ? AND payload_json LIKE ?",
		in.RequestID, `%"code":"SIGN_CALLER_NOT_ALLOWED"%`).Scan(&rejected); err != nil || rejected != 1 {
		t.Fatalf("1단계 거부 감사 기록 %d 건 (%v)", rejected, err)
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
	if res.Address != addr.Hex() || res.KeyID != "key-inst-b-transfer-1" {
		t.Fatalf("응답 키 불일치: %+v", res)
	}
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
	if rcpt.Status != types.ReceiptStatusSuccessful || from != addr {
		t.Fatalf("status=%d from=%s", rcpt.Status, from)
	}
	t.Logf("승인 2건 + HSM 서명 tx 확정: tx=%s block=%s from=%s", res.TxHash, rcpt.BlockNumber, addr.Hex())

	// 서명 기록과 감사 기록이 함께 남았다.
	var n int
	if err := signerDB(t).QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'SIGN_TX' AND subject = ?", in.RequestID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("SIGN_TX 감사 기록 %d 건 (%v)", n, err)
	}
}

// 승인이 부족한 요청은 HTTP 경로에서도 6단계로 거부되고, 거부가 감사로그에 남는다.
func TestSignTxRejectionIsAudited(t *testing.T) {
	in := transferIntent(t)
	h, _ := in.Hash()
	req := buildReq(t, in, 20261124, 0, approverSign(t, "apr-b-02", h, approval.Approve))
	code, body := postSign(t, mtlsClient(t, "apid", "localhost"), req)
	var rj signsvc.Rejection
	_ = json.Unmarshal(body, &rj)
	if code != http.StatusUnprocessableEntity || rj.Step != 6 || rj.Code != policy.CodeApprovalInsufficient {
		t.Fatalf("승인 1건 요청: %d %s", code, body)
	}
	var n int
	if err := signerDB(t).QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'SIGN_REJECTED' AND subject = ? AND payload_json LIKE ?",
		in.RequestID, `%"code":"APPROVAL_INSUFFICIENT"%`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("거부 감사 기록 %d 건 (%v)", n, err)
	}
}
