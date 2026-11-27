package evmtx

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
)

var testCode = []byte{0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15} // 임의의 생성 바이트코드

func deployIntent(t *testing.T, codeHash common.Hash) *intent.Intent {
	t.Helper()
	m := map[string]any{"request_id": "01JDQ8Z3V4N6P7R8S9T0W1X2Y3", "type": "DEPLOY", "ledger_id": "besu-local",
		"institution_id": "platform", "key_purpose": "CONTRACT_ADMIN", "contract": intent.ZeroAddress,
		"function": "constructor(string,string,address)", "args": []string{"Demo", "KRDEMO000001", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"},
		"drafter_id": "sec-01", "expires_at": "2026-12-01T09:00:00Z", "code_hash": codeHash.Hex()}
	raw, _ := json.Marshal(m)
	in, err := intent.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// 배포 tx 대조(5.3 의 7단계, D-19): to 없음, data = 바이트코드 ‖ 생성자 인자, keccak256(바이트코드) = code_hash.
func TestVerifyDeploy(t *testing.T) {
	in := deployIntent(t, crypto.Keccak256Hash(testCode))
	b := Builder{ChainID: 20261124, GasLimit: 300000, DeployGasLimit: 400000, Codes: CodeSet(testCode)}
	raw, err := b.BuildTx(context.Background(), in, common.Address{}, 4)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := DecodeUnsigned(raw)
	if err != nil {
		t.Fatal(err)
	}
	if tx.To() != nil || tx.Gas() != 400000 || !bytes.HasPrefix(tx.Data(), testCode) {
		t.Fatalf("배포 tx 형식: to=%v gas=%d", tx.To(), tx.Gas())
	}
	if err := VerifyTx(in, tx, 20261124, 500000); err != nil {
		t.Fatalf("정상 배포 tx 거부: %v", err)
	}
	args, _ := in.ConstructorArgs()
	to := common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")
	other := append([]byte{}, testCode...)
	other[0] ^= 1
	otherArgs := deployIntent(t, crypto.Keccak256Hash(testCode))
	otherArgs.Args[0] = "Other"
	wrongArgs, _ := otherArgs.ConstructorArgs()
	cases := []struct {
		name string
		p    txParts
		want string
	}{
		{"to 있음", txParts{to: &to, data: append(append([]byte{}, testCode...), args...)}, CodeTxToMismatch},
		{"바이트코드 바꿔치기", txParts{data: append(other, args...)}, CodeTxCodeHashMismatch},
		{"생성자 인자 바꿔치기", txParts{data: append(append([]byte{}, testCode...), wrongArgs...)}, CodeTxCalldataMismatch},
		{"인자 뒤에 바이트 추가", txParts{data: append(append(append([]byte{}, testCode...), args...), 0)}, CodeTxCalldataMismatch},
		{"바이트코드 없음", txParts{data: args}, CodeTxCalldataMismatch},
		{"바이트코드 앞에 바이트 추가", txParts{data: append(append([]byte{0}, testCode...), args...)}, CodeTxCodeHashMismatch},
	}
	for _, c := range cases {
		p := c.p
		p.chainID, p.value, p.tip, p.fee, p.gas = tx.ChainId(), tx.Value(), tx.GasTipCap(), tx.GasFeeCap(), 400000
		if got := code(VerifyTx(in, p.tx(), 20261124, 500000)); got != c.want {
			t.Errorf("%s: %q (기대 %s)", c.name, got, c.want)
		}
	}
	// 배포가 아닌 intent 에 to 없는 tx
	call := testIntent(t)
	p := goodParts(t, call)
	p.to = nil
	if got := code(VerifyTx(call, p.tx(), 20261124, 500000)); got != CodeTxToMismatch {
		t.Errorf("TX intent 에 배포 tx: %q", got)
	}
	// 모르는 바이트코드는 만들지 않는다.
	if _, err := b.BuildTx(context.Background(), deployIntent(t, common.HexToHash("0x01")), common.Address{}, 0); err == nil {
		t.Error("모르는 code_hash 로 배포 tx 를 만들었다")
	}
}
