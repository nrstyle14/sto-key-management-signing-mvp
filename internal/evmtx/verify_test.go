package evmtx

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
)

const maxGas = 500000

func testIntent(t *testing.T) *intent.Intent {
	t.Helper()
	in, err := intent.Parse([]byte(`{"request_id":"01JDQ8Z3V4N6P7R8S9T0W1X2Y3","type":"TX","ledger_id":"besu-local",
		"institution_id":"inst-a","key_purpose":"ISSUE","contract":"0x5FbDB2315678afecb367f032d93F642f64180aa3",
		"function":"issue(address,uint256)","args":["0x70997970C51812dc3A010C7d01b50e0d17dc79C8","1000"],
		"drafter_id":"apr-a-01","expires_at":"2026-12-01T09:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	return in
}

type txParts struct {
	chainID  *big.Int
	to       *common.Address
	value    *big.Int
	tip, fee *big.Int
	gas      uint64
	data     []byte
	access   types.AccessList
}

func goodParts(t *testing.T, in *intent.Intent) txParts {
	data, err := in.Calldata()
	if err != nil {
		t.Fatal(err)
	}
	to := in.ContractAddress()
	return txParts{chainID: big.NewInt(20261124), to: &to, value: big.NewInt(0), tip: big.NewInt(0), fee: big.NewInt(0), gas: 100000, data: data}
}

func (p txParts) tx() *types.Transaction {
	return types.NewTx(&types.DynamicFeeTx{ChainID: p.chainID, Nonce: 3, GasTipCap: p.tip, GasFeeCap: p.fee, Gas: p.gas,
		To: p.to, Value: p.value, Data: p.data, AccessList: p.access})
}

func code(err error) string {
	var ve *VerifyError
	if errors.As(err, &ve) {
		return ve.Code
	}
	return ""
}

func TestVerifyTxAccepts(t *testing.T) {
	in := testIntent(t)
	if err := VerifyTx(in, goodParts(t, in).tx(), 20261124, maxGas); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTxRejects(t *testing.T) {
	in := testIntent(t)
	other := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	good := goodParts(t, in)
	mut := func(f func(*txParts)) *types.Transaction {
		p := good
		p.data = append([]byte(nil), good.data...)
		f(&p)
		return p.tx()
	}

	// 다른 수신자·수량의 calldata
	otherAmount := *in
	otherAmount.Args = []string{in.Args[0], "1000000"}
	otherData, _ := otherAmount.Calldata()
	// 더러운 패딩: address 인자 상위 12바이트에 값을 넣는다(느슨한 디코더는 같은 주소로 읽는다)
	dirty := append([]byte(nil), good.data...)
	dirty[4] = 0xff

	cases := []struct {
		name string
		tx   *types.Transaction
		want string
	}{
		{"다른 chainId", mut(func(p *txParts) { p.chainID = big.NewInt(1) }), CodeTxChainIDMismatch},
		{"다른 to", mut(func(p *txParts) { p.to = &other }), CodeTxToMismatch},
		{"to 없음(컨트랙트 생성)", mut(func(p *txParts) { p.to = nil }), CodeTxToMismatch},
		{"0 이 아닌 value", mut(func(p *txParts) { p.value = big.NewInt(1) }), CodeTxValueNonzero},
		{"0 이 아닌 maxFeePerGas", mut(func(p *txParts) { p.fee = big.NewInt(1) }), CodeTxFeeNonzero},
		{"0 이 아닌 tip", mut(func(p *txParts) { p.tip = big.NewInt(1) }), CodeTxFeeNonzero},
		{"가스 한도 초과", mut(func(p *txParts) { p.gas = maxGas + 1 }), CodeTxGasLimitExceeded},
		{"가스 0", mut(func(p *txParts) { p.gas = 0 }), CodeTxGasLimitExceeded},
		{"access list", mut(func(p *txParts) { p.access = types.AccessList{{Address: other}} }), CodeTxAccessList},
		{"intent 와 다른 calldata(수량)", mut(func(p *txParts) { p.data = otherData }), CodeTxCalldataMismatch},
		{"다른 함수 선택자", mut(func(p *txParts) { p.data[0] ^= 0x01 }), CodeTxCalldataMismatch},
		{"calldata 뒤에 바이트 추가", mut(func(p *txParts) { p.data = append(p.data, 0x00) }), CodeTxCalldataMismatch},
		{"address 인자 더러운 패딩", mut(func(p *txParts) { p.data = dirty }), CodeTxCalldataMismatch},
		{"빈 calldata", mut(func(p *txParts) { p.data = nil }), CodeTxCalldataMismatch},
	}
	for _, c := range cases {
		if got := code(VerifyTx(in, c.tx, 20261124, maxGas)); got != c.want {
			t.Errorf("%s: 코드 %q, 기대 %q", c.name, got, c.want)
		}
	}
	legacy := types.NewTx(&types.LegacyTx{Nonce: 0, GasPrice: big.NewInt(0), Gas: 100000, To: good.to, Value: big.NewInt(0), Data: good.data})
	if got := code(VerifyTx(in, legacy, 20261124, maxGas)); got != CodeTxInvalid {
		t.Errorf("레거시 tx: %q", got)
	}
}
