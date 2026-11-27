//go:build integration

package besu

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger/besu/sectoken"
)

// 시험용 키는 실행할 때마다 메모리에서 만든다(가스비 0 네트워크라 잔액이 필요 없다). HSM 키와 무관하다.
const rpcURL = "http://127.0.0.1:8545"

type chainFx struct {
	t     *testing.T
	a     *Adapter
	key   *ecdsa.PrivateKey
	from  common.Address
	nonce uint64
	id    *big.Int
}

func newChainFx(t *testing.T) *chainFx {
	t.Helper()
	ctx := context.Background()
	a, eth, err := Dial(ctx, rpcURL, Config{ChainID: 20261124, GasLimit: 300000, DeployGasLimit: 3000000})
	if err != nil {
		t.Fatalf("RPC 연결(make up 필요): %v", err)
	}
	t.Cleanup(eth.Close)
	id, err := a.ChainID(ctx)
	if err != nil {
		t.Fatalf("chainId(make up 필요): %v", err)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &chainFx{t: t, a: a, key: key, from: crypto.PubkeyToAddress(key.PublicKey), id: id}
}

func (f *chainFx) sign(nonce uint64, to *common.Address, data []byte, gas uint64) []byte {
	f.t.Helper()
	tx, err := types.SignNewTx(f.key, types.LatestSignerForChainID(f.id), &types.DynamicFeeTx{
		ChainID: f.id, Nonce: nonce, GasTipCap: big.NewInt(0), GasFeeCap: big.NewInt(0), Gas: gas, To: to, Value: big.NewInt(0), Data: data,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *chainFx) wait(h common.Hash) *ledger.Receipt {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		r, err := f.a.Receipt(ctx, h)
		if err == nil {
			return r
		}
		if !errors.Is(err, ledger.ErrReceiptNotFound) {
			f.t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			f.t.Fatalf("영수증 대기 시간 초과 %s", h.Hex())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// send 는 다음 nonce 로 tx 를 서명·제출하고 성공 영수증을 기다린다.
func (f *chainFx) send(to *common.Address, data []byte, gas uint64) *ledger.Receipt {
	f.t.Helper()
	raw := f.sign(f.nonce, to, data, gas)
	f.nonce++
	h, err := f.a.Submit(context.Background(), raw)
	if err != nil {
		f.t.Fatal(err)
	}
	r := f.wait(h)
	if !r.Succeeded() {
		f.t.Fatalf("tx 실패 status=%d", r.Status)
	}
	return r
}

func (f *chainFx) pack(method string, args ...any) []byte {
	f.t.Helper()
	data, err := f.a.abi.Pack(method, args...)
	if err != nil {
		f.t.Fatal(err)
	}
	return data
}

// deploy 는 종목 하나를 배포하고 시험 키에 발행·대체 역할과 기관(inst-a)을 준 뒤 계좌 하나를 등록한다.
func (f *chainFx) deploy(acct common.Address) (common.Address, uint64) {
	f.t.Helper()
	ctor, err := f.a.abi.Pack("", "IT Bond", "KRIT00000001", f.from)
	if err != nil {
		f.t.Fatal(err)
	}
	r := f.send(nil, append(common.FromHex(sectoken.SecurityTokenMetaData.Bin), ctor...), 3000000)
	if r.ContractAddress == nil {
		f.t.Fatal("배포 영수증에 컨트랙트 주소가 없다")
	}
	c := *r.ContractAddress
	issuer := crypto.Keccak256Hash([]byte("ISSUER_ROLE"))
	agent := crypto.Keccak256Hash([]byte("TRANSFER_AGENT_ROLE"))
	f.send(&c, f.pack("grantRole", issuer, f.from), 300000)
	f.send(&c, f.pack("grantRole", agent, f.from), 300000)
	f.send(&c, f.pack("setAgentInstitution", f.from, "inst-a"), 300000)
	f.send(&c, f.pack("registerAccount", acct, "inst-a"), 300000)
	return c, r.BlockNumber
}

// 같은 서명된 tx 를 여러 번 제출해도 체인에는 한 번만 반영된다(작업지시서 T3.2 완료 기준).
// 대기 중 재제출("Known transaction"), 확정 뒤 재제출("Nonce too low" + 영수증 있음), 동시 제출을 모두 성공으로 처리한다.
func TestSameSignedTxSubmittedTwiceAppliesOnce(t *testing.T) {
	f := newChainFx(t)
	ctx := context.Background()
	acct := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	c, deployBlock := f.deploy(acct)

	raw := f.sign(f.nonce, &c, f.pack("issue", acct, big.NewInt(1000)), 300000)
	f.nonce++
	h1, err := f.a.Submit(ctx, raw)
	if err != nil {
		t.Fatalf("첫 제출: %v", err)
	}
	h2, err := f.a.Submit(ctx, raw) // 대기 중 재제출
	if err != nil {
		t.Fatalf("대기 중 재제출: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("재제출 해시가 다르다 %s %s", h1.Hex(), h2.Hex())
	}
	r := f.wait(h1)
	if !r.Succeeded() {
		t.Fatalf("발행 실패 status=%d", r.Status)
	}
	h3, err := f.a.Submit(ctx, raw) // 확정 뒤 재제출
	if err != nil || h3 != h1 {
		t.Fatalf("확정 뒤 재제출: %s %v", h3.Hex(), err)
	}

	// 동시 제출: 새 tx 하나를 다섯 곳에서 동시에 보낸다.
	raw2 := f.sign(f.nonce, &c, f.pack("issue", acct, big.NewInt(7)), 300000)
	f.nonce++
	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = f.a.Submit(ctx, raw2)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("동시 제출 %d: %v", i, err)
		}
	}
	var tx2 types.Transaction
	_ = tx2.UnmarshalBinary(raw2)
	f.wait(tx2.Hash())
	if _, err := f.a.Submit(ctx, raw2); err != nil {
		t.Fatalf("동시 제출 tx 의 확정 뒤 재제출: %v", err)
	}

	bal, err := f.a.BalanceOf(ctx, c, acct)
	if err != nil {
		t.Fatal(err)
	}
	supply, err := f.a.TotalSupply(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if bal.Int64() != 1007 || supply.Int64() != 1007 {
		t.Fatalf("한 번씩만 반영돼야 한다: balance=%s totalSupply=%s (기대 1007)", bal, supply)
	}

	// 이벤트: Issued 가 정확히 두 건(1000, 7)
	head, err := f.a.HeadBlock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	evs, err := f.a.Events(ctx, c, deployBlock, head)
	if err != nil {
		t.Fatal(err)
	}
	var issued []string
	names := map[string]int{}
	for _, e := range evs {
		names[e.Name]++
		if e.Name == "Issued" {
			if e.Payload["account"] != acct.Hex() {
				t.Fatalf("Issued.account %q", e.Payload["account"])
			}
			issued = append(issued, e.Payload["amount"])
		}
		if e.BlockTime.IsZero() || e.TxHash == (common.Hash{}) {
			t.Fatalf("이벤트 메타데이터 누락: %+v", e)
		}
	}
	if len(issued) != 2 || issued[0] != "1000" || issued[1] != "7" {
		t.Fatalf("Issued 이벤트 %v (기대 [1000 7])", issued)
	}
	if names["RoleGranted"] != 3 || names["AccountRegistered"] != 1 || names["AgentInstitutionSet"] != 1 {
		t.Fatalf("이벤트 건수 %v", names)
	}
}

// 확정된 nonce 를 다른 내용으로 다시 쓰면 영구 실패(ErrNonceConflict)다. 성공으로 오인하지 않는다.
func TestNonceConflictIsPermanent(t *testing.T) {
	f := newChainFx(t)
	ctx := context.Background()
	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	f.send(&to, nil, 50000)
	other := f.sign(0, &to, []byte{1}, 50000)
	_, err := f.a.Submit(ctx, other)
	if !errors.Is(err, ledger.ErrNonceConflict) {
		t.Fatalf("다른 내용의 같은 nonce: %v (기대 ErrNonceConflict)", err)
	}
	// 형식이 깨진 원문은 노드에 보내기 전에 거부한다.
	if _, err := f.a.Submit(ctx, []byte{0x02, 0x01}); !errors.Is(err, ledger.ErrRejected) {
		t.Fatalf("깨진 원문: %v (기대 ErrRejected)", err)
	}
	// 다른 chainId 로 서명한 tx 는 노드가 거부한다.
	tx, _ := types.SignNewTx(f.key, types.LatestSignerForChainID(big.NewInt(1)), &types.DynamicFeeTx{ChainID: big.NewInt(1), Nonce: 1, GasTipCap: big.NewInt(0), GasFeeCap: big.NewInt(0), Gas: 50000, To: &to})
	raw, _ := tx.MarshalBinary()
	if _, err := f.a.Submit(ctx, raw); !errors.Is(err, ledger.ErrRejected) {
		t.Fatalf("다른 chainId: %v (기대 ErrRejected)", err)
	}
}

// revert 된 tx 는 영수증 status 0 이다(요청 FAILED 판정 근거, T3.4).
func TestRevertReceipt(t *testing.T) {
	f := newChainFx(t)
	acct := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	c, _ := f.deploy(acct)
	raw := f.sign(f.nonce, &c, f.pack("redeem", acct, big.NewInt(1)), 300000)
	f.nonce++
	h, err := f.a.Submit(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if r := f.wait(h); r.Succeeded() {
		t.Fatal("잔고 없는 말소가 성공했다")
	}
}
