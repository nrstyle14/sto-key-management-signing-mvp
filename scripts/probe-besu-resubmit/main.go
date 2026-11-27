// Command probe-besu-resubmit 는 T3.2·T3.3 에서 기억에 의존하지 않으려고 Besu 동작을 실측한다.
//
//  1. 같은 서명된 tx 를 대기 중(pending)에 다시 보냈을 때와 확정 뒤 다시 보냈을 때의 응답
//  2. 확정된 nonce 를 다른 내용으로 다시 쓴 tx 의 응답
//  3. nonce 빈자리 뒤의 tx 가 풀에서 어떻게 되는지
//  4. SecurityToken 배포와 대표 함수의 가스 사용량(가스 한도 설정의 근거)
//
// 실행할 때마다 메모리에서 새 키를 만든다(잔액 0, 가스비 0 네트워크). 키는 출력하거나 저장하지 않는다.
package main

import (
	"context"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger/besu/sectoken"
)

func main() {
	rpc := flag.String("rpc", "http://127.0.0.1:8545", "JSON-RPC 주소(로컬만)")
	flag.Parse()
	if err := run(*rpc); err != nil {
		fmt.Fprintln(os.Stderr, "실패:", err)
		os.Exit(1)
	}
}

func run(rpc string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cli, err := ethclient.DialContext(ctx, rpc)
	if err != nil {
		return err
	}
	defer cli.Close()
	chainID, err := cli.ChainID(ctx)
	if err != nil {
		return err
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	signer := types.LatestSignerForChainID(chainID)
	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	mk := func(nonce uint64, data []byte) *types.Transaction {
		tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{ChainID: chainID, Nonce: nonce, GasTipCap: big.NewInt(0), GasFeeCap: big.NewInt(0), Gas: 50000, To: &to, Data: data})
		if err != nil {
			panic(err)
		}
		return tx
	}
	report := func(label string, err error) {
		if err == nil {
			fmt.Printf("%-34s 응답: 성공\n", label)
			return
		}
		fmt.Printf("%-34s 응답: 오류 %q\n", label, err.Error())
	}

	fmt.Printf("chainId=%s\n", chainID)
	tx0 := mk(0, nil)
	report("1a. 첫 제출(nonce 0)", cli.SendTransaction(ctx, tx0))
	report("1b. 같은 tx 즉시 재제출(대기 중)", cli.SendTransaction(ctx, tx0))
	r, err := wait(ctx, cli, tx0.Hash())
	if err != nil {
		return err
	}
	fmt.Printf("    확정: block=%s status=%d\n", r.BlockNumber, r.Status)
	report("1c. 같은 tx 확정 뒤 재제출", cli.SendTransaction(ctx, tx0))
	report("2.  확정된 nonce 0 을 다른 내용으로", cli.SendTransaction(ctx, mk(0, []byte{1})))

	tx2 := mk(2, nil)
	report("3a. nonce 2 제출(1 이 빈자리)", cli.SendTransaction(ctx, tx2))
	time.Sleep(5 * time.Second)
	_, err = cli.TransactionReceipt(ctx, tx2.Hash())
	fmt.Printf("    5초 뒤 nonce 2 영수증: %v\n", errOrOK(err))
	pending, _ := cli.PendingNonceAt(ctx, from)
	latest, _ := cli.NonceAt(ctx, from, nil)
	fmt.Printf("    pending nonce=%d latest nonce=%d\n", pending, latest)
	tx1 := mk(1, nil)
	report("3b. 빈자리 nonce 1 제출", cli.SendTransaction(ctx, tx1))
	if _, err := wait(ctx, cli, tx1.Hash()); err != nil {
		return err
	}
	r2, err := wait(ctx, cli, tx2.Hash())
	if err != nil {
		return err
	}
	fmt.Printf("    nonce 2 확정: block=%s status=%d\n", r2.BlockNumber, r2.Status)

	// 4. 배포와 함수 가스(가스비 0 이므로 잔액 없이 실행된다)
	auth, err := bind.NewKeyedTransactorWithChainID(key, chainID)
	if err != nil {
		return err
	}
	auth.GasTipCap, auth.GasFeeCap, auth.Nonce = big.NewInt(0), big.NewInt(0), big.NewInt(3)
	auth.GasLimit = 5_000_000
	addr, dtx, tok, err := sectoken.DeploySecurityToken(auth, cli, "Probe", "PROBE", from)
	if err != nil {
		return fmt.Errorf("배포: %w", err)
	}
	dr, err := wait(ctx, cli, dtx.Hash())
	if err != nil {
		return err
	}
	fmt.Printf("4.  배포: address=%s status=%d gasUsed=%d 코드 크기=%d바이트\n", addr.Hex(), dr.Status, dr.GasUsed, len(common.FromHex(sectoken.SecurityTokenMetaData.Bin)))
	n := uint64(4)
	call := func(label string, f func(*bind.TransactOpts) (*types.Transaction, error)) error {
		auth.Nonce = new(big.Int).SetUint64(n)
		n++
		tx, err := f(auth)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		r, err := wait(ctx, cli, tx.Hash())
		if err != nil {
			return err
		}
		fmt.Printf("    %-28s status=%d gasUsed=%d\n", label, r.Status, r.GasUsed)
		return nil
	}
	role, _ := tok.TRANSFERAGENTROLE(nil)
	irole, _ := tok.ISSUERROLE(nil)
	acct := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	acct2 := common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
	steps := []struct {
		l string
		f func(*bind.TransactOpts) (*types.Transaction, error)
	}{
		{"grantRole(TRANSFER_AGENT)", func(o *bind.TransactOpts) (*types.Transaction, error) { return tok.GrantRole(o, role, from) }},
		{"grantRole(ISSUER)", func(o *bind.TransactOpts) (*types.Transaction, error) { return tok.GrantRole(o, irole, from) }},
		{"setAgentInstitution", func(o *bind.TransactOpts) (*types.Transaction, error) {
			return tok.SetAgentInstitution(o, from, "inst-a")
		}},
		{"registerAccount", func(o *bind.TransactOpts) (*types.Transaction, error) { return tok.RegisterAccount(o, acct, "inst-a") }},
		{"registerAccount(2)", func(o *bind.TransactOpts) (*types.Transaction, error) { return tok.RegisterAccount(o, acct2, "inst-a") }},
		{"issue", func(o *bind.TransactOpts) (*types.Transaction, error) { return tok.Issue(o, acct, big.NewInt(1000)) }},
		{"transferByAgent", func(o *bind.TransactOpts) (*types.Transaction, error) {
			return tok.TransferByAgent(o, acct, acct2, big.NewInt(10))
		}},
	}
	for _, s := range steps {
		if err := call(s.l, s.f); err != nil {
			return err
		}
	}
	// 5. revert 된 tx 의 영수증(status 0)
	auth.Nonce = new(big.Int).SetUint64(n)
	auth.GasLimit = 200000
	rtx, err := tok.TransferByAgent(auth, acct2, acct, big.NewInt(1_000_000))
	if err != nil {
		return fmt.Errorf("revert 시험 제출: %w", err)
	}
	rr, err := wait(ctx, cli, rtx.Hash())
	if err != nil {
		return err
	}
	fmt.Printf("5.  잔고 초과 대체(revert): status=%d gasUsed=%d\n", rr.Status, rr.GasUsed)
	return nil
}

func errOrOK(err error) string {
	if err == nil {
		return "있음"
	}
	return "없음(" + err.Error() + ")"
}

func wait(ctx context.Context, cli *ethclient.Client, h common.Hash) (*types.Receipt, error) {
	for {
		r, err := cli.TransactionReceipt(ctx, h)
		if err == nil {
			return r, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("영수증 대기 %s: %w", h.Hex(), ctx.Err())
		case <-time.After(300 * time.Millisecond):
		}
	}
}
