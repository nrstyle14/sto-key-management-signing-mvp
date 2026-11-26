// Command zerogas-tx 는 잔액 0인 계정으로 가스비 0 트랜잭션이 확정되는지 실측한다(T0.2).
//
// 실행할 때마다 메모리에서 새 secp256k1 키를 만들고(잔액 0), 레거시(가스 가격 0)와
// EIP-1559(최대 수수료 0) 트랜잭션을 각각 보내 영수증 상태를 확인한다.
// 키는 출력하거나 저장하지 않는다.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	rpc := flag.String("rpc", "http://127.0.0.1:8545", "JSON-RPC 주소(로컬만)")
	kinds := flag.String("types", "legacy,dynamic", "보낼 트랜잭션 유형 목록")
	flag.Parse()

	if err := run(*rpc, *kinds); err != nil {
		fmt.Fprintln(os.Stderr, "실패:", err)
		os.Exit(1)
	}
}

func run(rpc, kinds string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cli, err := ethclient.DialContext(ctx, rpc)
	if err != nil {
		return fmt.Errorf("RPC 연결: %w", err)
	}
	defer cli.Close()

	chainID, err := cli.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("chainId 조회: %w", err)
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("키 생성: %w", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	bal, err := cli.BalanceAt(ctx, from, nil)
	if err != nil {
		return fmt.Errorf("잔액 조회: %w", err)
	}
	fmt.Printf("chainId=%s 송신 주소=%s 잔액=%s\n", chainID, from.Hex(), bal)
	if bal.Sign() != 0 {
		return errors.New("새 계정의 잔액이 0이 아니다")
	}

	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	signer := types.LatestSignerForChainID(chainID)
	nonce := uint64(0)

	for _, kind := range splitComma(kinds) {
		var inner types.TxData
		switch kind {
		case "legacy":
			inner = &types.LegacyTx{Nonce: nonce, GasPrice: big.NewInt(0), Gas: 21000, To: &to, Value: big.NewInt(0)}
		case "dynamic":
			inner = &types.DynamicFeeTx{ChainID: chainID, Nonce: nonce, GasTipCap: big.NewInt(0), GasFeeCap: big.NewInt(0), Gas: 21000, To: &to, Value: big.NewInt(0)}
		default:
			return fmt.Errorf("알 수 없는 유형: %s", kind)
		}
		tx, err := types.SignNewTx(key, signer, inner)
		if err != nil {
			return fmt.Errorf("%s 서명: %w", kind, err)
		}
		if err := cli.SendTransaction(ctx, tx); err != nil {
			return fmt.Errorf("%s 제출: %w", kind, err)
		}
		rcpt, err := waitReceipt(ctx, cli, tx.Hash())
		if err != nil {
			return fmt.Errorf("%s 영수증: %w", kind, err)
		}
		fmt.Printf("%-7s type=%d tx=%s block=%s status=%d gasUsed=%d effectiveGasPrice=%s\n",
			kind, tx.Type(), tx.Hash().Hex(), rcpt.BlockNumber, rcpt.Status, rcpt.GasUsed, rcpt.EffectiveGasPrice)
		if rcpt.Status != types.ReceiptStatusSuccessful {
			return fmt.Errorf("%s 트랜잭션 실패(status=%d)", kind, rcpt.Status)
		}
		nonce++
	}
	return nil
}

func waitReceipt(ctx context.Context, cli *ethclient.Client, h common.Hash) (*types.Receipt, error) {
	for {
		r, err := cli.TransactionReceipt(ctx, h)
		if err == nil {
			return r, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("시간 초과(마지막 오류: %v): %w", err, ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}
