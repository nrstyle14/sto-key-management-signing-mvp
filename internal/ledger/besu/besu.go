// Package besu 는 Hyperledger Besu 용 원장 어댑터다(설계서 10.3).
//
// 업무 서버만 쓴다. 서명 서버는 이 패키지를 import 하지 않는다(원장 노드에 접속하지 않음, make lint 가 검사).
//
// 제출 응답 처리(Besu 26.11.2 실측, scripts/probe-besu-resubmit):
//   - 같은 tx 를 대기 중에 다시 보내면 "Known transaction" → 성공으로 처리한다.
//   - 확정된 뒤 다시 보내면 "Nonce too low" → 같은 nonce 를 다른 내용으로 보낸 경우와 응답이 같으므로
//     이 tx 해시의 영수증이 있을 때만 성공, 없으면 ErrNonceConflict 다.
//   - 연결 실패 같은 전송 오류는 일시 오류로 그대로 돌려준다. 노드가 JSON-RPC 오류로 답한 나머지 경우는 ErrRejected 다.
package besu

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/evmtx"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger/besu/sectoken"
)

// Config 는 어댑터 설정이다.
type Config struct {
	ChainID uint64
	// GasLimit 은 함수 호출 tx 의 가스 한도, DeployGasLimit 은 배포 tx 의 가스 한도다(실측 근거는 설계서 10.3).
	GasLimit       uint64
	DeployGasLimit uint64
	// MaxGas 는 VerifyTx 의 가스 한도 상한이다(서명 서버의 signing.max_gas_limit 과 같은 의미).
	MaxGas uint64
}

// Adapter 는 Besu JSON-RPC 위의 ledger.Ledger 구현이다.
type Adapter struct {
	cfg Config
	evmtx.Builder
	eth *ethclient.Client
	abi *abi.ABI
}

var _ ledger.Ledger = (*Adapter)(nil)

// New 는 이미 연결된 클라이언트로 어댑터를 만든다.
func New(eth *ethclient.Client, cfg Config) (*Adapter, error) {
	if cfg.ChainID == 0 || cfg.GasLimit == 0 || cfg.DeployGasLimit == 0 {
		return nil, errors.New("besu: chain_id, gas_limit, deploy_gas_limit 이 필요하다")
	}
	if cfg.MaxGas == 0 {
		cfg.MaxGas = max(cfg.GasLimit, cfg.DeployGasLimit)
	}
	parsed, err := sectoken.SecurityTokenMetaData.GetAbi()
	if err != nil {
		return nil, fmt.Errorf("besu: ABI: %w", err)
	}
	return &Adapter{cfg: cfg, Builder: evmtx.Builder{ChainID: cfg.ChainID, GasLimit: cfg.GasLimit, DeployGasLimit: cfg.DeployGasLimit, Codes: evmtx.CodeSet(SecurityTokenCode())}, eth: eth, abi: parsed}, nil
}

// SecurityTokenCode 는 커밋된 바인딩의 SecurityToken 생성 바이트코드다(배포 intent 의 code_hash 기준).
func SecurityTokenCode() []byte { return common.FromHex(sectoken.SecurityTokenMetaData.Bin) }

// SecurityTokenCodeHash 는 SecurityTokenCode 의 keccak256 이다.
func SecurityTokenCodeHash() common.Hash { return crypto.Keccak256Hash(SecurityTokenCode()) }

// Dial 은 RPC 에 연결해 어댑터를 만든다.
func Dial(ctx context.Context, url string, cfg Config) (*Adapter, *ethclient.Client, error) {
	eth, err := ethclient.DialContext(ctx, url)
	if err != nil {
		return nil, nil, err
	}
	a, err := New(eth, cfg)
	if err != nil {
		eth.Close()
		return nil, nil, err
	}
	return a, eth, nil
}

// ChainID 는 노드의 chainId 다.
func (a *Adapter) ChainID(ctx context.Context) (*big.Int, error) { return a.eth.ChainID(ctx) }

// BuildTx 는 evmtx.Builder 의 것이다(가스비 0 인 type 2 미서명 tx, D-10).

// VerifyTx 는 서명 서버와 같은 규칙(evmtx.VerifyTx)으로 대조한다. 네트워크에 접근하지 않는다.
func (a *Adapter) VerifyTx(in *intent.Intent, raw ledger.UnsignedTx) error {
	tx, err := evmtx.DecodeUnsigned(raw)
	if err != nil {
		return err
	}
	return evmtx.VerifyTx(in, tx, a.cfg.ChainID, a.cfg.MaxGas)
}

// 실측한 Besu 응답 메시지(scripts/probe-besu-resubmit)
const (
	msgKnown        = "Known transaction"
	msgNonceTooLow  = "Nonce too low"
	receiptRecheck  = 3
	receiptInterval = 500 * time.Millisecond
)

// Submit 은 서명된 tx 원문을 eth_sendRawTransaction 으로 보낸다. 같은 tx 의 재제출은 성공이다.
func (a *Adapter) Submit(ctx context.Context, raw []byte) (ledger.TxHash, error) {
	var tx types.Transaction
	if err := tx.UnmarshalBinary(raw); err != nil {
		return ledger.TxHash{}, fmt.Errorf("%w: 서명된 tx 해석: %v", ledger.ErrRejected, err)
	}
	h := tx.Hash()
	var got common.Hash
	err := a.eth.Client().CallContext(ctx, &got, "eth_sendRawTransaction", hexutil.Encode(raw))
	if err == nil {
		if got != h {
			return h, fmt.Errorf("besu: 노드가 돌려준 tx 해시 %s, 기대 %s", got.Hex(), h.Hex())
		}
		return h, nil
	}
	var re rpc.Error
	if !errors.As(err, &re) {
		return h, fmt.Errorf("besu: 제출(일시 오류): %w", err) // 연결 실패·시간 초과
	}
	msg := strings.TrimSpace(re.Error())
	switch {
	case strings.EqualFold(msg, msgKnown):
		return h, nil
	case strings.EqualFold(msg, msgNonceTooLow):
		// 이 tx 가 이미 확정됐는지, 다른 tx 가 같은 nonce 를 썼는지 영수증으로 구분한다.
		for i := 0; i < receiptRecheck; i++ {
			if _, rerr := a.Receipt(ctx, h); rerr == nil {
				return h, nil
			} else if !errors.Is(rerr, ledger.ErrReceiptNotFound) {
				return h, fmt.Errorf("besu: 영수증 확인(일시 오류): %w", rerr)
			}
			select {
			case <-ctx.Done():
				return h, ctx.Err()
			case <-time.After(receiptInterval):
			}
		}
		return h, fmt.Errorf("%w: %s (nonce %d)", ledger.ErrNonceConflict, msg, tx.Nonce())
	default:
		return h, fmt.Errorf("%w: %s", ledger.ErrRejected, msg)
	}
}

// Receipt 는 영수증을 돌려준다. 없으면 ledger.ErrReceiptNotFound 다.
func (a *Adapter) Receipt(ctx context.Context, h ledger.TxHash) (*ledger.Receipt, error) {
	r, err := a.eth.TransactionReceipt(ctx, h)
	if errors.Is(err, ethereum.NotFound) {
		return nil, ledger.ErrReceiptNotFound
	}
	if err != nil {
		return nil, err
	}
	out := &ledger.Receipt{TxHash: r.TxHash, BlockNumber: r.BlockNumber.Uint64(), BlockHash: r.BlockHash, Status: r.Status, GasUsed: r.GasUsed}
	if r.ContractAddress != (common.Address{}) {
		addr := r.ContractAddress
		out.ContractAddress = &addr
	}
	for _, l := range r.Logs {
		out.Logs = append(out.Logs, *l)
	}
	return out, nil
}

// PendingNonce 는 eth_getTransactionCount(pending)다. 풀에서 빈자리 뒤에 있는 tx 는 세지 않는다(실측).
func (a *Adapter) PendingNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return a.eth.PendingNonceAt(ctx, addr)
}

// PendingNonceAt 은 workflow.Chain 인터페이스용 별칭이다.
func (a *Adapter) PendingNonceAt(ctx context.Context, addr common.Address) (uint64, error) {
	return a.PendingNonce(ctx, addr)
}

// HeadBlock 은 최신 블록 번호다.
func (a *Adapter) HeadBlock(ctx context.Context) (uint64, error) { return a.eth.BlockNumber(ctx) }

// Events 는 [from, to] 구간의 SecurityToken 이벤트를 블록·로그 순서로 디코딩한다.
// ABI 에 없는 로그는 오류다(종목 컨트랙트 주소만 넘긴다).
func (a *Adapter) Events(ctx context.Context, contract common.Address, from, to uint64) ([]ledger.Event, error) {
	if to < from {
		return nil, nil
	}
	logs, err := a.eth.FilterLogs(ctx, ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from), ToBlock: new(big.Int).SetUint64(to), Addresses: []common.Address{contract},
	})
	if err != nil {
		return nil, err
	}
	times := map[uint64]time.Time{}
	out := make([]ledger.Event, 0, len(logs))
	for _, l := range logs {
		if l.Removed {
			return nil, fmt.Errorf("besu: 제거된 로그(블록 %d)", l.BlockNumber) // QBFT 는 즉시 확정이라 생기면 안 된다
		}
		ev, err := DecodeLog(a.abi, l)
		if err != nil {
			return nil, err
		}
		bt, ok := times[l.BlockNumber]
		if !ok {
			hdr, err := a.eth.HeaderByHash(ctx, l.BlockHash)
			if err != nil {
				return nil, fmt.Errorf("besu: 블록 헤더 %d: %w", l.BlockNumber, err)
			}
			if hdr.Number.Uint64() != l.BlockNumber {
				return nil, fmt.Errorf("besu: 블록 해시와 번호가 맞지 않는다(%d)", l.BlockNumber)
			}
			bt = time.Unix(int64(hdr.Time), 0).UTC()
			times[l.BlockNumber] = bt
		}
		ev.BlockTime = bt
		out = append(out, ev)
	}
	return out, nil
}

// DecodeLog 는 SecurityToken 로그 하나를 이벤트로 디코딩한다(네트워크 접근 없음).
func DecodeLog(parsed *abi.ABI, l types.Log) (ledger.Event, error) {
	if len(l.Topics) == 0 {
		return ledger.Event{}, errors.New("besu: 토픽 없는 로그")
	}
	def, err := parsed.EventByID(l.Topics[0])
	if err != nil {
		return ledger.Event{}, fmt.Errorf("besu: 알 수 없는 이벤트 %s: %w", l.Topics[0].Hex(), err)
	}
	vals := map[string]any{}
	if len(l.Data) > 0 {
		if err := parsed.UnpackIntoMap(vals, def.Name, l.Data); err != nil {
			return ledger.Event{}, fmt.Errorf("besu: %s 데이터: %w", def.Name, err)
		}
	}
	var indexed abi.Arguments
	for _, arg := range def.Inputs {
		if arg.Indexed {
			indexed = append(indexed, arg)
		}
	}
	if err := abi.ParseTopicsIntoMap(vals, indexed, l.Topics[1:]); err != nil {
		return ledger.Event{}, fmt.Errorf("besu: %s 토픽: %w", def.Name, err)
	}
	payload := map[string]string{}
	for k, v := range vals {
		s, err := canonical(v)
		if err != nil {
			return ledger.Event{}, fmt.Errorf("besu: %s.%s: %w", def.Name, k, err)
		}
		payload[k] = s
	}
	return ledger.Event{
		BlockNumber: l.BlockNumber, BlockHash: l.BlockHash, TxHash: l.TxHash, LogIndex: l.Index,
		Name: def.Name, Payload: payload, Raw: l,
	}, nil
}

func canonical(v any) (string, error) {
	switch x := v.(type) {
	case common.Address:
		return x.Hex(), nil
	case *big.Int:
		return x.String(), nil
	case bool:
		if x {
			return "true", nil
		}
		return "false", nil
	case string:
		return x, nil
	case [32]byte:
		return "0x" + hex.EncodeToString(x[:]), nil
	case uint8:
		return fmt.Sprint(x), nil
	}
	return "", fmt.Errorf("지원하지 않는 값 형식 %T", v)
}

// BalanceOf 는 계좌의 온체인 잔고다.
func (a *Adapter) BalanceOf(ctx context.Context, contract, account common.Address) (*big.Int, error) {
	c, err := sectoken.NewSecurityTokenCaller(contract, a.eth)
	if err != nil {
		return nil, err
	}
	return c.BalanceOf(&bind.CallOpts{Context: ctx}, account)
}

// BalanceOfAt 은 블록 block 시점의 잔고다(대사, 설계서 11절). 연계장부가 반영한 블록과 같은 시점을 비교한다.
func (a *Adapter) BalanceOfAt(ctx context.Context, contract, account common.Address, block uint64) (*big.Int, error) {
	c, err := sectoken.NewSecurityTokenCaller(contract, a.eth)
	if err != nil {
		return nil, err
	}
	return c.BalanceOf(&bind.CallOpts{Context: ctx, BlockNumber: new(big.Int).SetUint64(block)}, account)
}

// TotalSupplyAt 은 블록 block 시점의 총 발행 수량이다.
func (a *Adapter) TotalSupplyAt(ctx context.Context, contract common.Address, block uint64) (*big.Int, error) {
	c, err := sectoken.NewSecurityTokenCaller(contract, a.eth)
	if err != nil {
		return nil, err
	}
	return c.TotalSupply(&bind.CallOpts{Context: ctx, BlockNumber: new(big.Int).SetUint64(block)})
}

// TotalSupply 는 총 발행 수량이다.
func (a *Adapter) TotalSupply(ctx context.Context, contract common.Address) (*big.Int, error) {
	c, err := sectoken.NewSecurityTokenCaller(contract, a.eth)
	if err != nil {
		return nil, err
	}
	return c.TotalSupply(&bind.CallOpts{Context: ctx})
}
