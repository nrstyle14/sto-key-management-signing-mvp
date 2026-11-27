// Package ledger 는 분산원장 어댑터 인터페이스다(설계서 10.3).
//
// 구현은 원장별 하위 패키지(internal/ledger/besu)에 둔다. 서명 서버는 이 인터페이스의 구현을 쓰지 않는다.
// 서명 서버의 미서명 tx 대조는 네트워크에 접근하지 않는 internal/evmtx.VerifyTx 를 직접 호출하고,
// 구현의 VerifyTx 도 같은 함수를 부른다(같은 규칙을 한 곳에서만 정의).
package ledger

import (
	"context"
	"errors"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
)

// UnsignedTx 는 type 2 미서명 트랜잭션의 바이너리 인코딩이다(evmtx.EncodeUnsigned).
type UnsignedTx = []byte

// TxHash 는 서명된 트랜잭션 해시다.
type TxHash = common.Hash

// Receipt 는 확정된 트랜잭션의 영수증이다.
type Receipt struct {
	TxHash          TxHash
	BlockNumber     uint64
	BlockHash       common.Hash
	Status          uint64 // 1 성공, 0 revert
	GasUsed         uint64
	ContractAddress *common.Address // 배포 tx 일 때만
	Logs            []types.Log
}

// Succeeded 는 영수증 상태가 성공인지다.
func (r *Receipt) Succeeded() bool { return r.Status == types.ReceiptStatusSuccessful }

// Event 는 디코딩한 컨트랙트 이벤트 하나다(설계서 10.4).
type Event struct {
	BlockNumber uint64
	BlockHash   common.Hash
	BlockTime   time.Time
	TxHash      TxHash
	LogIndex    uint
	Name        string
	// Payload 는 이벤트 인자 이름 → 정규 문자열 값(주소는 EIP-55, 수량은 10진수, bool 은 "true"/"false").
	Payload map[string]string
	Raw     types.Log
}

// 오류
var (
	// ErrReceiptNotFound 는 아직 영수증이 없다는 뜻이다(대기 중이거나 풀에서 빠졌다).
	ErrReceiptNotFound = errors.New("ledger: 영수증 없음")
	// ErrNonceConflict 는 같은 nonce 가 다른 tx 로 이미 확정돼 이 tx 는 반영될 수 없다는 뜻이다(영구 실패).
	ErrNonceConflict = errors.New("ledger: nonce 가 다른 tx 로 이미 쓰였다")
	// ErrRejected 는 노드가 tx 를 형식·규칙 위반으로 거부했다는 뜻이다(영구 실패).
	ErrRejected = errors.New("ledger: 노드가 tx 를 거부했다")
)

// Ledger 는 원장 어댑터다(설계서 10.3).
type Ledger interface {
	ChainID(ctx context.Context) (*big.Int, error)
	// BuildTx 는 intent 를 미서명 트랜잭션으로 만든다.
	BuildTx(ctx context.Context, in *intent.Intent, from common.Address, nonce uint64) (UnsignedTx, error)
	// VerifyTx 는 미서명 tx 를 해석해 intent 와 일치하는지 확인한다. 네트워크에 접근하지 않는다.
	VerifyTx(in *intent.Intent, tx UnsignedTx) error
	// Submit 은 서명된 tx 를 제출한다. 같은 tx 를 다시 보내면 성공으로 처리한다(이미 알려진 tx, 이미 확정된 tx).
	// 일시 오류는 그대로, 영구 실패는 ErrNonceConflict·ErrRejected 로 감싸 돌려준다.
	Submit(ctx context.Context, raw []byte) (TxHash, error)
	// Receipt 는 영수증을 돌려준다. 아직 없으면 ErrReceiptNotFound 다.
	Receipt(ctx context.Context, h TxHash) (*Receipt, error)
	PendingNonce(ctx context.Context, addr common.Address) (uint64, error)
	// HeadBlock 은 최신 블록 번호다(이벤트 수신 구간 계산용).
	HeadBlock(ctx context.Context) (uint64, error)
	Events(ctx context.Context, contract common.Address, from, to uint64) ([]Event, error)
	BalanceOf(ctx context.Context, contract, account common.Address) (*big.Int, error)
	TotalSupply(ctx context.Context, contract common.Address) (*big.Int, error)
}
