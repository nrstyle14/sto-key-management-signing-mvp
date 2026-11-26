package evmtx

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// 확정한 트랜잭션 유형은 EIP-1559(type 2)이고 수수료 필드는 0이다(D-10).

// NewUnsigned 는 가스비 0 인 type 2 미서명 트랜잭션을 만든다.
func NewUnsigned(chainID *big.Int, nonce uint64, to common.Address, data []byte, gas uint64) *types.Transaction {
	return types.NewTx(&types.DynamicFeeTx{
		ChainID:   new(big.Int).Set(chainID),
		Nonce:     nonce,
		GasTipCap: big.NewInt(0),
		GasFeeCap: big.NewInt(0),
		Gas:       gas,
		To:        &to,
		Value:     big.NewInt(0),
		Data:      append([]byte(nil), data...),
	})
}

// EncodeUnsigned 는 미서명 트랜잭션의 전송 형식이다: 서명 필드(yParity, r, s)가 0 인 type 2 바이너리 인코딩.
func EncodeUnsigned(tx *types.Transaction) ([]byte, error) {
	if tx.Type() != types.DynamicFeeTxType {
		return nil, fmt.Errorf("evmtx: type %d 는 지원하지 않는다(type 2 만)", tx.Type())
	}
	if !isUnsigned(tx) {
		return nil, errors.New("evmtx: 이미 서명된 트랜잭션이다")
	}
	return tx.MarshalBinary()
}

// DecodeUnsigned 는 EncodeUnsigned 형식을 해석한다. type 2 가 아니거나 서명 필드가 0 이 아니면 거부한다.
// 다시 인코딩한 바이트가 입력과 같아야 한다(뒤에 붙은 바이트·비정규 인코딩 거부).
func DecodeUnsigned(b []byte) (*types.Transaction, error) {
	if len(b) == 0 || b[0] != types.DynamicFeeTxType {
		return nil, errors.New("evmtx: type 2 트랜잭션이 아니다")
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(b); err != nil {
		return nil, fmt.Errorf("evmtx: 미서명 트랜잭션 해석: %w", err)
	}
	if !isUnsigned(tx) {
		return nil, errors.New("evmtx: 서명 필드가 0 이 아니다")
	}
	re, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(re, b) {
		return nil, errors.New("evmtx: 정규 인코딩이 아니다")
	}
	return tx, nil
}

func isUnsigned(tx *types.Transaction) bool {
	v, r, s := tx.RawSignatureValues()
	return v.Sign() == 0 && r.Sign() == 0 && s.Sign() == 0
}

// SigningHash 는 서명할 32바이트 해시다.
func SigningHash(tx *types.Transaction) [32]byte {
	return types.LatestSignerForChainID(tx.ChainId()).Hash(tx)
}

// UnsignedHash 는 미서명 전송 형식 바이트의 keccak256 이다(같은 요청의 재호출 비교용).
func UnsignedHash(raw []byte) [32]byte {
	return crypto.Keccak256Hash(raw)
}

// Assemble 은 65바이트 서명(r||s||v)을 붙인 트랜잭션을 만들고, 복구한 송신자가 want 인지 확인한다.
func Assemble(tx *types.Transaction, sig [65]byte, want common.Address) (*types.Transaction, []byte, error) {
	signer := types.LatestSignerForChainID(tx.ChainId())
	signed, err := tx.WithSignature(signer, sig[:])
	if err != nil {
		return nil, nil, fmt.Errorf("evmtx: 서명 결합: %w", err)
	}
	from, err := types.Sender(signer, signed)
	if err != nil {
		return nil, nil, fmt.Errorf("evmtx: 송신자 복구: %w", err)
	}
	if from != want {
		return nil, nil, fmt.Errorf("evmtx: 송신자 %s 가 키 주소 %s 와 다르다", from.Hex(), want.Hex())
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return signed, raw, nil
}
