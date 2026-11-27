package evmtx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
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

// Builder 는 intent 를 미서명 tx 바이트로 만드는 순수 함수 모음이다(네트워크 접근 없음).
// 업무 서버의 원장 어댑터(internal/ledger/besu)가 BuildTx 로 쓴다(설계서 10.3, T1.5 의 임시 생성 코드를 옮김).
type Builder struct {
	ChainID        uint64
	GasLimit       uint64 // 함수 호출 tx
	DeployGasLimit uint64 // 배포 tx
	// Codes 는 배포할 수 있는 생성 바이트코드다(keccak256 → 바이트코드). 배포 intent 의 code_hash 로 찾는다.
	Codes map[common.Hash][]byte
}

// CodeSet 은 바이트코드 목록을 keccak256 으로 찾는 맵으로 만든다.
func CodeSet(codes ...[]byte) map[common.Hash][]byte {
	m := map[common.Hash][]byte{}
	for _, c := range codes {
		m[crypto.Keccak256Hash(c)] = c
	}
	return m
}

// BuildTx 는 intent 를 가스비 0 인 type 2 미서명 tx 인코딩으로 만든다(D-10). from 은 쓰지 않는다(서명 키가 정한다).
// DEPLOY 는 to 가 없고 data 가 생성 바이트코드 ‖ 생성자 인자다(D-19).
func (b Builder) BuildTx(_ context.Context, in *intent.Intent, _ common.Address, nonce uint64) ([]byte, error) {
	if b.ChainID == 0 || b.GasLimit == 0 {
		return nil, errors.New("evmtx: chain_id, gas_limit 이 필요하다")
	}
	chainID := new(big.Int).SetUint64(b.ChainID)
	if in.Type == intent.TypeDeploy {
		code, ok := b.Codes[in.CodeHashBytes()]
		if !ok {
			return nil, fmt.Errorf("evmtx: code_hash %s 의 바이트코드를 모른다", in.CodeHash)
		}
		args, err := in.ConstructorArgs()
		if err != nil {
			return nil, err
		}
		if b.DeployGasLimit == 0 {
			return nil, errors.New("evmtx: deploy_gas_limit 이 필요하다")
		}
		data := append(append([]byte(nil), code...), args...)
		return EncodeUnsigned(types.NewTx(&types.DynamicFeeTx{ChainID: chainID, Nonce: nonce, GasTipCap: big.NewInt(0), GasFeeCap: big.NewInt(0),
			Gas: b.DeployGasLimit, To: nil, Value: big.NewInt(0), Data: data}))
	}
	data, err := in.Calldata()
	if err != nil {
		return nil, err
	}
	return EncodeUnsigned(NewUnsigned(chainID, nonce, in.ContractAddress(), data, b.GasLimit))
}

// GasFor 는 intent 유형에 맞는 가스 한도다(사전 정책 검사용).
func (b Builder) GasFor(in *intent.Intent) uint64 {
	if in.Type == intent.TypeDeploy {
		return b.DeployGasLimit
	}
	return b.GasLimit
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
