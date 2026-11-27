package evmtx

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
)

// 미서명 tx 대조 거부 코드(설계서 5.3 의 7단계)
const (
	CodeTxInvalid          = "TX_INVALID"
	CodeTxChainIDMismatch  = "TX_CHAIN_ID_MISMATCH"
	CodeTxToMismatch       = "TX_TO_MISMATCH"
	CodeTxValueNonzero     = "TX_VALUE_NONZERO"
	CodeTxFeeNonzero       = "TX_FEE_NONZERO"
	CodeTxGasLimitExceeded = "TX_GAS_LIMIT_EXCEEDED"
	CodeTxAccessList       = "TX_ACCESS_LIST_NOT_EMPTY"
	CodeTxCalldataMismatch = "TX_CALLDATA_MISMATCH"
	CodeTxCodeHashMismatch = "TX_CODE_HASH_MISMATCH" // 배포 tx 의 생성 바이트코드 해시가 intent 의 code_hash 와 다르다(D-19)
)

// VerifyError 는 대조 실패다.
type VerifyError struct{ Code, Msg string }

func (e *VerifyError) Error() string { return e.Code + ": " + e.Msg }

func vErr(code, format string, a ...any) error {
	return &VerifyError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// VerifyTx 는 미서명 tx 가 승인 대상 intent 와 일치하는지 확인한다(설계서 5.3 의 7단계).
// 네트워크에 접근하지 않는 순수 함수다. chainID 는 서명 서버 설정값, maxGas 는 가스 한도 상한이다.
// calldata 는 intent 에서 다시 인코딩한 값과 바이트 단위로 같아야 한다.
func VerifyTx(in *intent.Intent, tx *types.Transaction, chainID uint64, maxGas uint64) error {
	if tx.Type() != types.DynamicFeeTxType {
		return vErr(CodeTxInvalid, "type %d (type 2 만 허용)", tx.Type())
	}
	if c := tx.ChainId(); c == nil || !c.IsUint64() || c.Uint64() != chainID {
		return vErr(CodeTxChainIDMismatch, "chainId %v, 기대 %d", tx.ChainId(), chainID)
	}
	deploy := in.Type == intent.TypeDeploy
	switch {
	case deploy && tx.To() != nil:
		return vErr(CodeTxToMismatch, "배포 intent 인데 to 가 %s 다", tx.To().Hex())
	case !deploy && tx.To() == nil:
		return vErr(CodeTxToMismatch, "to 가 없다(컨트랙트 생성)")
	case !deploy && *tx.To() != in.ContractAddress():
		return vErr(CodeTxToMismatch, "to %s, intent contract %s", tx.To().Hex(), in.Contract)
	}
	if tx.Value() == nil || tx.Value().Sign() != 0 {
		return vErr(CodeTxValueNonzero, "value %v", tx.Value())
	}
	zero := big.NewInt(0)
	if tx.GasTipCap().Cmp(zero) != 0 || tx.GasFeeCap().Cmp(zero) != 0 {
		return vErr(CodeTxFeeNonzero, "maxPriorityFeePerGas %v, maxFeePerGas %v (가스비 0, D-10)", tx.GasTipCap(), tx.GasFeeCap())
	}
	if tx.Gas() == 0 || tx.Gas() > maxGas {
		return vErr(CodeTxGasLimitExceeded, "gas %d, 상한 %d", tx.Gas(), maxGas)
	}
	if len(tx.AccessList()) != 0 {
		return vErr(CodeTxAccessList, "access list 항목 %d", len(tx.AccessList()))
	}
	if deploy {
		return verifyDeployData(in, tx.Data())
	}
	want, err := in.Calldata()
	if err != nil {
		return vErr(CodeTxInvalid, "intent calldata: %v", err)
	}
	if !bytes.Equal(tx.Data(), want) {
		return vErr(CodeTxCalldataMismatch, "calldata 가 intent 와 다르다")
	}
	return nil
}

// verifyDeployData 는 배포 tx 의 data 가 "생성 바이트코드 ‖ 생성자 인자"이고,
// 생성자 인자가 intent 에서 다시 인코딩한 값과 바이트 단위로 같으며, 바이트코드의 keccak256 이 code_hash 인지 확인한다.
func verifyDeployData(in *intent.Intent, data []byte) error {
	args, err := in.ConstructorArgs()
	if err != nil {
		return vErr(CodeTxInvalid, "intent 생성자 인자: %v", err)
	}
	if len(data) <= len(args) || !bytes.Equal(data[len(data)-len(args):], args) {
		return vErr(CodeTxCalldataMismatch, "배포 data 끝의 생성자 인자가 intent 와 다르다")
	}
	code := data[:len(data)-len(args)]
	if got := crypto.Keccak256Hash(code); got != in.CodeHashBytes() {
		return vErr(CodeTxCodeHashMismatch, "생성 바이트코드 keccak256 %s, intent code_hash %s", got.Hex(), in.CodeHash)
	}
	return nil
}
