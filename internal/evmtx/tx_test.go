package evmtx

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

var chainID = big.NewInt(20261124)

func TestUnsignedRoundTripAndAssemble(t *testing.T) {
	k, _ := crypto.GenerateKey()
	pub := signer.PublicKey(crypto.FromECDSAPub(&k.PublicKey))
	addr, _ := pub.Address()
	to := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	tx := NewUnsigned(chainID, 7, to, []byte{1, 2, 3}, 100000)
	raw, err := EncodeUnsigned(tx)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeUnsigned(raw)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Hash() != tx.Hash() || dec.Nonce() != 7 || *dec.To() != to {
		t.Fatal("왕복 인코딩 불일치")
	}
	h := SigningHash(dec)
	sig65, _ := crypto.Sign(h[:], k)
	r, s := new(big.Int).SetBytes(sig65[:32]), new(big.Int).SetBytes(sig65[32:64])
	full, err := signer.CompleteEVM(h, r, s, pub)
	if err != nil {
		t.Fatal(err)
	}
	signed, rawSigned, err := Assemble(dec, full, addr)
	if err != nil {
		t.Fatal(err)
	}
	from, _ := types.Sender(types.LatestSignerForChainID(chainID), signed)
	if from != addr || len(rawSigned) == 0 {
		t.Fatalf("송신자 %s != %s", from, addr)
	}
	// 서명된 tx 는 미서명 형식으로 받지 않는다.
	if _, err := DecodeUnsigned(rawSigned); err == nil {
		t.Fatal("서명된 tx 가 미서명 tx 로 해석됐다")
	}
	// 다른 주소를 기대하면 거부한다.
	if _, _, err := Assemble(dec, full, common.HexToAddress("0x01")); err == nil {
		t.Fatal("송신자 불일치가 허용됐다")
	}
}

func TestDecodeUnsignedRejects(t *testing.T) {
	to := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	legacy := types.NewTx(&types.LegacyTx{Nonce: 0, GasPrice: big.NewInt(0), Gas: 21000, To: &to, Value: big.NewInt(0)})
	lraw, _ := legacy.MarshalBinary()
	if _, err := DecodeUnsigned(lraw); err == nil {
		t.Fatal("레거시 tx 가 허용됐다")
	}
	raw, _ := EncodeUnsigned(NewUnsigned(chainID, 0, to, nil, 21000))
	if _, err := DecodeUnsigned(append(raw, 0x00)); err == nil {
		t.Fatal("뒤에 바이트가 붙은 tx 가 허용됐다")
	}
}
