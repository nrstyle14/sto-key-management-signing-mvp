//go:build integration

// 통합 테스트: HSM 키로 서명한 트랜잭션이 Besu 에서 확정되는지 확인한다(T1.3).
// make it 이 SoftHSM2 컨테이너(시험 전용, Besu 네트워크에 연결)에서 실행한다. 환경이 없으면 실패한다.
package hsm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/evmtx"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/hsm"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

func rnd(t *testing.T) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newSigner(t *testing.T) (*Signer, string) {
	t.Helper()
	lib := os.Getenv("STO_TEST_PKCS11_LIB")
	if lib == "" {
		lib = "/usr/lib/softhsm/libsofthsm2.so"
	}
	m, err := hsm.Open(lib)
	if err != nil {
		t.Fatalf("PKCS#11 라이브러리(SoftHSM2 컨테이너에서 make it 으로 실행): %v", err)
	}
	t.Cleanup(m.Close)
	label, pin := "it-"+rnd(t), rnd(t)
	if _, err := m.InitToken(label, rnd(t), pin); err != nil {
		t.Fatal(err)
	}
	tok, err := m.Login(label, pin, 2)
	if err != nil {
		t.Fatal(err)
	}
	return New([]*hsm.Token{tok}, func(context.Context, string) (string, error) { return label, nil }), label
}

func TestHSMSignedTxIsConfirmedOnBesu(t *testing.T) {
	rpc := os.Getenv("STO_TEST_RPC")
	if rpc == "" {
		t.Fatal("STO_TEST_RPC 가 없다(make it 으로 실행)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, label := newSigner(t)
	keyID := "it-issue-" + rnd(t)
	pub, err := s.Generate(ctx, signer.KeySpec{KeyID: keyID, TokenLabel: label, Purpose: signer.PurposeIssue})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := pub.Address()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.PublicKeyOf(ctx, label, keyID); err != nil || string(got) != string(pub) {
		t.Fatalf("공개키 조회 불일치: %v", err)
	}

	eth, err := ethclient.DialContext(ctx, rpc)
	if err != nil {
		t.Fatal(err)
	}
	defer eth.Close()
	chainID, err := eth.ChainID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := eth.PendingNonceAt(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}

	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	tx := evmtx.NewUnsigned(chainID, nonce, to, []byte("sto-kms T1.3"), 100000)
	h := evmtx.SigningHash(tx)
	// 여러 번 서명해 high-s 가 나오는 경우도 확정까지 가는지 본다(정규화 경로).
	var raw []byte
	var signed *types.Transaction
	for i := 0; i < 8; i++ {
		r, sv, err := s.SignDigest(ctx, keyID, h)
		if err != nil {
			t.Fatal(err)
		}
		_, high := signer.NormalizeLowS(sv)
		sig, err := signer.CompleteEVM(h, r, sv, pub)
		if err != nil {
			t.Fatal(err)
		}
		signed, raw, err = evmtx.Assemble(tx, sig, addr)
		if err != nil {
			t.Fatal(err)
		}
		if high {
			t.Logf("high-s 서명을 정규화해 사용(시도 %d)", i+1)
			break
		}
	}
	if err := eth.SendTransaction(ctx, signed); err != nil {
		t.Fatalf("제출 실패: %v", err)
	}
	var rcpt *types.Receipt
	for rcpt == nil {
		rcpt, _ = eth.TransactionReceipt(ctx, signed.Hash())
		if rcpt == nil {
			select {
			case <-ctx.Done():
				t.Fatal("영수증 시간 초과")
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
	if rcpt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("status=%d", rcpt.Status)
	}
	t.Logf("HSM 서명 tx 확정: tx=%s block=%s from=%s raw=%dB", signed.Hash().Hex(), rcpt.BlockNumber, addr.Hex(), len(raw))
	if rcpt.BlockNumber.Cmp(big.NewInt(0)) <= 0 {
		t.Fatal("블록 번호가 없다")
	}

	// 삭제 후에는 서명되지 않는다.
	if err := s.Destroy(ctx, keyID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SignDigest(ctx, keyID, h); err == nil {
		t.Fatal("삭제된 키로 서명됐다")
	}
}

func TestGenerateRejectsUnknownPurpose(t *testing.T) {
	s, label := newSigner(t)
	if _, err := s.Generate(context.Background(), signer.KeySpec{KeyID: "x", TokenLabel: label, Purpose: "BOGUS"}); err == nil {
		t.Fatal("알 수 없는 용도로 키가 만들어졌다")
	}
}
