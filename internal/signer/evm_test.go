package signer

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func newKey(t *testing.T) ([]byte, func([32]byte) []byte) {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return crypto.FromECDSAPub(&k.PublicKey), func(d [32]byte) []byte {
		sig, err := crypto.Sign(d[:], k)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
}

func digest(t *testing.T) [32]byte {
	var d [32]byte
	if _, err := rand.Read(d[:]); err != nil {
		t.Fatal(err)
	}
	return d
}

func rs(sig []byte) (*big.Int, *big.Int) {
	return new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64])
}

func TestCompleteEVMLowS(t *testing.T) {
	pub, sign := newKey(t)
	for i := 0; i < 50; i++ {
		d := digest(t)
		want := sign(d) // go-ethereum 은 low-s 서명을 만든다
		r, s := rs(want)
		got, err := CompleteEVM(d, r, s, pub)
		if err != nil {
			t.Fatal(err)
		}
		if string(got[:]) != string(want) {
			t.Fatalf("서명 불일치\n got=%x\nwant=%x", got, want)
		}
		if !crypto.VerifySignature(pub, d[:], got[:64]) {
			t.Fatal("go-ethereum 검증 실패")
		}
	}
}

// HSM 은 s 를 정규화하지 않아 약 절반이 high-s 다(실측). (r, n-s)는 v 가 뒤집힌 같은 서명이다.
func TestCompleteEVMHighSIsNormalized(t *testing.T) {
	pub, sign := newKey(t)
	for i := 0; i < 50; i++ {
		d := digest(t)
		want := sign(d)
		r, s := rs(want)
		highS := new(big.Int).Sub(secpN, s)
		if highS.Cmp(secpHalfN) <= 0 {
			t.Fatal("시험 전제: n-s 는 high-s 여야 한다")
		}
		norm, changed := NormalizeLowS(highS)
		if !changed || norm.Cmp(s) != 0 {
			t.Fatalf("정규화 결과가 원래 s 가 아니다")
		}
		// high-s 형태는 복구 식별자가 뒤집혀야 같은 공개키로 복구된다(정규화 분기가 실제로 필요함을 확인).
		raw := make([]byte, 65)
		r.FillBytes(raw[:32])
		highS.FillBytes(raw[32:64])
		raw[64] = want[64] ^ 1
		if got, err := crypto.Ecrecover(d[:], raw); err != nil || string(got) != string(pub) {
			t.Fatalf("high-s(v 뒤집음) 복구 실패: %v", err)
		}
		got, err := CompleteEVM(d, r, highS, pub)
		if err != nil {
			t.Fatal(err)
		}
		if string(got[:]) != string(want) {
			t.Fatalf("high-s 입력의 완성 서명이 low-s 정답과 다르다\n got=%x\nwant=%x", got, want)
		}
		if !crypto.VerifySignature(pub, d[:], got[:64]) {
			t.Fatal("go-ethereum 검증 실패(high-s 가 남았을 수 있다)")
		}
	}
}

func TestCompleteEVMRejectsOutOfRange(t *testing.T) {
	pub, sign := newKey(t)
	d := digest(t)
	r, s := rs(sign(d))
	zero, n := big.NewInt(0), new(big.Int).Set(secpN)
	cases := map[string][2]*big.Int{
		"r=0": {zero, s}, "s=0": {r, zero}, "r=n": {n, s}, "s=n": {r, n}, "nil": {nil, s},
	}
	for name, c := range cases {
		if _, err := CompleteEVM(d, c[0], c[1], pub); err == nil {
			t.Errorf("%s: 범위 밖 값이 허용됐다", name)
		}
	}
}

func TestCompleteEVMRejectsOtherKey(t *testing.T) {
	_, sign := newKey(t)
	other, _ := newKey(t)
	d := digest(t)
	r, s := rs(sign(d))
	if _, err := CompleteEVM(d, r, s, other); err != ErrSignatureMismatch {
		t.Fatalf("다른 키의 공개키로 완성됐다: %v", err)
	}
}

func TestShortRSArePadded(t *testing.T) {
	// r 이 작아 31바이트 이하로 표현돼도 32바이트로 채워야 한다.
	pub, _ := newKey(t)
	var d [32]byte
	if _, err := CompleteEVM(d, big.NewInt(1), big.NewInt(1), pub); err != ErrSignatureMismatch {
		t.Fatalf("작은 r, s 에서 패딩·복구 경로가 동작하지 않았다: %v", err)
	}
}

func TestClassOf(t *testing.T) {
	cases := map[Purpose]Class{
		PurposeIssue: ClassOperational, PurposeTransfer: ClassOperational,
		PurposeContractAdmin: ClassRoot, PurposeEmergency: ClassRoot, PurposeAudit: ClassAudit,
	}
	for p, want := range cases {
		got, err := ClassOf(p)
		if err != nil || got != want {
			t.Fatalf("%s: %s %v", p, got, err)
		}
		if got.Extractable() != (want == ClassRoot) {
			t.Fatalf("%s: 추출 가능 여부가 D-3 과 다르다", p)
		}
	}
	if _, err := ClassOf("UNKNOWN"); err == nil {
		t.Fatal("알 수 없는 용도가 허용됐다")
	}
}
