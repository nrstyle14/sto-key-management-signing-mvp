package signer

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	secpN     = new(big.Int).Set(crypto.S256().Params().N)
	secpHalfN = new(big.Int).Rsh(crypto.S256().Params().N, 1)
)

// ErrSignatureMismatch 는 서명에서 복구한 공개키가 기대한 키와 다를 때의 오류다.
var ErrSignatureMismatch = errors.New("signer: 서명이 기대한 공개키로 복구되지 않는다")

// NormalizeLowS 는 s > n/2 이면 n - s 를 돌려준다(EIP-2). 두 번째 값은 바꿨는지 여부다.
func NormalizeLowS(s *big.Int) (*big.Int, bool) {
	if s.Cmp(secpHalfN) > 0 {
		return new(big.Int).Sub(secpN, s), true
	}
	return new(big.Int).Set(s), false
}

// CompleteEVM 은 HSM 이 돌려준 (r, s)로 EVM 서명 65바이트(r || s || v, v∈{0,1})를 만든다(설계서 6.2).
//  1. r, s 가 [1, n-1] 범위인지 확인
//  2. low-s 정규화
//  3. 복구 식별자 0, 1 로 공개키를 복구해 pub(레지스트리의 공개키)와 같은 값을 고른다
func CompleteEVM(digest [32]byte, r, s *big.Int, pub PublicKey) ([65]byte, error) {
	var out [65]byte
	if r == nil || s == nil || r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(secpN) >= 0 || s.Cmp(secpN) >= 0 {
		return out, errors.New("signer: r 또는 s 가 [1, n-1] 범위 밖이다")
	}
	if len(pub) != 65 || pub[0] != 0x04 {
		return out, fmt.Errorf("signer: 공개키 형식이 65바이트 비압축이 아니다(길이 %d)", len(pub))
	}
	low, _ := NormalizeLowS(s)
	r.FillBytes(out[0:32])
	low.FillBytes(out[32:64])
	for v := byte(0); v <= 1; v++ {
		out[64] = v
		got, err := crypto.Ecrecover(digest[:], out[:])
		if err != nil {
			continue
		}
		if bytes.Equal(got, pub) {
			return out, nil
		}
	}
	return [65]byte{}, ErrSignatureMismatch
}

// Address 는 공개키의 EVM 주소다.
func (p PublicKey) Address() (common.Address, error) {
	k, err := crypto.UnmarshalPubkey(p)
	if err != nil {
		return common.Address{}, fmt.Errorf("signer: 공개키 해석: %w", err)
	}
	return crypto.PubkeyToAddress(*k), nil
}
