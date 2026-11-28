package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"math/big"
)

// P-256 서명 보조(Fabric 신원 키, D-26).

// P256DER 은 (r, s)를 low-S 로 맞춰 ASN.1 DER 로 만든다(Fabric 은 high-S 를 거부한다).
func P256DER(r, s *big.Int) ([]byte, error) {
	n := elliptic.P256().Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return nil, errors.New("signer: 서명 값 범위")
	}
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		s = new(big.Int).Sub(n, s)
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

// P256Public 는 65바이트 비압축 공개키를 P-256 공개키로 바꾼다.
func P256Public(pub PublicKey) (*ecdsa.PublicKey, error) {
	if len(pub) != 65 || pub[0] != 4 {
		return nil, errors.New("signer: P-256 공개키 형식")
	}
	x, y := new(big.Int).SetBytes(pub[1:33]), new(big.Int).SetBytes(pub[33:])
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, errors.New("signer: P-256 곡선 위의 점이 아니다")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}
