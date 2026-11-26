// Package hsm 은 PKCS#11 HSM 을 쓰는 signer.Signer 구현이다(설계서 6.4).
package hsm

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/hsm"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

// Resolver 는 keyID 가 들어 있는 토큰 라벨을 돌려준다(키 레지스트리가 제공).
type Resolver func(ctx context.Context, keyID string) (tokenLabel string, err error)

// Signer 는 로그인된 토큰들 위의 HSM 서명기다.
type Signer struct {
	resolve Resolver

	mu     sync.RWMutex
	tokens map[string]*hsm.Token
}

var _ signer.Signer = (*Signer)(nil)

// New 는 서명기를 만든다. tokens 는 로그인된 토큰이고 resolve 는 keyID → 토큰 라벨 조회다.
func New(tokens []*hsm.Token, resolve Resolver) *Signer {
	m := make(map[string]*hsm.Token, len(tokens))
	for _, t := range tokens {
		m[t.Label()] = t
	}
	return &Signer{resolve: resolve, tokens: m}
}

func (s *Signer) token(label string) (*hsm.Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[label]
	if !ok {
		return nil, fmt.Errorf("signer/hsm: 로그인된 토큰이 아니다: %s", label)
	}
	return t, nil
}

func (s *Signer) tokenFor(ctx context.Context, keyID string) (*hsm.Token, error) {
	if s.resolve == nil {
		return nil, errors.New("signer/hsm: 키 조회기가 없다")
	}
	label, err := s.resolve(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return s.token(label)
}

// Generate 는 spec.TokenLabel 토큰에 키를 만든다. 추출 가능 여부는 용도의 부류로 정한다(D-3).
func (s *Signer) Generate(ctx context.Context, spec signer.KeySpec) (signer.PublicKey, error) {
	class, err := signer.ClassOf(spec.Purpose)
	if err != nil {
		return nil, err
	}
	t, err := s.token(spec.TokenLabel)
	if err != nil {
		return nil, err
	}
	pub, err := t.GenerateSecp256k1(ctx, spec.KeyID, hsm.KeyAttrs{Extractable: class.Extractable()})
	if err != nil {
		return nil, err
	}
	return signer.PublicKey(pub), nil
}

// SignDigest 는 keyID 로 다이제스트에 서명한다.
func (s *Signer) SignDigest(ctx context.Context, keyID string, digest [32]byte) (*big.Int, *big.Int, error) {
	t, err := s.tokenFor(ctx, keyID)
	if err != nil {
		return nil, nil, err
	}
	sig, err := t.SignDigest(ctx, keyID, digest[:])
	if err != nil {
		return nil, nil, err
	}
	return new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]), nil
}

// Destroy 는 keyID 의 키 객체를 삭제한다.
func (s *Signer) Destroy(ctx context.Context, keyID string) error {
	t, err := s.tokenFor(ctx, keyID)
	if err != nil {
		return err
	}
	return t.Destroy(ctx, keyID)
}

// PublicKeyOf 는 HSM 에 있는 keyID 공개키를 돌려주고, 개인키 객체도 있는지 확인한다(기동 점검용).
func (s *Signer) PublicKeyOf(ctx context.Context, tokenLabel, keyID string) (signer.PublicKey, error) {
	t, err := s.token(tokenLabel)
	if err != nil {
		return nil, err
	}
	if err := t.HasPrivateKey(ctx, keyID); err != nil {
		return nil, err
	}
	pub, err := t.PublicKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return signer.PublicKey(pub), nil
}

// DestroyIn 은 토큰을 직접 지정해 keyID 키를 삭제한다(레지스트리 등록 전 부트스트랩 롤백용).
func (s *Signer) DestroyIn(ctx context.Context, tokenLabel, keyID string) error {
	t, err := s.token(tokenLabel)
	if err != nil {
		return err
	}
	return t.Destroy(ctx, keyID)
}
