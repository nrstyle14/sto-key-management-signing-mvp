// Package router 는 키별 서명기 선택이다(설계서 6.4, D-25). 레지스트리의 키 backend 로 HSM 또는 MPC 를 고른다.
// 이 패키지는 internal/hsm·alice 를 import 하지 않는다(구현은 주입받는다).
package router

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

// HSM 은 HSM 서명기(signer/hsm.Signer)의 기능이다.
type HSM interface {
	signer.Signer
	PublicKeyOf(ctx context.Context, tokenLabel, keyID string) (signer.PublicKey, error)
	ObjectCount(ctx context.Context, tokenLabel, keyID string) (int, error)
	DestroyIn(ctx context.Context, tokenLabel, keyID string) error
}

// MPC 는 MPC 조정자(signer/mpc.Client)의 기능이다.
type MPC interface {
	signer.Signer
	PublicKeyOf(ctx context.Context, tokenLabel, keyID string) (signer.PublicKey, error)
	ObjectCount(ctx context.Context, tokenLabel, keyID string) (int, error)
	DestroyIn(ctx context.Context, tokenLabel, keyID string) (int, error)
}

// ErrNoMPC 는 MPC 서명기가 설정되지 않았다는 것이다.
var ErrNoMPC = errors.New("router: MPC 서명기가 설정되지 않았다")

// Router 는 키별로 서명기를 고른다. BackendOf 는 레지스트리에 없는 키에 대해 HSM 을 돌려준다.
type Router struct {
	HSM       HSM
	MPC       MPC // nil 이면 MPC 키 작업·서명을 거부한다
	BackendOf func(ctx context.Context, keyID string) (signer.Backend, error)
}

func (r *Router) mpc() (MPC, error) {
	if r.MPC == nil {
		return nil, ErrNoMPC
	}
	return r.MPC, nil
}

func (r *Router) isMPC(ctx context.Context, keyID string) (bool, error) {
	b, err := r.BackendOf(ctx, keyID)
	if err != nil {
		return false, err
	}
	switch b {
	case signer.BackendMPC:
		return true, nil
	case signer.BackendHSM, "":
		return false, nil
	}
	return false, fmt.Errorf("router: 키 %s 의 알 수 없는 서명기 %q", keyID, b)
}

// Generate 는 spec.Backend 로 서명기를 고른다.
func (r *Router) Generate(ctx context.Context, spec signer.KeySpec) (signer.PublicKey, error) {
	if spec.Backend == "" {
		spec.Backend = signer.BackendHSM
	}
	if err := signer.CheckBackend(spec.Backend, spec.Purpose); err != nil {
		return nil, err
	}
	if spec.Backend == signer.BackendMPC {
		m, err := r.mpc()
		if err != nil {
			return nil, err
		}
		return m.Generate(ctx, spec)
	}
	return r.HSM.Generate(ctx, spec)
}

// SignDigest 는 키의 서명기로 서명한다.
func (r *Router) SignDigest(ctx context.Context, keyID string, digest [32]byte) (*big.Int, *big.Int, error) {
	isMPC, err := r.isMPC(ctx, keyID)
	if err != nil {
		return nil, nil, err
	}
	if isMPC {
		m, err := r.mpc()
		if err != nil {
			return nil, nil, err
		}
		return m.SignDigest(ctx, keyID, digest)
	}
	return r.HSM.SignDigest(ctx, keyID, digest)
}

// Destroy 는 키의 서명기에서 지운다.
func (r *Router) Destroy(ctx context.Context, keyID string) error {
	isMPC, err := r.isMPC(ctx, keyID)
	if err != nil {
		return err
	}
	if isMPC {
		m, err := r.mpc()
		if err != nil {
			return err
		}
		return m.Destroy(ctx, keyID)
	}
	return r.HSM.Destroy(ctx, keyID)
}

// PublicKeyOf 는 서명기가 가진 공개키다.
func (r *Router) PublicKeyOf(ctx context.Context, tokenLabel, keyID string) (signer.PublicKey, error) {
	isMPC, err := r.isMPC(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if isMPC {
		m, err := r.mpc()
		if err != nil {
			return nil, err
		}
		return m.PublicKeyOf(ctx, tokenLabel, keyID)
	}
	return r.HSM.PublicKeyOf(ctx, tokenLabel, keyID)
}

// ObjectCount 는 남은 객체(HSM)·조각(MPC) 수다. MPC 는 응답하지 않는 노드가 있으면 오류다.
func (r *Router) ObjectCount(ctx context.Context, tokenLabel, keyID string) (int, error) {
	isMPC, err := r.isMPC(ctx, keyID)
	if err != nil {
		return 0, err
	}
	if isMPC {
		m, err := r.mpc()
		if err != nil {
			return 0, err
		}
		return m.ObjectCount(ctx, tokenLabel, keyID)
	}
	return r.HSM.ObjectCount(ctx, tokenLabel, keyID)
}

// DestroyIn 은 객체·조각을 지운다.
func (r *Router) DestroyIn(ctx context.Context, tokenLabel, keyID string) error {
	isMPC, err := r.isMPC(ctx, keyID)
	if err != nil {
		return err
	}
	if isMPC {
		m, err := r.mpc()
		if err != nil {
			return err
		}
		_, err = m.DestroyIn(ctx, tokenLabel, keyID)
		return err
	}
	return r.HSM.DestroyIn(ctx, tokenLabel, keyID)
}
