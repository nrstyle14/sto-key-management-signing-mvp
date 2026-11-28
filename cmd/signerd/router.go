package main

import (
	"context"
	"errors"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer/mpc"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer/router"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

// newRouter 는 키별 서명기 선택기를 만든다. mpc.nodes 가 있으면 MPC 조정자를 붙인다(D-25).
func (a *app) newRouter() (*router.Router, error) {
	r := &router.Router{HSM: a.hsm, BackendOf: func(ctx context.Context, keyID string) (signer.Backend, error) {
		k, err := keyreg.Get(ctx, a.db, keyID)
		if errors.Is(err, keyreg.ErrKeyNotFound) {
			return signer.BackendHSM, nil
		}
		if err != nil {
			return "", err
		}
		return k.Backend, nil
	}}
	m := a.cfg.MPC
	if len(m.Nodes) == 0 {
		return r, nil
	}
	if len(m.Nodes) != 3 {
		return nil, errors.New("mpc.nodes 는 3개여야 한다")
	}
	// 노드 인증서는 URL 의 호스트 이름(mpcd-N)으로 확인한다(ServerName 비움).
	tlsCfg, err := transport.ClientTLSConfig(a.cfg.TLS, "")
	if err != nil {
		return nil, err
	}
	c := &mpc.Client{Nodes: m.Nodes, HTTP: transport.NewClient(tlsCfg, 30*time.Second),
		PublicKey: func(ctx context.Context, keyID string) (signer.PublicKey, error) {
			k, err := keyreg.Get(ctx, a.db, keyID)
			if err != nil {
				return nil, err
			}
			return k.PublicKey, nil
		}}
	if m.GenerateTimeout != "" {
		if c.GenerateTimeout, err = time.ParseDuration(m.GenerateTimeout); err != nil {
			return nil, err
		}
	}
	if m.SignTimeout != "" {
		if c.SignTimeout, err = time.ParseDuration(m.SignTimeout); err != nil {
			return nil, err
		}
	}
	r.MPC = c
	return r, nil
}
