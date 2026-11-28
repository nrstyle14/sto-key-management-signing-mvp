package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger/fabric"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
)

// startFabric 은 Fabric 원장(설계서 10.5, D-26)을 켠다. 설정이 없거나 peer TLS CA 가 없으면(make up-fabric 전) 끄고 nil.
func (a *app) startFabric(ctx context.Context, interval time.Duration, log *slog.Logger, logw func(string, ...any)) *fabric.Adapter {
	c := a.cfg.Fabric
	if c.LedgerID == "" {
		return nil
	}
	if _, err := os.Stat(c.TLSCAFile); err != nil {
		log.Warn("Fabric peer TLS CA 가 없어 Fabric 원장을 끈다", "ledger", c.LedgerID, "file", c.TLSCAFile)
		return nil
	}
	ad, err := fabric.New(fabric.Config{PeerAddress: c.PeerAddress, ServerName: c.ServerName, TLSCAFile: c.TLSCAFile})
	if err != nil {
		log.Error("Fabric 어댑터", "err", err)
		return nil
	}
	a.wf.FabricLedgerID = c.LedgerID
	w := &workflow.FabricWorker{DB: a.db, LedgerID: c.LedgerID, Ledger: ad, Signer: a.signer, Identities: a.signer,
		IsTransient: func(err error) bool { return errors.Is(err, fabric.ErrTransient) }}
	go w.Run(ctx, interval, logw)
	log.Info("Fabric 원장", "ledger", c.LedgerID, "peer", c.PeerAddress)
	return ad
}
