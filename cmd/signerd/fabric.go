package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyops"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

// Fabric 원장 설정(설계서 10.5, D-26).

func (a *app) ledger(id string) (LedgerConfig, bool) {
	for _, l := range a.cfg.Ledgers {
		if l.ID == id {
			return l, true
		}
	}
	return LedgerConfig{}, false
}

// curveOf 는 원장의 키 곡선이다.
func (a *app) curveOf(ledgerID string) signer.Curve {
	if l, ok := a.ledger(ledgerID); ok && l.IsFabric() {
		return signer.CurveP256
	}
	return signer.CurveSecp256k1
}

// fabricMSP 는 Fabric 원장 범위의 MSP ID 다.
func (a *app) fabricMSP(ledgerID, institutionID string) (string, bool) {
	l, ok := a.ledger(ledgerID)
	if !ok || !l.IsFabric() || len(a.fabricRoots[ledgerID]) == 0 {
		return "", false
	}
	m, ok := l.MSPs[institutionID]
	return m, ok
}

// loadFabricRoots 는 Fabric 원장의 MSP 루트 CA 인증서를 읽는다(기동 때 한 번). 파일이 없으면 기동하지 않는다.
func (a *app) loadFabricRoots() error {
	a.fabricRoots = map[string][]*x509.Certificate{}
	for _, l := range a.cfg.Ledgers {
		if !l.IsFabric() {
			continue
		}
		for _, f := range l.CACerts {
			raw, err := os.ReadFile(f)
			if errors.Is(err, os.ErrNotExist) {
				// make up-fabric 전: 이 원장만 끈다(Besu 환경은 그대로 동작해야 한다).
				a.log.Warn("Fabric 루트 CA 가 없어 Fabric 원장을 끈다", "ledger", l.ID, "file", f)
				delete(a.fabricRoots, l.ID)
				break
			}
			if err != nil {
				return fmt.Errorf("Fabric 원장 %s 루트 CA: %w", l.ID, err)
			}
			b, _ := pem.Decode(raw)
			if b == nil {
				return fmt.Errorf("Fabric 원장 %s 루트 CA %s 형식", l.ID, f)
			}
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return err
			}
			if !c.IsCA {
				return errors.New("Fabric 루트 CA 인증서가 CA 가 아니다")
			}
			a.fabricRoots[l.ID] = append(a.fabricRoots[l.ID], c)
		}
	}
	return nil
}

func (a *app) fabricConfig() keyops.FabricConfig {
	return keyops.FabricConfig{MSP: a.fabricMSP, Roots: func(id string) []*x509.Certificate { return a.fabricRoots[id] }}
}

// GET /v1/fabric/identities: Fabric 신원 인증서(공개 정보). 업무 서버는 제안 생성자 인증서로 쓴다.
func (a *app) listFabricIdentities(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.QueryContext(r.Context(), `SELECT key_id FROM fabric_identities ORDER BY created_at`)
	if err != nil {
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "신원 조회 실패")
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	out := []any{}
	for _, id := range ids {
		if i, err := keyreg.GetIdentity(r.Context(), a.db, id); err == nil {
			out = append(out, i)
		}
	}
	transport.WriteJSON(w, http.StatusOK, map[string]any{"identities": out})
}
