//go:build integration

package test

import (
	"crypto/tls"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

const (
	signerdURL = "https://127.0.0.1:8443"
	apidURL    = "https://127.0.0.1:9443"
	besuRPC    = "http://127.0.0.1:8545"
)

// mtlsClient 는 deploy/certs 의 cn 인증서로 serverName 서버에 접속하는 클라이언트다.
func mtlsClient(t *testing.T, cn, serverName string) *http.Client {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "deploy", "certs")
	cfg, err := transport.ClientTLSConfig(transport.TLSFiles{
		CA: filepath.Join(dir, "ca.crt"), Cert: filepath.Join(dir, cn+".crt"), Key: filepath.Join(dir, cn+".key"),
	}, serverName)
	if err != nil {
		t.Fatalf("인증서(make up 필요): %v", err)
	}
	return transport.NewClient(cfg, 10*time.Second)
}

// noCertClient 는 서버 인증서만 검증하고 클라이언트 인증서는 내지 않는다.
func noCertClient(t *testing.T, serverName string) *http.Client {
	t.Helper()
	cfg, err := transport.ClientTLSConfig(transport.TLSFiles{
		CA: filepath.Join(repoRoot(t), "deploy", "certs", "ca.crt"), Cert: filepath.Join(repoRoot(t), "deploy", "certs", "stoctl.crt"),
		Key: filepath.Join(repoRoot(t), "deploy", "certs", "stoctl.key"),
	}, serverName)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Certificates = nil
	return transport.NewClient(&tls.Config{MinVersion: cfg.MinVersion, RootCAs: cfg.RootCAs, ServerName: serverName}, 10*time.Second)
}
