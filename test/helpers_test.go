//go:build integration

package test

import (
	"crypto/ed25519"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
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

// approverSign 은 deploy/approvers/<id>.json 키(암호는 deploy/secrets/approver_<id>_password)로 승인 서명을 만든다.
func approverSign(t *testing.T, id string, intentHash [32]byte, d approval.Decision) approval.Approval {
	t.Helper()
	kf, err := approval.ReadKeyFile(filepath.Join(repoRoot(t), "deploy", "approvers", id+".json"))
	if err != nil {
		t.Fatalf("승인자 키 파일(make up 필요): %v", err)
	}
	pw, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "secrets", "approver_"+id+"_password"))
	if err != nil {
		t.Fatal(err)
	}
	priv, err := kf.Decrypt([]byte(strings.TrimSpace(string(pw))))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(priv)
	sig, err := approval.Sign(priv, intentHash, d)
	if err != nil {
		t.Fatal(err)
	}
	return approval.Approval{ApproverID: id, Decision: d, Signature: hex.EncodeToString(sig)}
}

// signerDB 는 signer 스키마에 signer_app 으로 접속한다(조회용).
func signerDB(t *testing.T) *sql.DB {
	t.Helper()
	pw, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "secrets", "signer_app_password"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr, cfg.DBName = "signer_app", strings.TrimSpace(string(pw)), "tcp", "127.0.0.1:3306", "signer"
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func bigInt(v int64) *big.Int { return big.NewInt(v) }

// approverKey 는 승인자 키 파일을 풀어 개인키를 돌려준다(호출자가 clear).
func approverKey(t *testing.T, id string) ed25519.PrivateKey {
	t.Helper()
	kf, err := approval.ReadKeyFile(filepath.Join(repoRoot(t), "deploy", "approvers", id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	pw, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "secrets", "approver_"+id+"_password"))
	if err != nil {
		t.Fatal(err)
	}
	priv, err := kf.Decrypt([]byte(strings.TrimSpace(string(pw))))
	if err != nil {
		t.Fatal(err)
	}
	return priv
}
