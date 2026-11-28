// Command gen-certs 는 로컬 CA 와 apid, signerd, stoctl, mpcd-1~3 인증서를 만든다(T1.1, T5.1). 이미 있는 인증서는 두고 없는 것만 발급한다.
// 결과는 -out 디렉터리(기본 deploy/certs, 커밋 금지)에 PEM 으로 쓴다. 이미 CA 가 있으면 아무것도 하지 않는다.
// macOS 의 openssl 이 LibreSSL 일 수 있어 Go 표준 라이브러리로 만든다.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type leaf struct {
	cn       string
	dns      []string
	ips      []net.IP
	usages   []x509.ExtKeyUsage
	validity time.Duration
}

func main() {
	out := flag.String("out", "deploy/certs", "출력 디렉터리")
	flag.Parse()
	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "실패:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	// 기존 디렉터리라도 소유자 전용으로 강제한다.
	if err := os.Chmod(out, 0o700); err != nil {
		return err
	}
	now := time.Now()
	caCert, caKey, err := loadCA(out)
	if err != nil {
		return err
	}
	if caCert == nil {
		if caCert, caKey, err = newCA(out, now); err != nil {
			return err
		}
	} else {
		fmt.Println("기존 CA 사용:", filepath.Join(out, "ca.crt"), "(없는 인증서만 발급한다)")
	}

	loop := []net.IP{net.ParseIP("127.0.0.1")}
	both := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	leaves := []leaf{
		{cn: "signerd", dns: []string{"signerd", "localhost"}, ips: loop, usages: both, validity: 365 * 24 * time.Hour},
		{cn: "apid", dns: []string{"apid", "localhost"}, ips: loop, usages: both, validity: 365 * 24 * time.Hour},
		{cn: "stoctl", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, validity: 365 * 24 * time.Hour},
		// MPC 키 조각 노드(T5.1, D-25). 서명 서버가 호스트 이름 mpcd-N 으로 접속하고, 헬스체크는 자기 인증서로 자기에게 접속한다.
		{cn: "mpcd-1", dns: []string{"mpcd-1", "localhost"}, ips: loop, usages: both, validity: 365 * 24 * time.Hour},
		{cn: "mpcd-2", dns: []string{"mpcd-2", "localhost"}, ips: loop, usages: both, validity: 365 * 24 * time.Hour},
		{cn: "mpcd-3", dns: []string{"mpcd-3", "localhost"}, ips: loop, usages: both, validity: 365 * 24 * time.Hour},
	}
	for _, l := range leaves {
		if _, err := os.Stat(filepath.Join(out, l.cn+".crt")); err == nil {
			continue
		}
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		tpl := &x509.Certificate{
			SerialNumber: serial(),
			Subject:      pkix.Name{CommonName: l.cn, Organization: []string{"sto-kms-mvp"}},
			NotBefore:    now.Add(-time.Minute),
			NotAfter:     now.Add(l.validity),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  l.usages,
			DNSNames:     l.dns,
			IPAddresses:  l.ips,
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &k.PublicKey, caKey)
		if err != nil {
			return err
		}
		if err := writePEM(filepath.Join(out, l.cn+".crt"), "CERTIFICATE", der, 0o644); err != nil {
			return err
		}
		// 개인키는 소유자 전용(0600)이다. Docker Desktop 은 바인드 마운트 파일을 컨테이너 사용자 소유로 보여 주므로
		// 비 root 컨테이너도 읽는다. Linux Docker Engine 에서는 파일 소유자를 컨테이너 uid 로 바꿔야 한다(README 한계 참조).
		if err := writeKey(filepath.Join(out, l.cn+".key"), k, 0o600); err != nil {
			return err
		}
		fmt.Println("생성:", filepath.Join(out, l.cn+".crt"))
	}
	return nil
}

// newCA 는 로컬 CA 를 만든다.
func newCA(out string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	caTpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "sto-kms local CA", Organization: []string{"sto-kms-mvp"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(3, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, err
	}
	if err := writePEM(filepath.Join(out, "ca.crt"), "CERTIFICATE", caDER, 0o644); err != nil {
		return nil, nil, err
	}
	// CA 개인키는 어느 컨테이너에도 마운트하지 않으므로 소유자만 읽게 둔다.
	if err := writeKey(filepath.Join(out, "ca.key"), caKey, 0o600); err != nil {
		return nil, nil, err
	}
	return caCert, caKey, nil
}

// loadCA 는 기존 CA 를 읽는다. 없으면 (nil, nil, nil).
func loadCA(out string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(filepath.Join(out, "ca.crt"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(out, "ca.key"))
	if err != nil {
		return nil, nil, fmt.Errorf("CA 개인키: %w", err)
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, errors.New("CA 파일 형식")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("CA 개인키 형식")
	}
	return cert, ek, nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		panic(err)
	}
	return n
}

func writeKey(path string, k *ecdsa.PrivateKey, mode os.FileMode) error {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	return writePEM(path, "PRIVATE KEY", der, mode)
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}
