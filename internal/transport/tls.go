package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

// TLSFiles 는 mTLS 에 쓰는 PEM 파일 경로다.
type TLSFiles struct {
	CA   string `yaml:"ca"`
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// Validate 는 경로가 모두 지정됐는지 확인한다.
func (f TLSFiles) Validate() error {
	if f.CA == "" || f.Cert == "" || f.Key == "" {
		return errors.New("tls.ca, tls.cert, tls.key 가 모두 필요하다")
	}
	return nil
}

func loadPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("CA 인증서 읽기: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("CA 인증서를 해석하지 못했다")
	}
	return pool, nil
}

// ServerTLSConfig 는 클라이언트 인증서를 필수로 검증하는 서버 TLS 설정을 만든다.
// allowed 는 접속을 허용할 클라이언트 인증서 CN 목록이다. 목록 밖의 CN 은 핸드셰이크에서 거부한다.
// 경로별로 더 좁히려면 RequireCaller 를 쓴다.
func ServerTLSConfig(f TLSFiles, allowed []string) (*tls.Config, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	if len(allowed) == 0 {
		return nil, errors.New("허용 호출자 목록이 비었다")
	}
	pool, err := loadPool(f.CA)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(f.Cert, f.Key)
	if err != nil {
		return nil, fmt.Errorf("서버 인증서 읽기: %w", err)
	}
	return newServerTLS(pool, cert, allowed), nil
}

func newServerTLS(pool *x509.CertPool, cert tls.Certificate, allowed []string) *tls.Config {
	allow := toSet(allowed)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		// 검증된 체인의 말단 인증서 CN 으로 허용 여부를 판단한다.
		VerifyConnection: func(cs tls.ConnectionState) error {
			cn, err := verifiedCN(cs)
			if err != nil {
				return err
			}
			if !allow[cn] {
				return fmt.Errorf("허용되지 않은 호출자 CN: %q", cn)
			}
			return nil
		},
	}
}

// ClientTLSConfig 는 서버 인증서를 CA 로 검증하고 자신의 인증서를 제시하는 클라이언트 TLS 설정을 만든다.
func ClientTLSConfig(f TLSFiles, serverName string) (*tls.Config, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	pool, err := loadPool(f.CA)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(f.Cert, f.Key)
	if err != nil {
		return nil, fmt.Errorf("클라이언트 인증서 읽기: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ServerName:   serverName,
	}, nil
}

// NewClient 는 mTLS HTTP 클라이언트를 만든다.
func NewClient(cfg *tls.Config, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true},
	}
}

func verifiedCN(cs tls.ConnectionState) (string, error) {
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return "", errors.New("검증된 클라이언트 인증서가 없다")
	}
	return cs.VerifiedChains[0][0].Subject.CommonName, nil
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
