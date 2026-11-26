package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newCA(t *testing.T, name string) *testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	p := x509.NewCertPool()
	p.AddCert(c)
	return &testCA{cert: c, key: k, pool: p}
}

func (ca *testCA) issue(t *testing.T, cn string, server bool) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	if server {
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// 실제 TLS 핸드셰이크로 서버를 띄운다. /any 는 서버 허용 목록만, /apid-only 는 apid 만 허용한다.
func startServer(t *testing.T, ca *testCA) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/any", RequireCaller([]string{"apid", "stoctl"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, 200, map[string]string{"caller": Caller(r.Context())})
	})))
	mux.Handle("/apid-only", RequireCaller([]string{"apid"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, 200, map[string]string{"caller": Caller(r.Context())})
	})))
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = newServerTLS(ca.pool, ca.issue(t, "signerd", true), []string{"apid", "stoctl"})
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func client(ca *testCA, cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.pool}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return NewClient(cfg, 5*time.Second)
}

func TestMTLSAllowedCaller(t *testing.T) {
	ca := newCA(t, "ca")
	srv := startServer(t, ca)
	c := ca.issue(t, "apid", false)
	resp, err := client(ca, &c).Get(srv.URL + "/apid-only")
	if err != nil {
		t.Fatalf("허용된 호출자가 거부됐다: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != 200 || body["caller"] != "apid" {
		t.Fatalf("status=%d body=%v", resp.StatusCode, body)
	}
}

func TestMTLSRejectsNoClientCert(t *testing.T) {
	ca := newCA(t, "ca")
	srv := startServer(t, ca)
	if resp, err := client(ca, nil).Get(srv.URL + "/any"); err == nil {
		resp.Body.Close()
		t.Fatalf("인증서 없는 호출이 허용됐다: status=%d", resp.StatusCode)
	}
}

func TestMTLSRejectsOtherCA(t *testing.T) {
	ca := newCA(t, "ca")
	other := newCA(t, "other")
	srv := startServer(t, ca)
	c := other.issue(t, "apid", false) // CN 은 맞지만 다른 CA 가 발급
	if resp, err := client(ca, &c).Get(srv.URL + "/any"); err == nil {
		resp.Body.Close()
		t.Fatalf("다른 CA 의 인증서가 허용됐다: status=%d", resp.StatusCode)
	}
}

func TestMTLSRejectsDisallowedCN(t *testing.T) {
	ca := newCA(t, "ca")
	srv := startServer(t, ca)
	c := ca.issue(t, "intruder", false) // 같은 CA, 허용 목록 밖의 CN
	if resp, err := client(ca, &c).Get(srv.URL + "/any"); err == nil {
		resp.Body.Close()
		t.Fatalf("허용되지 않은 CN 이 핸드셰이크를 통과했다: status=%d", resp.StatusCode)
	}
}

func TestRouteAllowlistNarrowerThanServer(t *testing.T) {
	ca := newCA(t, "ca")
	srv := startServer(t, ca)
	c := ca.issue(t, "stoctl", false) // 서버에는 허용, /apid-only 에는 불허
	resp, err := client(ca, &c).Get(srv.URL + "/apid-only")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body ErrorBody
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusForbidden || body.Code != CodeCallerNotAllowed {
		t.Fatalf("경로 허용 목록 밖 호출: status=%d code=%s", resp.StatusCode, body.Code)
	}
}
