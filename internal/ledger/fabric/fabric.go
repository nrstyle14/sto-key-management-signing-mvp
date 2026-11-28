// Package fabric 은 Fabric 원장 어댑터다(설계서 10.5, D-26). 업무 서버만 쓴다(서명 서버는 이 패키지를 링크하지 않는다).
//
// 게이트웨이 오프라인 서명을 쓴다: 이 어댑터는 서명할 원문(제안, 보증된 트랜잭션, 커밋 상태 요청)을 만들고
// 서명 서버가 준 서명을 붙여 보낸다. 신원 키는 서명 서버의 HSM 에만 있다.
package fabric

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// Config 는 peer 게이트웨이 접속 설정이다.
type Config struct {
	PeerAddress string // 예: peer0.insta.example.com:7051
	ServerName  string // peer TLS 인증서 이름
	TLSCAFile   string // peer TLS CA
}

// Adapter 는 게이트웨이 접속이다.
type Adapter struct {
	conn *grpc.ClientConn
}

// ErrTransient 는 다시 시도할 수 있는 오류(peer 응답 없음 등)다.
var ErrTransient = errors.New("fabric: 일시 오류")

// New 는 peer 게이트웨이 gRPC 연결을 만든다(접속은 처음 호출 때).
func New(c Config) (*Adapter, error) {
	raw, err := os.ReadFile(c.TLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("fabric: peer TLS CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, errors.New("fabric: peer TLS CA 형식")
	}
	conn, err := grpc.NewClient(c.PeerAddress, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: c.ServerName, MinVersion: tls.VersionTLS12})))
	if err != nil {
		return nil, err
	}
	return &Adapter{conn: conn}, nil
}

// Close 는 연결을 닫는다.
func (a *Adapter) Close() error { return a.conn.Close() }

func (a *Adapter) gateway(certPEM []byte, mspID string) (*client.Gateway, error) {
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, err
	}
	id, err := identity.NewX509Identity(mspID, cert)
	if err != nil {
		return nil, err
	}
	// WithSign 없음: 오프라인 서명
	return client.Connect(id, client.WithClientConnection(a.conn), client.WithEvaluateTimeout(10*time.Second),
		client.WithEndorseTimeout(20*time.Second), client.WithSubmitTimeout(20*time.Second), client.WithCommitStatusTimeout(60*time.Second))
}

// classify 는 gRPC 오류를 일시 오류와 영구 오류로 나눈다.
func classify(err error) error {
	if err == nil {
		return nil
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Canceled:
		return fmt.Errorf("%w: %v", ErrTransient, err)
	}
	return err
}

// NewProposal 은 서명할 제안 원문(gateway.ProposedTransaction)과 txID 를 만든다(접속하지 않는다).
func (a *Adapter) NewProposal(certPEM []byte, mspID, channel, chaincode, fn string, args []string) ([]byte, string, error) {
	gw, err := a.gateway(certPEM, mspID)
	if err != nil {
		return nil, "", err
	}
	defer gw.Close()
	p, err := gw.GetNetwork(channel).GetContract(chaincode).NewProposal(fn, client.WithArguments(args...))
	if err != nil {
		return nil, "", err
	}
	b, err := p.Bytes()
	return b, p.TransactionID(), err
}

// Endorse 는 서명된 제안을 보증받아 서명할 트랜잭션 원문(gateway.PreparedTransaction)을 돌려준다.
func (a *Adapter) Endorse(ctx context.Context, certPEM []byte, mspID string, proposal, sig []byte) ([]byte, error) {
	gw, err := a.gateway(certPEM, mspID)
	if err != nil {
		return nil, err
	}
	defer gw.Close()
	p, err := gw.NewSignedProposal(proposal, sig)
	if err != nil {
		return nil, err
	}
	tx, err := p.EndorseWithContext(ctx)
	if err != nil {
		return nil, classify(err)
	}
	return tx.Bytes()
}

// Submit 은 서명된 트랜잭션을 orderer 로 보내고 서명할 커밋 상태 요청 원문을 돌려준다.
func (a *Adapter) Submit(ctx context.Context, certPEM []byte, mspID string, transaction, sig []byte) ([]byte, error) {
	gw, err := a.gateway(certPEM, mspID)
	if err != nil {
		return nil, err
	}
	defer gw.Close()
	t, err := gw.NewSignedTransaction(transaction, sig)
	if err != nil {
		return nil, err
	}
	c, err := t.SubmitWithContext(ctx)
	if err != nil {
		return nil, classify(err)
	}
	return c.Bytes()
}

// Status 는 서명된 커밋 상태 요청으로 확정 결과를 기다린다. ok 가 false 면 무효 트랜잭션이고 code 가 그 사유다.
func (a *Adapter) Status(ctx context.Context, certPEM []byte, mspID string, commit, sig []byte) (ok bool, block uint64, code string, err error) {
	gw, err := a.gateway(certPEM, mspID)
	if err != nil {
		return false, 0, "", err
	}
	defer gw.Close()
	c, err := gw.NewSignedCommit(commit, sig)
	if err != nil {
		return false, 0, "", err
	}
	st, err := c.StatusWithContext(ctx)
	if err != nil {
		return false, 0, "", classify(err)
	}
	return st.Successful, st.BlockNumber, st.Code.String(), nil
}
