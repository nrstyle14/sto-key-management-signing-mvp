package signsvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

func testCert(t *testing.T, cn string) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// proposal 은 피어에 접속하지 않고 게이트웨이로 제안 원문을 만든다(오프라인 서명).
func proposal(t *testing.T, certPEM []byte, fn string, args []string, opts ...client.ProposalOption) []byte {
	t.Helper()
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := identity.NewX509Identity("InstAMSP", cert)
	conn, err := grpc.NewClient("127.0.0.1:1", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	gw, err := client.Connect(id, client.WithClientConnection(conn))
	if err != nil {
		t.Fatal(err)
	}
	p, err := gw.GetNetwork("sto-channel").GetContract("sectoken").NewProposal(fn, append([]client.ProposalOption{client.WithArguments(args...)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := p.Bytes()
	return b
}

// endorsed 는 제안에서 보증된 트랜잭션(PreparedTransaction)을 조립한다. mut 으로 일부를 바꿀 수 있다.
func endorsed(t *testing.T, proposedBytes []byte, mut func(chHdr, sigHdr, payload *[]byte, hash *[]byte)) []byte {
	t.Helper()
	var pt gateway.ProposedTransaction
	if err := proto.Unmarshal(proposedBytes, &pt); err != nil {
		t.Fatal(err)
	}
	var prop peer.Proposal
	_ = proto.Unmarshal(pt.Proposal.ProposalBytes, &prop)
	var hdr common.Header
	_ = proto.Unmarshal(prop.Header, &hdr)
	h := sha256.New()
	h.Write(hdr.ChannelHeader)
	h.Write(hdr.SignatureHeader)
	h.Write(prop.Payload)
	chHdr, sigHdr, payload, hash := hdr.ChannelHeader, hdr.SignatureHeader, prop.Payload, h.Sum(nil)
	if mut != nil {
		mut(&chHdr, &sigHdr, &payload, &hash)
	}
	prp, _ := proto.Marshal(&peer.ProposalResponsePayload{ProposalHash: hash})
	cap_, _ := proto.Marshal(&peer.ChaincodeActionPayload{ChaincodeProposalPayload: payload,
		Action: &peer.ChaincodeEndorsedAction{ProposalResponsePayload: prp, Endorsements: []*peer.Endorsement{{Endorser: []byte("peer"), Signature: []byte("sig")}}}})
	tx, _ := proto.Marshal(&peer.Transaction{Actions: []*peer.TransactionAction{{Header: sigHdr, Payload: cap_}}})
	pl, _ := proto.Marshal(&common.Payload{Header: &common.Header{ChannelHeader: chHdr, SignatureHeader: sigHdr}, Data: tx})
	out, _ := proto.Marshal(&gateway.PreparedTransaction{TransactionId: pt.TransactionId, Envelope: &common.Envelope{Payload: pl}})
	return out
}

func code(err error) string {
	var rj *Rejection
	if errors.As(err, &rj) {
		return rj.Code
	}
	return ""
}

// 제안 해석: 채널·체인코드·함수·인자·생성자·txID 를 꺼내고, transient 가 있으면 거부한다.
func TestParseProposal(t *testing.T) {
	cert := testCert(t, "inst-a-transfer-1")
	pb := proposal(t, cert, "RegisterAccount", []string{"acct-1"})
	var pt gateway.ProposedTransaction
	_ = proto.Unmarshal(pb, &pt)
	pp, cis, creator, cc, err := parseProposalBytes(pt.Proposal.ProposalBytes)
	if err != nil {
		t.Fatal(err)
	}
	if pp.channel != "sto-channel" || cc != "sectoken" || pp.txID != pt.TransactionId || creator.Mspid != "InstAMSP" || string(creator.IdBytes) != string(cert) {
		t.Fatalf("해석 %+v %s %s", pp, cc, creator.Mspid)
	}
	args := cis.ChaincodeSpec.Input.Args
	if len(args) != 2 || string(args[0]) != "RegisterAccount" || string(args[1]) != "acct-1" {
		t.Fatalf("인자 %q", args)
	}
	withTransient := proposal(t, cert, "RegisterAccount", []string{"acct-1"}, client.WithTransient(map[string][]byte{"k": []byte("v")}))
	_ = proto.Unmarshal(withTransient, &pt)
	if _, _, _, _, err := parseProposalBytes(pt.Proposal.ProposalBytes); code(err) != CodeFabricMismatch {
		t.Fatalf("transient 제안: %v", err)
	}
	if _, _, _, _, err := parseProposalBytes([]byte("garbage")); code(err) != CodeFabricInvalid {
		t.Fatalf("깨진 제안: %v", err)
	}
}

// 트랜잭션·커밋 대조: 서명한 제안에서 나온 것만 받는다.
func TestCheckTransactionAndCommit(t *testing.T) {
	cert := testCert(t, "inst-a-transfer-1")
	pb := proposal(t, cert, "RegisterAccount", []string{"acct-1"})
	var pt gateway.ProposedTransaction
	_ = proto.Unmarshal(pb, &pt)
	pp, _, _, _, err := parseProposalBytes(pt.Proposal.ProposalBytes)
	if err != nil {
		t.Fatal(err)
	}
	good := endorsed(t, pb, nil)
	d, err := checkTransaction(good, pp)
	if err != nil {
		t.Fatal(err)
	}
	var prepared gateway.PreparedTransaction
	_ = proto.Unmarshal(good, &prepared)
	if d != sha256.Sum256(prepared.Envelope.Payload) {
		t.Fatal("트랜잭션 다이제스트는 SHA-256(Envelope.Payload) 여야 한다")
	}
	other := proposal(t, cert, "RegisterAccount", []string{"acct-2"}) // 다른 제안(다른 txID·입력)
	var opt gateway.ProposedTransaction
	_ = proto.Unmarshal(other, &opt)
	var oprop peer.Proposal
	_ = proto.Unmarshal(opt.Proposal.ProposalBytes, &oprop)
	var ohdr common.Header
	_ = proto.Unmarshal(oprop.Header, &ohdr)
	cases := map[string][]byte{
		"다른 제안의 트랜잭션":       endorsed(t, other, nil),
		"헤더 바꿔치기":           endorsed(t, pb, func(ch, sh, _, _ *[]byte) { *ch, *sh = ohdr.ChannelHeader, ohdr.SignatureHeader }),
		"호출 입력 바꿔치기":        endorsed(t, pb, func(_, _, pl, _ *[]byte) { *pl = oprop.Payload }),
		"proposal_hash 불일치": endorsed(t, pb, func(_, _, _, h *[]byte) { *h = make([]byte, 32) }),
		"깨진 원문":             []byte("garbage"),
	}
	for name, b := range cases {
		if _, err := checkTransaction(b, pp); err == nil {
			t.Errorf("%s 를 받아들였다", name)
		}
	}
	// 커밋 상태 요청
	commit := func(txID, channel string, identity []byte) []byte {
		req, _ := proto.Marshal(&gateway.CommitStatusRequest{TransactionId: txID, ChannelId: channel, Identity: identity})
		b, _ := proto.Marshal(&gateway.SignedCommitStatusRequest{Request: req})
		return b
	}
	if _, err := checkCommit(commit(pp.txID, "sto-channel", pp.creator), pp); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"다른 txID": commit(opt.TransactionId, "sto-channel", pp.creator),
		"다른 채널":   commit(pp.txID, "other", pp.creator),
		"다른 신원":   commit(pp.txID, "sto-channel", []byte("someone")),
		"깨진 원문":   []byte("garbage"),
	} {
		if _, err := checkCommit(b, pp); err == nil {
			t.Errorf("커밋 %s 를 받아들였다", name)
		}
	}
}

// proposalBytesOf 는 ProposedTransaction 원문에서 ProposalBytes 를 꺼낸다.
func proposalBytesOf(t *testing.T, proposed []byte) []byte {
	t.Helper()
	var pt gateway.ProposedTransaction
	if err := proto.Unmarshal(proposed, &pt); err != nil {
		t.Fatal(err)
	}
	return pt.Proposal.ProposalBytes
}

// commitBytes 는 제안에 대한 커밋 상태 요청 원문(SignedCommitStatusRequest)이다.
func commitBytes(t *testing.T, proposed []byte) []byte {
	t.Helper()
	pp, _, _, _, err := parseProposalBytes(proposalBytesOf(t, proposed))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := proto.Marshal(&gateway.CommitStatusRequest{TransactionId: pp.txID, ChannelId: pp.channel, Identity: pp.creator})
	b, _ := proto.Marshal(&gateway.SignedCommitStatusRequest{Request: req})
	return b
}
