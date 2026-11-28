// sectoken-cc 는 Fabric 체인코드다(T5.2, D-26). 체인코드-as-a-service 로 실행된다(peer 에 Docker 소켓 없음).
// 완료 기준에 필요한 함수만 둔다(Besu 컨트랙트와 같은 기능을 옮기지 않는다):
//
//	RegisterAccount(acct): 호출자 MSP 와 인증서 주체(CN)를 계좌 기록으로 남기고 이벤트 AccountRegistered 를 낸다.
//	                       호출자 인증서에 CA 속성 sto.role=agent 가 있어야 한다(stoctl fabric enroll 이 붙인 HSM 신원만).
//	                       cryptogen 파일 신원(기관 관리자·peer)은 서명 서버를 거치지 않으므로 거부한다(D-26 ⑥).
//	GetAccount(acct):      기록을 돌려준다.
package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/hyperledger/fabric-chaincode-go/v2/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/protobuf/proto"
)

// agentAttr 는 원장을 바꾸는 함수를 부를 수 있는 신원의 CA 속성이다(stoctl fabric enroll 이 등록 때 붙인다).
const agentAttr = "sto.role"

var acctRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Account 는 계좌 기록이다.
type Account struct {
	Account string `json:"account"`
	MSPID   string `json:"msp_id"`
	Agent   string `json:"agent"` // 등록한 신원 인증서의 CN
	TxID    string `json:"tx_id"`
}

type cc struct{}

func (cc) Init(shim.ChaincodeStubInterface) *peer.Response { return shim.Success(nil) }

func creator(stub shim.ChaincodeStubInterface) (string, string, error) {
	raw, err := stub.GetCreator()
	if err != nil {
		return "", "", err
	}
	var id msp.SerializedIdentity
	if err := proto.Unmarshal(raw, &id); err != nil {
		return "", "", err
	}
	b, _ := pem.Decode(id.IdBytes)
	if b == nil {
		return "", "", errors.New("생성자 인증서 형식")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return "", "", err
	}
	return id.Mspid, c.Subject.CommonName, nil
}

func (cc) Invoke(stub shim.ChaincodeStubInterface) *peer.Response {
	fn, args := stub.GetFunctionAndParameters()
	if len(args) != 1 || !acctRe.MatchString(args[0]) {
		return shim.Error("인자는 계좌 식별자 1개다")
	}
	key := "acct:" + args[0]
	switch fn {
	case "RegisterAccount":
		if err := cid.AssertAttributeValue(stub, agentAttr, "agent"); err != nil {
			return shim.Error("호출자 신원에 " + agentAttr + "=agent 속성이 없다(서명 서버를 거친 HSM 신원만 원장을 바꾼다)")
		}
		if v, _ := stub.GetState(key); v != nil {
			return shim.Error(fmt.Sprintf("계좌 %s 는 이미 등록됐다", args[0]))
		}
		mspID, cn, err := creator(stub)
		if err != nil {
			return shim.Error(err.Error())
		}
		a := Account{Account: args[0], MSPID: mspID, Agent: cn, TxID: stub.GetTxID()}
		b, _ := json.Marshal(a)
		if err := stub.PutState(key, b); err != nil {
			return shim.Error(err.Error())
		}
		if err := stub.SetEvent("AccountRegistered", b); err != nil {
			return shim.Error(err.Error())
		}
		return shim.Success(b)
	case "GetAccount":
		v, err := stub.GetState(key)
		if err != nil {
			return shim.Error(err.Error())
		}
		if v == nil {
			return shim.Error("계좌가 없다")
		}
		return shim.Success(v)
	}
	return shim.Error("알 수 없는 함수 " + fn)
}

func main() {
	id := os.Getenv("CHAINCODE_ID")
	if id == "" {
		fmt.Fprintln(os.Stderr, "CHAINCODE_ID 가 필요하다")
		os.Exit(1)
	}
	s := &shim.ChaincodeServer{CCID: id, Address: "0.0.0.0:9999", CC: cc{}, TLSProps: shim.TLSProperties{Disabled: true}}
	if err := s.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
