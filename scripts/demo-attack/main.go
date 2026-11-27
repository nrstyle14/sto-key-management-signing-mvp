// demo-attack 은 시연(T4.4)의 공격 흉내다. 실제 서명 서버·DB 를 상대로 하고, 검사를 건너뛰는 경로는 없다.
//
//	insufficient-approvals: 침해된 업무 서버 흉내. 승인 1건(필요 2건)만 붙인 요청을 서명 서버에 직접 보낸다.
//	  서명 서버가 6단계 APPROVAL_INSUFFICIENT 로 거부해야 한다.
//	calldata-swap: 침해된 업무 서버 흉내. 업무 서버 인증서(deploy/certs/apid.*)로 서명 서버에 직접, 승인자 2명이
//	  승인한 계좌대체 intent 와 수량을 바꾼 calldata 의 미서명 tx 를 보낸다. 서명 서버가 7단계 TX_CALLDATA_MISMATCH 로
//	  거부해야 한다(거부는 서명 서버 감사로그 SIGN_REJECTED 에 남는다). 거부되면 종료 코드 0.
//	audit-tamper: 감사로그 변조 탐지. ① 서버용 계정(api_app)의 audit_log UPDATE 가 거부되는지 확인하고
//	  ② 관리 계정으로 api.audit_log 를 일회용 스키마에 복사해 가운데 레코드를 고친 뒤 체인 검증이 그 seq 를 찾는지 본다.
//	  운영 감사로그는 바꾸지 않는다(복사본은 끝나면 지운다). 탐지하면 종료 코드 0.
//	holding-skew: 연계장부 착오기재 흉내. 업무 서버 계정으로 holdings 수량을 delta 만큼 바꾼다(대사 시연용, 되돌릴 때 -delta).
//
// 비밀(승인자 키 암호, DB 비밀번호)은 deploy/ 의 파일에서 읽고 출력하지 않는다.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/go-sql-driver/mysql"
	"github.com/oklog/ulid/v2"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/evmtx"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/policy"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signsvc"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "사용: demo-attack calldata-swap|insufficient-approvals|audit-tamper|holding-skew [플래그]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "calldata-swap":
		err = calldataSwap(os.Args[2:])
	case "insufficient-approvals":
		err = insufficientApprovals(os.Args[2:])
	case "audit-tamper":
		err = auditTamper(os.Args[2:])
	case "holding-skew":
		err = holdingSkew(os.Args[2:])
	default:
		err = fmt.Errorf("알 수 없는 명령 %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "실패:", err)
		os.Exit(1)
	}
}

func approverKey(id string) (ed25519.PrivateKey, error) {
	kf, err := approval.ReadKeyFile(filepath.Join("deploy", "approvers", id+".json"))
	if err != nil {
		return nil, err
	}
	pw, err := os.ReadFile(filepath.Join("deploy", "secrets", "approver_"+id+"_password"))
	if err != nil {
		return nil, err
	}
	defer clear(pw)
	return kf.Decrypt(bytes.TrimRight(pw, "\r\n"))
}

func calldataSwap(args []string) error {
	fs := flag.NewFlagSet("calldata-swap", flag.ExitOnError)
	a := attemptFlags(fs)
	swapped := fs.String("swapped", "99999", "calldata 에 넣을 수량(바꿔치기)")
	_ = fs.Parse(args)
	return a.run(*swapped, []string{"apr-a-02", "apr-a-03"}, evmtx.CodeTxCalldataMismatch)
}

func insufficientApprovals(args []string) error {
	fs := flag.NewFlagSet("insufficient-approvals", flag.ExitOnError)
	a := attemptFlags(fs)
	_ = fs.Parse(args)
	return a.run(*a.amount, []string{"apr-a-02"}, policy.CodeApprovalInsufficient)
}

type attempt struct {
	contract, from, to, amount, signerURL *string
	chainID                               *int64
}

func attemptFlags(fs *flag.FlagSet) *attempt {
	return &attempt{
		contract:  fs.String("contract", "", "종목 컨트랙트"),
		from:      fs.String("from", "", "출고 계좌 주소"),
		to:        fs.String("to", "", "입고 계좌 주소"),
		amount:    fs.String("amount", "1", "승인받은 수량"),
		chainID:   fs.Int64("chain-id", 20261124, "체인 ID"),
		signerURL: fs.String("signerd", "https://127.0.0.1:8443", "서명 서버"),
	}
}

// run 은 침해된 업무 서버처럼 서명 서버에 직접 서명을 요청한다. approvers 가 승인한 계좌대체 intent 와
// 수량 calldataAmount 의 calldata 를 보내고, 서명 서버가 want 코드로 거부해야 성공이다.
func (a *attempt) run(calldataAmount string, approvers []string, want string) error {
	in := &intent.Intent{RequestID: ulid.Make().String(), Type: intent.TypeTX, LedgerID: "besu-local", InstitutionID: "inst-a", KeyPurpose: "TRANSFER",
		Contract: common.HexToAddress(*a.contract).Hex(), Function: "transferByAgent(address,address,uint256)",
		Args:      []string{common.HexToAddress(*a.from).Hex(), common.HexToAddress(*a.to).Hex(), *a.amount},
		DrafterID: "apr-a-01", ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Format(intent.TimeLayout)}
	if err := in.Validate(); err != nil {
		return err
	}
	h, err := in.Hash()
	if err != nil {
		return err
	}
	var apprs []approval.Approval
	for _, id := range approvers {
		priv, err := approverKey(id)
		if err != nil {
			return err
		}
		sig, err := approval.Sign(priv, h, approval.Approve)
		clear(priv)
		if err != nil {
			return err
		}
		apprs = append(apprs, approval.Approval{ApproverID: id, Decision: approval.Approve, Signature: hex.EncodeToString(sig)})
	}
	sent := *in
	sent.Args = []string{in.Args[0], in.Args[1], calldataAmount}
	data, err := sent.Calldata()
	if err != nil {
		return err
	}
	raw, err := evmtx.EncodeUnsigned(evmtx.NewUnsigned(big.NewInt(*a.chainID), 0, in.ContractAddress(), data, 100000))
	if err != nil {
		return err
	}
	canon, _ := in.Canonical()
	body, _ := json.Marshal(signsvc.Request{Intent: canon, IntentHash: hex.EncodeToString(h[:]), Approvals: apprs, UnsignedTx: "0x" + hex.EncodeToString(raw)})
	tlsCfg, err := transport.ClientTLSConfig(transport.TLSFiles{CA: "deploy/certs/ca.crt", Cert: "deploy/certs/apid.crt", Key: "deploy/certs/apid.key"}, "localhost")
	if err != nil {
		return err
	}
	resp, err := transport.NewClient(tlsCfg, 30*time.Second).Post(*a.signerURL+"/v1/sign/tx", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	var rj signsvc.Rejection
	_ = json.Unmarshal(out, &rj)
	fmt.Printf("REQUEST_ID=%s\n승인 intent: %s(%s, %s, %s), 승인 %d건 %v\n보낸 calldata 수량: %s\n서명 서버 응답: HTTP %d 단계 %d %s\n",
		in.RequestID, in.Function, in.Args[0], in.Args[1], in.Args[2], len(apprs), approvers, calldataAmount, resp.StatusCode, rj.Step, rj.Code)
	if resp.StatusCode == http.StatusOK || rj.Code != want {
		return fmt.Errorf("기대한 거부(%s)가 아니다: %s", want, out)
	}
	return nil
}

func secret(name string) (string, error) {
	b, err := os.ReadFile(filepath.Join("deploy", "secrets", name))
	return strings.TrimSpace(string(b)), err
}

func open(user, pwFile, schema string) (*sql.DB, error) {
	pw, err := secret(pwFile)
	if err != nil {
		return nil, err
	}
	c := mysql.NewConfig()
	c.User, c.Passwd, c.Net, c.Addr, c.DBName, c.ParseTime = user, pw, "tcp", "127.0.0.1:3306", schema, true
	db, err := sql.Open("mysql", c.FormatDSN())
	if err != nil {
		return nil, err
	}
	return db, db.Ping()
}

func auditTamper(_ []string) error {
	ctx := context.Background()
	// ① 서버용 계정은 감사로그를 고칠 수 없다(추가 전용 권한, NFR-2)
	app, err := open("api_app", "api_app_password", "api")
	if err != nil {
		return err
	}
	defer app.Close()
	_, err = app.ExecContext(ctx, `UPDATE audit_log SET actor = 'attacker' WHERE seq = 1`)
	var me *mysql.MySQLError
	if !errors.As(err, &me) || me.Number != 1142 {
		return fmt.Errorf("api_app 의 audit_log UPDATE 가 거부되지 않았다: %v", err)
	}
	fmt.Printf("① 서버용 계정 api_app 의 audit_log UPDATE: 거부(MySQL %d)\n", me.Number)

	// ② 관리 계정이 고친 경우: 일회용 복사본에서 탐지
	root, err := open("root", "mysql_root_password", "")
	if err != nil {
		return err
	}
	defer root.Close()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	schema := "demo_tamper_" + hex.EncodeToString(b)
	if _, err := root.ExecContext(ctx, "CREATE DATABASE `"+schema+"`"); err != nil {
		return err
	}
	defer func() { _, _ = root.ExecContext(context.Background(), "DROP DATABASE `"+schema+"`") }()
	for _, q := range []string{"CREATE TABLE `" + schema + "`.audit_log LIKE api.audit_log", "INSERT INTO `" + schema + "`.audit_log SELECT * FROM api.audit_log"} {
		if _, err := root.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	copyDB, err := open("root", "mysql_root_password", schema)
	if err != nil {
		return err
	}
	defer copyDB.Close()
	verify := func() (audit.Result, error) {
		v := audit.NewVerifier()
		var from uint64 = 1
		for {
			recs, err := audit.Load(ctx, copyDB, from, 1000)
			if err != nil {
				return audit.Result{}, err
			}
			for _, r := range recs {
				v.Add(r)
			}
			if len(recs) < 1000 {
				return v.Result(), nil
			}
			from = recs[len(recs)-1].Seq + 1
		}
	}
	before, err := verify()
	if err != nil {
		return err
	}
	if !before.OK || before.Count < 3 {
		return fmt.Errorf("복사본 검증(변경 전): %+v", before)
	}
	target := before.HeadSeq / 2
	var action string
	_ = copyDB.QueryRowContext(ctx, `SELECT action FROM audit_log WHERE seq = ?`, target).Scan(&action)
	if _, err := copyDB.ExecContext(ctx, `UPDATE audit_log SET actor = CONCAT(actor, '-변조') WHERE seq = ?`, target); err != nil {
		return err
	}
	after, err := verify()
	if err != nil {
		return err
	}
	fmt.Printf("② 복사본(api.audit_log %d건) 검증: 변경 전 정상 → seq %d(%s)의 actor 를 관리 계정으로 고친 뒤 검증: ", before.Count, target, action)
	if after.OK || after.FirstBadSeq != target {
		fmt.Println("탐지 실패")
		return fmt.Errorf("변조를 seq %d 에서 탐지하지 못했다: %+v", target, after)
	}
	fmt.Printf("seq %d 에서 탐지(%s)\n", after.FirstBadSeq, after.Reason)
	return nil
}

func holdingSkew(args []string) error {
	fs := flag.NewFlagSet("holding-skew", flag.ExitOnError)
	account := fs.String("account", "", "계좌번호")
	security := fs.String("security", "", "종목 코드")
	delta := fs.Int64("delta", 0, "더할 수량(음수 가능)")
	_ = fs.Parse(args)
	db, err := open("api_app", "api_app_password", "api")
	if err != nil {
		return err
	}
	defer db.Close()
	res, err := db.Exec(`UPDATE holdings SET quantity = quantity + ? WHERE account_no = ? AND issue_code = ?`, *delta, *account, *security)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("보유 수량 행이 없다(%s, %s)", *account, *security)
	}
	var q string
	_ = db.QueryRow(`SELECT CAST(quantity AS CHAR) FROM holdings WHERE account_no = ? AND issue_code = ?`, *account, *security).Scan(&q)
	fmt.Printf("연계장부 %s %s 수량을 %+d 바꿈 → %s\n", *security, *account, *delta, q)
	return nil
}
