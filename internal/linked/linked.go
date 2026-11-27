// Package linked 는 연계장부(모의 계좌·보유 수량)다(설계서 11절, FR-7.1, D-7, D-22).
//
// 계좌는 업무 서버가 무작위 20바이트 주소와 함께 만들고(개인키 없음, D-7) PENDING 으로 둔다. 같은 DB 트랜잭션에서
// 지정한 종목에 registerAccount(주소, 기관 ID) 요청을 기안한다. 원장에는 주소와 기관 ID 만 가고 권리자 이름·계좌번호는
// 가지 않는다(E-2-1). 보유 수량은 이벤트 수신 작업자가 이벤트를 저장하는 같은 트랜잭션에서 ApplyEvent 로 갱신한다.
package linked

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/go-sql-driver/mysql"
	"github.com/oklog/ulid/v2"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/store"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
)

// 계좌 상태
const (
	StatusPending = "PENDING" // 원장 등록 전
	StatusActive  = "ACTIVE"  // 원장의 AccountRegistered 를 보존함
)

// 오류 코드
const (
	CodeBadRequest      = "ACCOUNT_INVALID"
	CodeExists          = "ACCOUNT_EXISTS"
	CodeNotFound        = "ACCOUNT_NOT_FOUND"
	CodeSecurityUnknown = "SECURITY_NOT_FOUND"
)

// 원장 함수(설계서 10.2)
const fnRegister = "registerAccount(address,string)"

// Account 는 연계장부 계좌다.
type Account struct {
	AccountNo      string    `json:"account_no"`
	InstitutionID  string    `json:"institution_id"`
	HolderName     string    `json:"holder_name"` // 모의 권리자 이름. 원장에 올리지 않는다
	OnchainAddress string    `json:"onchain_address"`
	Status         string    `json:"status"`
	Holdings       []Holding `json:"holdings"`
}

// Holding 은 계좌·종목별 보유 수량이다(10진 문자열).
type Holding struct {
	AccountNo string `json:"account_no"`
	IssueCode string `json:"issue_code"`
	Quantity  string `json:"quantity"`
}

// RegisterInput 은 계좌 등록 요청이다(POST /v1/accounts).
type RegisterInput struct {
	AccountNo     string `json:"account_no"` // 비우면 업무 서버가 만든다
	InstitutionID string `json:"institution_id"`
	HolderName    string `json:"holder_name"`
	IssueCode     string `json:"issue_code"`
	DrafterID     string `json:"drafter_id"`
}

// Service 는 연계장부 처리다.
type Service struct {
	DB       *sql.DB
	WF       *workflow.Service
	LedgerID string
}

var accountRe = regexp.MustCompile(`^[A-Z0-9][A-Z0-9-]{3,31}$`)

func bad(status int, code, format string, a ...any) error {
	return &workflow.Error{Status: status, Code: code, Msg: fmt.Sprintf(format, a...)}
}

// newAddress 는 무작위 20바이트 주소다(개인키 없음, D-7).
func newAddress() (common.Address, error) {
	var a common.Address
	if _, err := rand.Read(a[:]); err != nil {
		return a, err
	}
	return a, nil
}

func (s *Service) contractOf(ctx context.Context, issueCode string) (string, error) {
	var c sql.NullString
	err := s.DB.QueryRowContext(ctx, `SELECT contract_address FROM securities WHERE issue_code = ? AND ledger_id = ?`, issueCode, s.LedgerID).Scan(&c)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !c.Valid) {
		return "", bad(404, CodeSecurityUnknown, "종목 %s 가 없다", issueCode)
	}
	return c.String, err
}

func (s *Service) draftRegistration(ctx context.Context, institutionID, contract string, addr common.Address, drafter string,
	extra func(ctx context.Context, tx *sql.Tx, requestID string) error) (*workflow.Request, error) {
	return s.WF.DraftWith(ctx, workflow.DraftInput{InstitutionID: institutionID, KeyPurpose: "TRANSFER", Contract: contract,
		Function: fnRegister, Args: []string{addr.Hex(), institutionID}, DrafterID: drafter}, extra)
}

// Register 는 계좌를 만들고 그 종목에 원장 계좌 등록 요청을 기안한다(같은 트랜잭션).
func (s *Service) Register(ctx context.Context, in RegisterInput) (*Account, *workflow.Request, error) {
	if in.AccountNo == "" {
		in.AccountNo = "AC-" + ulid.Make().String()
	}
	if !accountRe.MatchString(in.AccountNo) {
		return nil, nil, bad(400, CodeBadRequest, "account_no 는 대문자·숫자·하이픈 4~32자다")
	}
	in.HolderName = strings.TrimSpace(in.HolderName)
	if in.HolderName == "" || utf8.RuneCountInString(in.HolderName) > 64 {
		return nil, nil, bad(400, CodeBadRequest, "holder_name 은 1~64자다")
	}
	if in.InstitutionID == "" || in.IssueCode == "" || in.DrafterID == "" {
		return nil, nil, bad(400, CodeBadRequest, "institution_id, issue_code, drafter_id 가 필요하다")
	}
	contract, err := s.contractOf(ctx, in.IssueCode)
	if err != nil {
		return nil, nil, err
	}
	addr, err := newAddress()
	if err != nil {
		return nil, nil, err
	}
	req, err := s.draftRegistration(ctx, in.InstitutionID, contract, addr, in.DrafterID, func(ctx context.Context, tx *sql.Tx, requestID string) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO accounts (account_no, institution_id, holder_name, onchain_address, status) VALUES (?, ?, ?, ?, ?)`,
			in.AccountNo, in.InstitutionID, in.HolderName, addr.Hex(), StatusPending); err != nil {
			var me *mysql.MySQLError
			if errors.As(err, &me) && me.Number == 1062 {
				return bad(409, CodeExists, "계좌 %s 가 이미 있다", in.AccountNo)
			}
			return err
		}
		// 권리자 이름은 감사 payload 에 넣지 않는다(허용 키에도 없다).
		_, err := audit.Append(ctx, tx, audit.Entry{Actor: in.DrafterID, Action: "ACCOUNT_CREATED", Subject: in.AccountNo, Payload: map[string]any{
			"account_no": in.AccountNo, "institution_id": in.InstitutionID, "address": addr.Hex(), "issue_code": in.IssueCode,
			"request_id": requestID, "status": StatusPending,
		}})
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	acc, err := s.Get(ctx, in.AccountNo)
	return acc, req, err
}

// AddRegistration 은 기존 계좌를 다른 종목에 등록하는 요청을 기안한다.
func (s *Service) AddRegistration(ctx context.Context, accountNo, issueCode, drafter string) (*workflow.Request, error) {
	acc, err := s.Get(ctx, accountNo)
	if err != nil {
		return nil, err
	}
	if issueCode == "" || drafter == "" {
		return nil, bad(400, CodeBadRequest, "issue_code, drafter_id 가 필요하다")
	}
	contract, err := s.contractOf(ctx, issueCode)
	if err != nil {
		return nil, err
	}
	return s.draftRegistration(ctx, acc.InstitutionID, contract, common.HexToAddress(acc.OnchainAddress), drafter, nil)
}

// Get 은 계좌 하나와 보유 수량이다.
func (s *Service) Get(ctx context.Context, accountNo string) (*Account, error) {
	var a Account
	err := s.DB.QueryRowContext(ctx, `SELECT account_no, institution_id, holder_name, onchain_address, status FROM accounts WHERE account_no = ?`, accountNo).
		Scan(&a.AccountNo, &a.InstitutionID, &a.HolderName, &a.OnchainAddress, &a.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, bad(404, CodeNotFound, "계좌 %s 가 없다", accountNo)
	}
	if err != nil {
		return nil, err
	}
	if a.Holdings, err = Holdings(ctx, s.DB, "", accountNo); err != nil {
		return nil, err
	}
	return &a, nil
}

// List 는 계좌 목록이다(institution 이 비어 있지 않으면 그 기관만). 보유 수량은 넣지 않는다.
func List(ctx context.Context, db store.DBTX, institution string) ([]Account, error) {
	q := `SELECT account_no, institution_id, holder_name, onchain_address, status FROM accounts`
	var args []any
	if institution != "" {
		q += ` WHERE institution_id = ?`
		args = append(args, institution)
	}
	rows, err := db.QueryContext(ctx, q+` ORDER BY account_no`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Account{}
	for rows.Next() {
		var a Account
		if err := rows.Scan(&a.AccountNo, &a.InstitutionID, &a.HolderName, &a.OnchainAddress, &a.Status); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Holdings 는 보유 수량이다(issueCode·accountNo 가 비어 있지 않으면 그것만).
func Holdings(ctx context.Context, db store.DBTX, issueCode, accountNo string) ([]Holding, error) {
	q := `SELECT account_no, issue_code, CAST(quantity AS CHAR) FROM holdings WHERE 1 = 1`
	var args []any
	if issueCode != "" {
		q += ` AND issue_code = ?`
		args = append(args, issueCode)
	}
	if accountNo != "" {
		q += ` AND account_no = ?`
		args = append(args, accountNo)
	}
	rows, err := db.QueryContext(ctx, q+` ORDER BY issue_code, account_no`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Holding{}
	for rows.Next() {
		var h Holding
		if err := rows.Scan(&h.AccountNo, &h.IssueCode, &h.Quantity); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ApplyEvent 는 보존하는 원장 이벤트 하나를 연계장부에 반영한다. 이벤트를 저장하는 같은 트랜잭션에서 부른다(registry.Worker.Apply).
// 등록되지 않은 종목, 연계장부에 없는 주소는 반영하지 않는다(오류가 아니다: 이벤트 수신이 멈추면 안 된다).
func ApplyEvent(ctx context.Context, tx store.DBTX, ledgerID string, ev ledger.Event) error {
	var issueCode string
	err := tx.QueryRowContext(ctx, `SELECT issue_code FROM securities WHERE ledger_id = ? AND contract_address = ?`, ledgerID, ev.Raw.Address.Hex()).Scan(&issueCode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	p := ev.Payload
	switch ev.Name {
	case "AccountRegistered":
		_, err := tx.ExecContext(ctx, `UPDATE accounts SET status = ? WHERE onchain_address = ? AND institution_id = ? AND status = ?`,
			StatusActive, addr(p["account"]), p["institutionId"], StatusPending)
		return err
	case "Issued":
		return add(ctx, tx, issueCode, p["account"], p["amount"], false)
	case "Redeemed":
		return add(ctx, tx, issueCode, p["account"], p["amount"], true)
	case "Transferred":
		if err := add(ctx, tx, issueCode, p["from"], p["amount"], true); err != nil {
			return err
		}
		return add(ctx, tx, issueCode, p["to"], p["amount"], false)
	}
	return nil
}

func addr(s string) string { return common.HexToAddress(s).Hex() }

// add 는 연계장부 계좌(주소)의 수량에 amount 를 더하거나 뺀다. 계좌가 없으면 아무것도 하지 않는다.
func add(ctx context.Context, tx store.DBTX, issueCode, address, amount string, negate bool) error {
	v, ok := new(big.Int).SetString(amount, 10)
	if !ok || v.Sign() < 0 {
		return fmt.Errorf("linked: 수량 %q 형식", amount)
	}
	if negate {
		v.Neg(v)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO holdings (account_no, issue_code, quantity)
		SELECT * FROM (SELECT a.account_no, ? AS issue_code, CAST(? AS DECIMAL(65,0)) AS q FROM accounts a WHERE a.onchain_address = ?) AS n
		ON DUPLICATE KEY UPDATE quantity = holdings.quantity + n.q`, issueCode, v.String(), addr(address))
	if err != nil {
		return fmt.Errorf("linked: 보유 수량 갱신(%s, %s): %w", issueCode, addr(address), err)
	}
	return nil
}
