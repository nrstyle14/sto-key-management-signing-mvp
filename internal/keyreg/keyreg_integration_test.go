//go:build integration

// 통합 테스트: 키 레지스트리의 (원장, 기관, 용도) 조회와 상태 전이(T1.4).
// 호스트에서 MySQL(make up && make migrate)에 signer_app 으로 접속한다. 모든 쓰기는 롤백한다.
package keyreg

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-sql-driver/mysql"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

func openSigner(t *testing.T) *sql.DB {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	pw, err := os.ReadFile(filepath.Join(root, "deploy", "secrets", "signer_app_password"))
	if err != nil {
		t.Fatalf("비밀 파일(make up 필요): %v", err)
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr, cfg.DBName = "signer_app", strings.TrimSpace(string(pw)), "tcp", "127.0.0.1:3306", "signer"
	cfg.ParseTime = true
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("DB 접속(make up && make migrate 필요): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func rid() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func pubKey(t *testing.T) signer.PublicKey {
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return crypto.FromECDSAPub(&k.PublicKey)
}

// fixture 는 롤백되는 트랜잭션 안에 원장 하나와 기관 A·B 토큰, 키를 만든다.
type fixture struct {
	tx                      *sql.Tx
	ledger, instA, instB    string
	keyAIssue, keyBTransfer string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	db := openSigner(t)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	s := rid()
	f := &fixture{tx: tx, ledger: "it-ledger-" + s, instA: "it-a-" + s, instB: "it-b-" + s,
		keyAIssue: "it-a-issue-" + s, keyBTransfer: "it-b-transfer-" + s}
	for _, inst := range []string{f.instA, f.instB} {
		if err := RegisterToken(ctx, tx, Token{TokenID: f.ledger + "." + inst, Label: "it-" + inst, LedgerID: f.ledger, InstitutionID: inst}); err != nil {
			t.Fatal(err)
		}
	}
	if err := RegisterKey(ctx, tx, Key{KeyID: f.keyAIssue, TokenID: f.ledger + "." + f.instA, Purpose: signer.PurposeIssue, PublicKey: pubKey(t)}); err != nil {
		t.Fatal(err)
	}
	if err := RegisterKey(ctx, tx, Key{KeyID: f.keyBTransfer, TokenID: f.ledger + "." + f.instB, Purpose: signer.PurposeTransfer, PublicKey: pubKey(t)}); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLookupReturnsOwnInstitutionKey(t *testing.T) {
	f := setup(t)
	k, err := Lookup(context.Background(), f.tx, f.ledger, f.instA, signer.PurposeIssue)
	if err != nil {
		t.Fatal(err)
	}
	if k.KeyID != f.keyAIssue || k.InstitutionID != f.instA || k.Class != signer.ClassOperational || k.TokenLabel != "it-"+f.instA {
		t.Fatalf("잘못된 키: %+v", k)
	}
}

// 기관 A 의 요청으로 기관 B 의 키를 얻을 수 없다(FR-2.1).
func TestLookupCannotReachOtherInstitutionKey(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	// 기관 B 에는 TRANSFER 키가 있지만, 기관 A 로 TRANSFER 를 찾으면 나오지 않아야 한다.
	if k, err := Lookup(ctx, f.tx, f.ledger, f.instA, signer.PurposeTransfer); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("기관 A 요청으로 키가 나왔다: %+v %v", k, err)
	}
	// 반대로 기관 B 로 ISSUE 를 찾아도 기관 A 의 ISSUE 키가 나오지 않는다.
	if k, err := Lookup(ctx, f.tx, f.ledger, f.instB, signer.PurposeIssue); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("기관 B 요청으로 기관 A 키가 나왔다: %+v %v", k, err)
	}
	// 다른 원장으로는 같은 기관의 키도 나오지 않는다.
	if k, err := Lookup(ctx, f.tx, "other-ledger", f.instA, signer.PurposeIssue); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("다른 원장 요청으로 키가 나왔다: %+v %v", k, err)
	}
}

// 용도가 다른 키는 얻을 수 없다(FR-2.2).
func TestLookupCannotReachOtherPurposeKey(t *testing.T) {
	f := setup(t)
	for _, p := range []signer.Purpose{signer.PurposeTransfer, signer.PurposeContractAdmin, signer.PurposeEmergency, signer.PurposeAudit} {
		if k, err := Lookup(context.Background(), f.tx, f.ledger, f.instA, p); !errors.Is(err, ErrNoActiveKey) {
			t.Fatalf("용도 %s 로 키가 나왔다: %+v %v", p, k, err)
		}
	}
}

func TestStatusTransitionsAndLookup(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if err := SetStatus(ctx, f.tx, f.keyAIssue, StatusActive, StatusDestroyed); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("ACTIVE → DESTROYED 가 허용됐다: %v", err)
	}
	if err := SetStatus(ctx, f.tx, f.keyAIssue, StatusActive, StatusFrozen); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(ctx, f.tx, f.ledger, f.instA, signer.PurposeIssue); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("FROZEN 키가 조회됐다: %v", err)
	}
	if err := SetStatus(ctx, f.tx, f.keyAIssue, StatusActive, StatusRetired); !errors.Is(err, ErrStatusChanged) {
		t.Fatalf("이미 바뀐 상태에서 전이가 됐다: %v", err)
	}
	if err := SetStatus(ctx, f.tx, f.keyAIssue, StatusFrozen, StatusActive); err != nil {
		t.Fatal(err)
	}
	if err := SetStatus(ctx, f.tx, f.keyAIssue, StatusActive, StatusRetired); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(ctx, f.tx, f.ledger, f.instA, signer.PurposeIssue); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("RETIRED 키가 조회됐다: %v", err)
	}
	if err := SetStatus(ctx, f.tx, f.keyAIssue, StatusRetired, StatusDestroyed); err != nil {
		t.Fatal(err)
	}
	k, err := Get(ctx, f.tx, f.keyAIssue)
	if err != nil || k.Status != StatusDestroyed {
		t.Fatalf("%+v %v", k, err)
	}
}

func TestRegisterKeyRejectsWrongClassAndAddress(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	err := RegisterKey(ctx, f.tx, Key{KeyID: "x-" + rid(), TokenID: f.ledger + "." + f.instA, Purpose: signer.PurposeIssue,
		Class: signer.ClassRoot, PublicKey: pubKey(t)})
	if !errors.Is(err, ErrClassMismatch) {
		t.Fatalf("운영 용도의 키가 ROOT 부류로 등록됐다: %v", err)
	}
	other, _ := pubKey(t).Address()
	err = RegisterKey(ctx, f.tx, Key{KeyID: "y-" + rid(), TokenID: f.ledger + "." + f.instA, Purpose: signer.PurposeIssue,
		PublicKey: pubKey(t), Address: other})
	if !errors.Is(err, ErrAddressMismatch) {
		t.Fatalf("공개키와 다른 주소가 등록됐다: %v", err)
	}
}

func TestLookupAmbiguous(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if err := RegisterKey(ctx, f.tx, Key{KeyID: "dup-" + rid(), TokenID: f.ledger + "." + f.instA, Purpose: signer.PurposeIssue, PublicKey: pubKey(t)}); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(ctx, f.tx, f.ledger, f.instA, signer.PurposeIssue); !errors.Is(err, ErrAmbiguousKey) {
		t.Fatalf("ACTIVE 키 둘 중 하나가 임의로 선택됐다: %v", err)
	}
}

type noHSM struct{ t *testing.T }

func (n noHSM) Generate(context.Context, signer.KeySpec) (signer.PublicKey, error) {
	n.t.Fatal("이미 초기화된 DB 에서 HSM 키 생성이 호출됐다")
	return nil, nil
}
func (n noHSM) DestroyIn(context.Context, string, string) error {
	n.t.Fatal("이미 초기화된 DB 에서 HSM 키 삭제가 호출됐다")
	return nil
}

// make up 으로 부트스트랩된 DB 에 두 번째 부트스트랩을 시도하면 HSM 에 손대지 않고 거부된다.
func TestSecondBootstrapIsRejected(t *testing.T) {
	db := openSigner(t)
	scopes := map[string]TokenScope{"besu-local.inst-a": {Label: "besu-local.inst-a", LedgerID: "besu-local", InstitutionID: "inst-a"}}
	f := &BootstrapFile{
		Tokens: []BootstrapToken{{Label: "besu-local.inst-a"}},
		Keys:   []BootstrapKey{{KeyID: "never-" + rid(), Token: "besu-local.inst-a", Purpose: signer.PurposeIssue}},
	}
	if _, err := ApplyBootstrap(context.Background(), db, noHSM{t}, f, scopes); !errors.Is(err, ErrAlreadyBootstrapped) {
		t.Fatalf("두 번째 부트스트랩이 거부되지 않았다: %v", err)
	}
}

// 부트스트랩의 DB 기록(토큰, 키, 승인자·그룹, 정책)을 롤백되는 트랜잭션에서 실행해 확인한다.
func TestBootstrapInsertsAllSections(t *testing.T) {
	ctx := context.Background()
	db := openSigner(t)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	s := rid()
	label := "it-boot-" + s
	scopes := map[string]TokenScope{label: {Label: label, LedgerID: "it-ledger-" + s, InstitutionID: "it-inst-" + s}}
	f := &BootstrapFile{
		Tokens: []BootstrapToken{{Label: label}},
		Keys:   []BootstrapKey{{KeyID: "it-boot-key-" + s, Token: label, Purpose: signer.PurposeIssue}},
		Approvers: []BootstrapApprover{{ApproverID: "it-apr-" + s, Name: "시험 승인자", InstitutionID: "it-inst-" + s, Role: "APPROVER",
			Ed25519Pubkey: hex.EncodeToString(make([]byte, 31)) + s[:2], Groups: []string{"it-grp-" + s}}},
		Policies: []BootstrapPolicy{{PolicyID: "it-pol-" + s, LedgerID: "it-ledger-" + s, InstitutionID: "it-inst-" + s, KeyPurpose: signer.PurposeIssue,
			Body: map[string]any{"required_approvals": 2, "allowed_functions": []any{"issue(address,uint256)"}}}},
	}
	if err := f.Validate(scopes); err != nil {
		t.Fatal(err)
	}
	keys := []GeneratedKey{{KeyID: f.Keys[0].KeyID, Token: label, Purpose: signer.PurposeIssue, PublicKey: pubKey(t)}}
	if err := insertBootstrap(ctx, tx, f, keys, scopes); err != nil {
		t.Fatal(err)
	}
	k, err := Lookup(ctx, tx, "it-ledger-"+s, "it-inst-"+s, signer.PurposeIssue)
	if err != nil || k.KeyID != f.Keys[0].KeyID {
		t.Fatalf("키 조회: %+v %v", k, err)
	}
	var n int
	var body string
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM approvers a JOIN approver_groups g USING (approver_id) WHERE a.approver_id = ? AND g.group_id = ?`,
		"it-apr-"+s, "it-grp-"+s).Scan(&n); err != nil || n != 1 {
		t.Fatalf("승인자·그룹: n=%d err=%v", n, err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT body_json FROM policies WHERE policy_id = ? AND version = 1`, "it-pol-"+s).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if body != `{"allowed_functions":["issue(address,uint256)"],"required_approvals":2}` {
		t.Fatalf("정책 본문: %s", body)
	}
}
