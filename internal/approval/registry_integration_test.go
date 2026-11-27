//go:build integration

// 통합 테스트: 서명 서버 승인자 명부 대조(T2.2). 모든 쓰기는 롤백한다.
package approval

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
)

func signerTx(t *testing.T) *sql.Tx {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	pw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "deploy", "secrets", "signer_app_password"))
	if err != nil {
		t.Fatalf("비밀 파일(make up 필요): %v", err)
	}
	c := mysql.NewConfig()
	c.User, c.Passwd, c.Net, c.Addr, c.DBName = "signer_app", strings.TrimSpace(string(pw)), "tcp", "127.0.0.1:3306", "signer"
	db, err := sql.Open("mysql", c.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("DB 접속(make up 필요): %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	return tx
}

func TestVerifyOneAgainstRegistry(t *testing.T) {
	ctx := context.Background()
	tx := signerTx(t)
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	s := hex.EncodeToString(b)
	active, inactive := "it-apr-on-"+s, "it-apr-off-"+s
	pubOn, privOn := keys(t)
	pubOff, privOff := keys(t)
	for id, v := range map[string][2]any{active: {[]byte(pubOn), "ACTIVE"}, inactive: {[]byte(pubOff), "DISABLED"}} {
		if _, err := tx.Exec(`INSERT INTO approvers (approver_id, name, institution_id, role, ed25519_pubkey, status) VALUES (?, 'it', 'it-inst', 'APPROVER', ?, ?)`,
			id, v[0], v[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO approver_groups (group_id, approver_id) VALUES ('it-grp', ?)`, active); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("intent"))
	sign := func(priv []byte, d Decision) string {
		sig, _ := Sign(priv, h, d)
		return hex.EncodeToString(sig)
	}
	ap, err := VerifyOne(ctx, tx, Approval{ApproverID: active, Decision: Approve, Signature: sign(privOn, Approve)}, h)
	if err != nil || ap.InstitutionID != "it-inst" || len(ap.Groups) != 1 || ap.Groups[0] != "it-grp" {
		t.Fatalf("정상 승인: %+v %v", ap, err)
	}
	code := func(err error) string {
		var e *Error
		if errors.As(err, &e) {
			return e.Code
		}
		return ""
	}
	cases := []struct {
		name string
		a    Approval
		want string
	}{
		{"등록되지 않은 승인자", Approval{ApproverID: "it-nobody-" + s, Decision: Approve, Signature: sign(privOn, Approve)}, CodeUnknownApprover},
		{"비활성 승인자", Approval{ApproverID: inactive, Decision: Approve, Signature: sign(privOff, Approve)}, CodeApproverInactive},
		{"위조 서명(다른 키)", Approval{ApproverID: active, Decision: Approve, Signature: sign(privOff, Approve)}, CodeInvalidSignature},
		{"반려 서명을 승인으로", Approval{ApproverID: active, Decision: Approve, Signature: sign(privOn, Reject)}, CodeInvalidSignature},
		{"서명 형식 오류", Approval{ApproverID: active, Decision: Approve, Signature: "zz"}, CodeInvalidSignature},
	}
	for _, c := range cases {
		if _, err := VerifyOne(ctx, tx, c.a, h); code(err) != c.want {
			t.Errorf("%s: %v (기대 %s)", c.name, err, c.want)
		}
	}
	other := sha256.Sum256([]byte("other intent"))
	if _, err := VerifyOne(ctx, tx, Approval{ApproverID: active, Decision: Approve, Signature: sign(privOn, Approve)}, other); code(err) != CodeInvalidSignature {
		t.Errorf("다른 intent 에 서명 재사용: %v", err)
	}
}
