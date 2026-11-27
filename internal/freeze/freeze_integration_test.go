//go:build integration

// 통합 테스트: 동결·해제의 서명·권한·재전송 검사(T2.6). signer 스키마에 signer_app 으로 접속하고, 만든 행은 지운다.
package freeze

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func signerDB(t *testing.T) *sql.DB {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	pw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "deploy", "secrets", "signer_app_password"))
	if err != nil {
		t.Fatalf("비밀 파일(make up 필요): %v", err)
	}
	c := mysql.NewConfig()
	c.User, c.Passwd, c.Net, c.Addr, c.DBName = "signer_app", strings.TrimSpace(string(pw)), "tcp", "127.0.0.1:3306", "signer"
	c.ParseTime = true
	db, err := sql.Open("mysql", c.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type env struct {
	db     *sql.DB
	cfg    Config
	keys   map[string]ed25519.PrivateKey
	s      string
	target string
}

func setup(t *testing.T) *env {
	t.Helper()
	db := signerDB(t)
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	s := hex.EncodeToString(b)
	e := &env{db: db, s: s, keys: map[string]ed25519.PrivateKey{}, target: "it-key-" + s}
	group := "it-admins-" + s
	e.cfg = Config{AdminGroup: group, ReleaseApprovals: 2,
		TargetExists: func(_ context.Context, _ Scope, target string) (bool, error) {
			return strings.HasPrefix(target, "it-"), nil
		}}
	ids := []string{"it-sec1-" + s, "it-sec2-" + s, "it-apr-" + s}
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM freezes WHERE target LIKE ?", "it-%"+s)
		_, _ = db.Exec("DELETE FROM approver_groups WHERE group_id = ?", group)
		_, _ = db.Exec("DELETE FROM approvers WHERE approver_id IN (?, ?, ?)", ids[0], ids[1], ids[2])
	})
	for i, id := range ids {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		e.keys[id] = priv
		role := "SECURITY_ADMIN"
		if i == 2 {
			role = "APPROVER" // 보안관리자가 아닌 승인자
		}
		if _, err := db.Exec(`INSERT INTO approvers (approver_id, name, institution_id, role, ed25519_pubkey, status) VALUES (?, 'it', 'platform', ?, ?, 'ACTIVE')`, id, role, []byte(pub)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO approver_groups (group_id, approver_id) VALUES (?, ?)`, group, id); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func code(err error) string {
	var fe *Error
	if errors.As(err, &fe) {
		return fe.Code
	}
	if err != nil {
		return "?" + err.Error()
	}
	return ""
}

func TestFreezeAndRelease(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	now := time.Now()
	sec1, sec2, apr := "it-sec1-"+e.s, "it-sec2-"+e.s, "it-apr-"+e.s

	r := NewRequest(ScopeKey, e.target, "도난 의심", sec1, e.keys[sec1], now)
	if err := Freeze(ctx, e.db, e.cfg, r, "stoctl", now); err != nil {
		t.Fatal(err)
	}
	if c := code(Freeze(ctx, e.db, e.cfg, r, "stoctl", now)); c != CodeExists {
		t.Fatalf("같은 대상 재동결: %s", c)
	}
	// 대상 바꿔치기(서명은 원래 요청)
	tampered := r
	tampered.FreezeID = NewRequest(ScopeKey, "x", "x", sec1, e.keys[sec1], now).FreezeID
	tampered.Target = "it-other-" + e.s
	if c := code(Freeze(ctx, e.db, e.cfg, tampered, "stoctl", now)); c != CodeSignature {
		t.Fatalf("변조된 동결 요청: %s", c)
	}
	// 보안관리자가 아닌 승인자
	if c := code(Freeze(ctx, e.db, e.cfg, NewRequest(ScopeKey, "it-k2-"+e.s, "x", apr, e.keys[apr], now), "stoctl", now)); c != CodeAdmin {
		t.Fatalf("일반 승인자의 동결: %s", c)
	}
	// 오래된 요청(재전송)
	if c := code(Freeze(ctx, e.db, e.cfg, NewRequest(ScopeKey, "it-k3-"+e.s, "x", sec1, e.keys[sec1], now.Add(-10*time.Minute)), "stoctl", now)); c != CodeStale {
		t.Fatalf("오래된 동결 요청: %s", c)
	}

	// 해제: 1인 서명 거부, 같은 관리자 두 번 거부, 일반 승인자 거부, 동결 서명을 해제 서명으로 재사용 거부
	rel := NewRelease(r.FreezeID, now)
	rel.SignRelease(sec1, e.keys[sec1])
	if c := code(Release(ctx, e.db, e.cfg, rel, "stoctl", now)); c != CodeInsufficient {
		t.Fatalf("1인 해제: %s", c)
	}
	dup := rel
	dup.Approvals = append(append([]ReleaseSignature(nil), rel.Approvals...), rel.Approvals[0])
	if c := code(Release(ctx, e.db, e.cfg, dup, "stoctl", now)); c != CodeInvalid {
		t.Fatalf("같은 관리자 중복 서명: %s", c)
	}
	withApr := NewRelease(r.FreezeID, now)
	withApr.SignRelease(sec1, e.keys[sec1])
	withApr.SignRelease(apr, e.keys[apr])
	if c := code(Release(ctx, e.db, e.cfg, withApr, "stoctl", now)); c != CodeAdmin {
		t.Fatalf("일반 승인자가 낀 해제: %s", c)
	}
	cross := NewRelease(r.FreezeID, now)
	cross.SignRelease(sec1, e.keys[sec1])
	cross.Approvals = append(cross.Approvals, ReleaseSignature{AdminID: sec2, Signature: hex.EncodeToString(ed25519.Sign(e.keys[sec2], r.Message()))})
	if c := code(Release(ctx, e.db, e.cfg, cross, "stoctl", now)); c != CodeSignature {
		t.Fatalf("동결 서명을 해제 서명으로 재사용: %s", c)
	}

	ok := NewRelease(r.FreezeID, now)
	ok.SignRelease(sec1, e.keys[sec1])
	ok.SignRelease(sec2, e.keys[sec2])
	if err := Release(ctx, e.db, e.cfg, ok, "stoctl", now); err != nil {
		t.Fatalf("2인 해제: %v", err)
	}
	if c := code(Release(ctx, e.db, e.cfg, ok, "stoctl", now)); c != CodeReleased {
		t.Fatalf("이미 해제된 동결: %s", c)
	}
	// 해제 뒤 같은 동결 요청 재전송: freeze_id 재사용
	if c := code(Freeze(ctx, e.db, e.cfg, r, "stoctl", now)); c != CodeReplay {
		t.Fatalf("동결 요청 재전송: %s", c)
	}
	// 같은 release_id 를 다른 동결 해제에 재사용
	r2 := NewRequest(ScopeKey, "it-k4-"+e.s, "x", sec1, e.keys[sec1], now)
	if err := Freeze(ctx, e.db, e.cfg, r2, "stoctl", now); err != nil {
		t.Fatal(err)
	}
	reuse := ok
	reuse.FreezeID = r2.FreezeID
	reuse.Approvals = nil
	reuse.SignRelease(sec1, e.keys[sec1])
	reuse.SignRelease(sec2, e.keys[sec2])
	if c := code(Release(ctx, e.db, e.cfg, reuse, "stoctl", now)); c != CodeReplay {
		t.Fatalf("release_id 재사용: %s", c)
	}
}
