//go:build integration

// 통합 테스트: 정책 변경(화이트리스트 추가, D-22)의 승인 검증, 재전송 방지, 대상 정책 조건, 원자성, 감사 기록.
// MySQL(signer 스키마)에 signer_app 으로 접속한다. 만든 행은 시험이 끝나면 지운다(감사 기록은 추가 전용이라 남는다).
package policychange

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/go-sql-driver/mysql"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyops"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/policy"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	pw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "deploy", "secrets", "signer_app_password"))
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
		t.Fatalf("DB 접속: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type fx struct {
	db     *sql.DB
	ex     *Executor
	s      string
	admins map[string]ed25519.PrivateKey
}

func (f *fx) id(short string) string { return "it-" + short + "-" + f.s }

func setup(t *testing.T) *fx {
	t.Helper()
	db := openDB(t)
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	s := hex.EncodeToString(b)
	f := &fx{db: db, s: s, admins: map[string]ed25519.PrivateKey{}}
	group := "it-sec-" + s
	type ap struct{ id, role, status, group string }
	for _, a := range []ap{{"s1", "SECURITY_ADMIN", "ACTIVE", group}, {"s2", "SECURITY_ADMIN", "ACTIVE", group},
		{"x1", "APPROVER", "ACTIVE", group}, {"s4", "SECURITY_ADMIN", "DISABLED", group}} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		f.admins[a.id] = priv
		if _, err := db.Exec(`INSERT INTO approvers (approver_id, name, institution_id, role, ed25519_pubkey, status) VALUES (?, 'it', 'platform', ?, ?, ?)`,
			f.id(a.id), a.role, []byte(pub), a.status); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO approver_groups (group_id, approver_id) VALUES (?, ?)`, a.group, f.id(a.id)); err != nil {
			t.Fatal(err)
		}
	}
	// 화이트리스트를 쓰는 정책 두 개(wl1, wl2), 쓰지 않는 정책(nowl), 비활성 정책(old)
	body := func(wl bool) string {
		return fmt.Sprintf(`{"allowed_functions":["issue(address,uint256)"],"max_amount":"100","recipient_whitelist":%v,"required_approvals":2,"approver_group":"g","gas_limit_cap":500000}`, wl)
	}
	for _, p := range []struct {
		id, status string
		wl         bool
	}{{"wl1", "ACTIVE", true}, {"wl2", "ACTIVE", true}, {"nowl", "ACTIVE", false}, {"old", "RETIRED", true}} {
		if _, err := policy.ParseBody([]byte(body(p.wl))); err != nil {
			t.Fatalf("시험 정책 본문: %v", err)
		}
		if _, err := db.Exec(`INSERT INTO policies (policy_id, version, ledger_id, institution_id, key_purpose, body_json, status) VALUES (?, 1, ?, ?, 'ISSUE', ?, ?)`,
			f.id(p.id), "it-led-"+s, "it-inst-"+p.id+"-"+s, body(p.wl), p.status); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM whitelists WHERE policy_id LIKE ?", "it-%-"+s)
		_, _ = db.Exec("DELETE FROM policies WHERE policy_id LIKE ?", "it-%-"+s)
		_, _ = db.Exec("DELETE FROM policy_changes WHERE policy_ids LIKE ?", "%-"+s+"%")
		_, _ = db.Exec("DELETE FROM approver_groups WHERE group_id = ?", group)
		_, _ = db.Exec("DELETE FROM approvers WHERE approver_id LIKE ?", "it-%-"+s)
	})
	f.ex = &Executor{DB: db, AdminGroup: group, Approvals: 2}
	return f
}

func randAddr() common.Address {
	var a common.Address
	_, _ = rand.Read(a[:])
	return a
}

func (f *fx) req(addr common.Address, pols []string, signers ...string) Request {
	var ids []string
	for _, p := range pols {
		ids = append(ids, f.id(p))
	}
	r := NewWhitelistAdd(ids, addr, "시험", time.Now())
	for _, s := range signers {
		r.Sign(f.id(s), f.admins[s])
	}
	return r
}

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return fmt.Sprintf("(코드 없음: %v)", err)
}

func (f *fx) listed(t *testing.T, pol string, addr common.Address) bool {
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM whitelists WHERE policy_id = ? AND account_address = ?`, f.id(pol), addr.Hex()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func (f *fx) audits(t *testing.T, action, subject string) int {
	var n int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = ? AND subject = ?`, action, subject).Scan(&n)
	return n
}

// 보안관리자 2명이 서명하면 여러 정책에 한 번에 들어가고, 정책 평가(policy.Load)에서 보인다. 같은 change_id 는 다시 쓸 수 없다.
func TestWhitelistAdd(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	addr := randAddr()
	r := f.req(addr, []string{"wl1", "wl2"}, "s1", "s2")
	res, err := f.ex.Execute(ctx, r, "stoctl", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 2 || !f.listed(t, "wl1", addr) || !f.listed(t, "wl2", addr) {
		t.Fatalf("추가 결과 %+v", res)
	}
	p, err := policy.Lookup(ctx, f.db, "it-led-"+f.s, "it-inst-wl1-"+f.s, "ISSUE")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range p.Whitelist {
		found = found || w == addr.Hex()
	}
	if !found {
		t.Fatalf("정책 평가에 추가한 주소가 없다: %v", p.Whitelist)
	}
	if f.audits(t, "POLICY_WHITELIST_ADDED", addr.Hex()) != 1 {
		t.Fatal("감사 기록 POLICY_WHITELIST_ADDED 가 없다")
	}
	if _, err := f.ex.Execute(ctx, r, "stoctl", time.Now()); code(err) != CodeReplay {
		t.Fatalf("재전송: %v", err)
	}
	// 이미 있는 주소를 다시 추가하면 성공하되 새로 들어간 정책 수는 0
	res, err = f.ex.Execute(ctx, f.req(addr, []string{"wl1"}, "s1", "s2"), "stoctl", time.Now())
	if err != nil || res.Added != 0 {
		t.Fatalf("중복 추가: %+v %v", res, err)
	}
}

// 거부 사례: 하나라도 거부되면 어떤 정책에도 들어가지 않고 감사로그에 POLICY_CHANGE_REJECTED 가 남는다.
func TestWhitelistAddRejections(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	tampered := func() Request {
		r := f.req(randAddr(), []string{"wl1"}, "s1", "s2")
		r.Address = randAddr().Hex() // 서명 뒤 주소 바꿔치기
		return r
	}
	keyopSig := func() Request {
		// 키 작업 서명(도메인 sto-keyop-v1)을 정책 변경에 붙여도 통하지 않는다
		r := f.req(randAddr(), []string{"wl1"})
		k := keyops.New(keyops.TypeDestroy, time.Now())
		k.OpID, k.KeyID, k.Reason, k.RequestedAt = r.ChangeID, "x", r.Reason, r.RequestedAt
		k.Sign(f.id("s1"), f.admins["s1"])
		k.Sign(f.id("s2"), f.admins["s2"])
		r.Approvals = k.Approvals
		return r
	}
	stale := func() Request {
		r := NewWhitelistAdd([]string{f.id("wl1")}, randAddr(), "시험", time.Now().Add(-10*time.Minute))
		r.Sign(f.id("s1"), f.admins["s1"])
		r.Sign(f.id("s2"), f.admins["s2"])
		return r
	}
	unsorted := func() Request {
		r := f.req(randAddr(), nil)
		r.PolicyIDs = []string{f.id("wl2"), f.id("wl1")}
		r.Sign(f.id("s1"), f.admins["s1"])
		r.Sign(f.id("s2"), f.admins["s2"])
		return r
	}
	lower := func() Request {
		r := f.req(randAddr(), nil)
		r.PolicyIDs = []string{f.id("wl1")}
		r.Address = strings.ToLower(r.Address)
		r.Sign(f.id("s1"), f.admins["s1"])
		r.Sign(f.id("s2"), f.admins["s2"])
		return r
	}
	cases := []struct {
		name string
		r    Request
		want string
	}{
		{"보안관리자 1명", f.req(randAddr(), []string{"wl1"}, "s1"), CodeInsufficient},
		{"같은 보안관리자 두 번", f.req(randAddr(), []string{"wl1"}, "s1", "s1"), CodeInvalid},
		{"보안관리자가 아닌 승인자", f.req(randAddr(), []string{"wl1"}, "s1", "x1"), CodeAdmin},
		{"비활성 보안관리자", f.req(randAddr(), []string{"wl1"}, "s1", "s4"), CodeAdmin},
		{"서명 뒤 주소 변경", tampered(), CodeSignature},
		{"키 작업 서명 재사용", keyopSig(), CodeSignature},
		{"오래된 요청", stale(), CodeStale},
		{"정렬되지 않은 정책 목록", unsorted(), CodeInvalid},
		{"EIP-55 아닌 주소", lower(), CodeInvalid},
		{"화이트리스트를 쓰지 않는 정책 포함", f.req(randAddr(), []string{"wl1", "nowl"}, "s1", "s2"), CodePolicy},
		{"비활성 정책", f.req(randAddr(), []string{"old"}, "s1", "s2"), CodePolicy},
		{"없는 정책", f.req(randAddr(), []string{"none"}, "s1", "s2"), CodePolicy},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := f.ex.Execute(ctx, c.r, "stoctl", time.Now())
			if code(err) != c.want {
				t.Fatalf("기대 %s, 받은 %v", c.want, err)
			}
			if f.listed(t, "wl1", common.HexToAddress(c.r.Address)) {
				t.Fatal("거부된 변경이 화이트리스트에 들어갔다")
			}
			if f.audits(t, "POLICY_CHANGE_REJECTED", c.r.ChangeID) != 1 {
				t.Fatal("거부 감사 기록이 없다")
			}
		})
	}
}
