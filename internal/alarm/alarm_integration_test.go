//go:build integration

// 통합 테스트: 알람 규칙(T2.6). api 스키마에 api_app 으로 접속하고, 만든 행은 지운다.
package alarm

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func apiDB(t *testing.T) *sql.DB {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	pw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "deploy", "secrets", "api_app_password"))
	if err != nil {
		t.Fatalf("비밀 파일(make up 필요): %v", err)
	}
	c := mysql.NewConfig()
	c.User, c.Passwd, c.Net, c.Addr, c.DBName = "api_app", strings.TrimSpace(string(pw)), "tcp", "127.0.0.1:3306", "api"
	c.ParseTime = true
	db, err := sql.Open("mysql", c.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestAlarmRules(t *testing.T) {
	db := apiDB(t)
	ctx := context.Background()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	s := hex.EncodeToString(b)
	ledger, addr, drafter := "it-ledger-"+s, "0x00000000000000000000000000000000"+s, "it-drafter-"+s
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM alarms WHERE subject IN (?, ?) OR subject LIKE ?", addr, drafter, "it-req-"+s+"%")
		_, _ = db.Exec("DELETE FROM requests WHERE ledger_id = ?", ledger)
	})
	rec := &Recorder{DB: db, Rules: Defaults}

	// 고액: 한도의 80% 경계(big.Int)
	if ok, err := rec.HighAmount(ctx, "it-req-"+s+"-1", "pol", big.NewInt(79999), big.NewInt(100000)); err != nil || ok {
		t.Fatalf("79999/100000: %v %v", ok, err)
	}
	if ok, err := rec.HighAmount(ctx, "it-req-"+s+"-2", "pol", big.NewInt(80000), big.NewInt(100000)); err != nil || !ok {
		t.Fatalf("80000/100000: %v %v", ok, err)
	}

	insert := func(i int, status, signer string) {
		t.Helper()
		_, err := db.Exec(`INSERT INTO requests (request_id, type, ledger_id, institution_id, intent_json, intent_hash, status, drafter_id, signer_address, expires_at)
			VALUES (?, 'TX', ?, 'inst-a', '{}', REPEAT(CHAR(0), 32), ?, ?, ?, ?)`,
			fmt.Sprintf("IT%s%016d", strings.ToUpper(s), i), ledger, status, drafter, signer, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
	}
	// 반복: 같은 키로 5건 미만이면 알람 없음, 5건이면 알람, 다시 평가해도 창 안에서는 한 번만
	for i := 0; i < 4; i++ {
		insert(i, "SIGNED", addr)
	}
	if ok, err := rec.RepeatKey(ctx, ledger, addr); err != nil || ok {
		t.Fatalf("4건: %v %v", ok, err)
	}
	insert(4, "SIGNED", addr)
	if ok, err := rec.RepeatKey(ctx, ledger, addr); err != nil || !ok {
		t.Fatalf("5건: %v %v", ok, err)
	}
	if ok, err := rec.RepeatKey(ctx, ledger, addr); err != nil || ok {
		t.Fatalf("창 안 중복 알람: %v %v", ok, err)
	}
	// 거부 반복: 같은 기안자의 FAILED 3건
	for i := 10; i < 12; i++ {
		insert(i, "FAILED", "")
	}
	if ok, err := rec.RejectRepeat(ctx, drafter); err != nil || ok {
		t.Fatalf("거부 2건: %v %v", ok, err)
	}
	insert(12, "FAILED", "")
	if ok, err := rec.RejectRepeat(ctx, drafter); err != nil || !ok {
		t.Fatalf("거부 3건: %v %v", ok, err)
	}
	list, err := List(ctx, db, 50)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, a := range list {
		if a.Subject == addr || a.Subject == drafter || strings.HasPrefix(a.Subject, "it-req-"+s) {
			seen[a.Rule] = true
		}
	}
	for _, r := range []string{RuleHighAmount, RuleRepeatKey, RuleRejectRepeat} {
		if !seen[r] {
			t.Errorf("알람 %s 가 기록되지 않았다", r)
		}
	}
}
