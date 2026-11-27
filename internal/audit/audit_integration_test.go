//go:build integration

// 통합 테스트: 감사 체인의 동시 추가와 변조 탐지(T2.1).
// 실제 체인(api, signer)을 건드리지 않도록 관리 계정(root)으로 임시 DB 를 만들어 실제 signer 마이그레이션을
// 적용하고, 시험이 끝나면 지운다. 실행 전 make up 이 필요하다.
package audit

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	migratemysql "github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func rootDSN(t *testing.T, db string, multi bool) string {
	t.Helper()
	pw, err := os.ReadFile(filepath.Join(repoRoot(), "deploy", "secrets", "mysql_root_password"))
	if err != nil {
		t.Fatalf("비밀 파일(make up 필요): %v", err)
	}
	c := mysql.NewConfig()
	c.User, c.Passwd, c.Net, c.Addr, c.DBName = "root", strings.TrimSpace(string(pw)), "tcp", "127.0.0.1:3306", db
	c.ParseTime, c.MultiStatements = true, multi
	return c.FormatDSN()
}

// tempChainDB 는 실제 signer 마이그레이션을 적용한 임시 DB 를 만든다.
func tempChainDB(t *testing.T) *sql.DB {
	t.Helper()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := "audit_it_" + hex.EncodeToString(b)
	admin, err := sql.Open("mysql", rootDSN(t, "", false))
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(); err != nil {
		t.Fatalf("MySQL 접속(make up 필요): %v", err)
	}
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP DATABASE " + name)
		_ = admin.Close()
	})
	mdb, err := sql.Open("mysql", rootDSN(t, name, true))
	if err != nil {
		t.Fatal(err)
	}
	drv, err := migratemysql.WithInstance(mdb, &migratemysql.Config{DatabaseName: name})
	if err != nil {
		t.Fatal(err)
	}
	m, err := migrate.NewWithDatabaseInstance("file://"+filepath.Join(repoRoot(), "migrations", "signer"), name, drv)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Up(); err != nil {
		t.Fatal(err)
	}
	_ = mdb.Close()
	db, err := sql.Open("mysql", rootDSN(t, name, false))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(32)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func loadAll(t *testing.T, db *sql.DB) []Record {
	t.Helper()
	rs, err := Load(context.Background(), db, 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestConcurrentAppendKeepsChain(t *testing.T) {
	db := tempChainDB(t)
	const n = 100
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := AppendTx(context.Background(), db, Entry{Actor: "it", Action: "TEST", Subject: fmt.Sprintf("s-%d", i),
				Payload: map[string]any{"count": i}})
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("동시 추가 실패: %v", err)
	}
	rs := loadAll(t, db)
	res := Verify(rs)
	if !res.OK || res.Count != n || res.HeadSeq != n {
		t.Fatalf("체인이 끊겼다: %+v", res)
	}
	var headSeq uint64
	var headHash []byte
	if err := db.QueryRow("SELECT seq, hash FROM audit_head WHERE id = 1").Scan(&headSeq, &headHash); err != nil {
		t.Fatal(err)
	}
	if headSeq != n || string(headHash) != string(res.HeadHash[:]) {
		t.Fatalf("머리 행 불일치: seq=%d", headSeq)
	}
}

// 관리 계정으로 한 행을 고치면 검증이 그 seq 에서 실패한다.
func TestAdminTamperDetectedAtSeq(t *testing.T) {
	db := tempChainDB(t)
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		if _, err := AppendTx(ctx, db, Entry{Actor: "it", Action: "TEST", Subject: fmt.Sprintf("s-%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if res := Verify(loadAll(t, db)); !res.OK {
		t.Fatalf("변조 전 검증 실패: %+v", res)
	}
	if _, err := db.Exec("UPDATE audit_log SET subject = 'tampered' WHERE seq = 37"); err != nil {
		t.Fatal(err)
	}
	res := Verify(loadAll(t, db))
	if res.OK || res.FirstBadSeq != 37 {
		t.Fatalf("변조를 seq 37 에서 찾지 못했다: %+v", res)
	}
	// 해시까지 다시 계산해 넣어도 다음 레코드에서 잡힌다.
	rs := loadAll(t, db)
	r := rs[36]
	r.Hash = ComputeHash(r)
	if _, err := db.Exec("UPDATE audit_log SET hash = ? WHERE seq = 37", r.Hash[:]); err != nil {
		t.Fatal(err)
	}
	res = Verify(loadAll(t, db))
	if res.OK || res.FirstBadSeq != 38 {
		t.Fatalf("해시를 다시 계산한 변조: %+v", res)
	}
	// 중간 행 삭제
	if _, err := db.Exec("DELETE FROM audit_log WHERE seq = 10"); err != nil {
		t.Fatal(err)
	}
	if res := Verify(loadAll(t, db)); res.OK || res.FirstBadSeq != 10 {
		t.Fatalf("행 삭제: %+v", res)
	}
}
