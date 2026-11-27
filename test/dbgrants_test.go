//go:build integration

// 통합 테스트: 서버용 DB 계정의 감사 테이블 권한(T0.5, NFR-2).
// 실행 전 `make up && make migrate` 가 필요하다. 환경이 없으면 건너뛰지 않고 실패한다.
package test

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// MySQL 오류 1142: ER_TABLEACCESS_DENIED_ERROR (명령이 테이블에 대해 거부됨)
const errTableAccessDenied = 1142

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("저장소 경로를 찾지 못했다")
	}
	return filepath.Dir(filepath.Dir(file))
}

func openAs(t *testing.T, user, schema string) *sql.DB {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "secrets", user+"_password"))
	if err != nil {
		t.Fatalf("비밀 파일을 읽지 못했다(make up 이 필요하다): %v", err)
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.DBName = user, strings.TrimSpace(string(b)), "tcp", schema
	cfg.Addr = os.Getenv("STO_MYSQL_ADDR")
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:3306"
	}
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("%s 접속 실패(make up && make migrate 가 필요하다): %v", user, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func mustDenied(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s 가 허용됐다(거부돼야 한다)", what)
	}
	var me *mysql.MySQLError
	if !errors.As(err, &me) || me.Number != errTableAccessDenied {
		t.Fatalf("%s 가 권한 오류가 아닌 이유로 실패했다: %v", what, err)
	}
}

func TestAppAccountCannotModifyAuditLog(t *testing.T) {
	for _, schema := range []string{"api", "signer"} {
		t.Run(schema, func(t *testing.T) {
			db := openAs(t, schema+"_app", schema)
			var before int
			if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&before); err != nil {
				t.Fatalf("SELECT 는 허용돼야 한다: %v", err)
			}
			// 감사 체인에 시험 행이 남지 않도록 한 트랜잭션 안에서 확인하고 롤백한다.
			// (MySQL 은 권한 오류가 난 문장이 있어도 트랜잭션을 중단하지 않는다.)
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			seq := uint64(1)<<62 + uint64(time.Now().UnixNano())%(1<<40)
			zero := make([]byte, 32)
			_, err = tx.Exec(`INSERT INTO audit_log (seq, ts, actor, action, subject, payload_json, prev_hash, hash)
				VALUES (?, NOW(6), 'it-test', 'GRANT_CHECK', 'audit_log', '{}', ?, ?)`, seq, zero, zero)
			if err != nil {
				_ = tx.Rollback()
				t.Fatalf("INSERT 는 허용돼야 한다: %v", err)
			}
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE seq = ?`, seq).Scan(&n); err != nil || n != 1 {
				_ = tx.Rollback()
				t.Fatalf("SELECT 는 허용돼야 한다: n=%d err=%v", n, err)
			}
			_, updErr := tx.Exec(`UPDATE audit_log SET actor = 'tampered' WHERE seq = ?`, seq)
			_, delErr := tx.Exec(`DELETE FROM audit_log WHERE seq = ?`, seq)
			if err := tx.Rollback(); err != nil {
				t.Fatalf("롤백 실패: %v", err)
			}
			mustDenied(t, updErr, "audit_log UPDATE")
			mustDenied(t, delErr, "audit_log DELETE")
			var after int
			if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&after); err != nil || after != before {
				t.Fatalf("시험 후 audit_log 행 수가 달라졌다: %d -> %d (err=%v)", before, after, err)
			}
			// DDL 은 암묵적으로 커밋될 수 있으므로 롤백 뒤에 시도한다.
			_, err = db.Exec(`TRUNCATE TABLE audit_log`)
			if err == nil {
				t.Fatal("audit_log TRUNCATE 가 허용됐다")
			}
			_, err = db.Exec(`DROP TABLE audit_log`)
			if err == nil {
				t.Fatal("audit_log DROP 이 허용됐다")
			}
		})
	}
}

func TestSignerAppCannotModifyAuditCheckpoints(t *testing.T) {
	db := openAs(t, "signer_app", "signer")
	_, err := db.Exec(`UPDATE audit_checkpoints SET seq = seq WHERE id = 0`)
	mustDenied(t, err, "audit_checkpoints UPDATE")
	_, err = db.Exec(`DELETE FROM audit_checkpoints WHERE id = 0`)
	mustDenied(t, err, "audit_checkpoints DELETE")
}

func TestAppAccountCanWriteBusinessTables(t *testing.T) {
	db := openAs(t, "api_app", "api")
	addr := fmt.Sprintf("0x%040x", time.Now().UnixNano())
	if _, err := db.Exec(`INSERT INTO nonces (ledger_id, address, next_nonce) VALUES ('it-test', ?, 0)`, addr); err != nil {
		t.Fatalf("업무 테이블 INSERT: %v", err)
	}
	if _, err := db.Exec(`UPDATE nonces SET next_nonce = 1 WHERE ledger_id = 'it-test' AND address = ?`, addr); err != nil {
		t.Fatalf("업무 테이블 UPDATE: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM nonces WHERE ledger_id = 'it-test' AND address = ?`, addr); err != nil {
		t.Fatalf("업무 테이블 DELETE: %v", err)
	}
}

func TestAppAccountsAreSchemaIsolated(t *testing.T) {
	db := openAs(t, "api_app", "api")
	_, err := db.Exec(`SELECT COUNT(*) FROM signer.audit_log`)
	mustDenied(t, err, "api_app 의 signer 스키마 조회")
	_, err = db.Exec(`CREATE TABLE api.it_should_fail (id INT)`)
	if err == nil {
		t.Fatal("api_app 의 DDL 이 허용됐다")
	}
}

// 머리 잠금 행(audit_head)은 SELECT, UPDATE 만 된다. 행 추가·삭제는 거부된다.
func TestAppAccountAuditHeadIsLockOnly(t *testing.T) {
	for _, schema := range []string{"api", "signer"} {
		t.Run(schema, func(t *testing.T) {
			db := openAs(t, schema+"_app", schema)
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback() }()
			var seq uint64
			if err := tx.QueryRow(`SELECT seq FROM audit_head WHERE id = 1 FOR UPDATE`).Scan(&seq); err != nil {
				t.Fatalf("머리 행 잠금 읽기는 허용돼야 한다: %v", err)
			}
			_, err = tx.Exec(`INSERT INTO audit_head (id, seq, hash) VALUES (2, 0, REPEAT(CHAR(0), 32))`)
			mustDenied(t, err, "audit_head INSERT")
			_, err = tx.Exec(`DELETE FROM audit_head WHERE id = 1`)
			mustDenied(t, err, "audit_head DELETE")
		})
	}
}
