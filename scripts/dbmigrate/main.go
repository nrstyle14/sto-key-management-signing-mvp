// Command dbmigrate 는 api, signer 스키마 마이그레이션을 실행하고 서버용 계정에 테이블 단위 권한을 준다(T0.5).
//
//   - 마이그레이션은 스키마별 마이그레이션 계정(<schema>_migrator)으로 실행한다(golang-migrate).
//   - 서버용 계정(<schema>_app)의 권한은 마이그레이션 뒤 실제 테이블 목록을 보고 관리 계정(root)으로 부여한다.
//     MySQL 은 스키마 권한에서 특정 테이블만 빼는 방법이 없으므로 테이블 단위로 준다.
//   - 감사 테이블(audit_log, audit_checkpoints)에는 SELECT, INSERT 만 준다(NFR-2). 머리 행(audit_head)은 SELECT, UPDATE 만.
//
// 비밀번호는 deploy/secrets/ 파일에서 읽어 메모리의 DSN 에만 쓰고 출력하지 않는다.
package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	migratemysql "github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// appendOnly 는 서버용 계정에 SELECT, INSERT 만 주는 테이블이다.
var appendOnly = map[string]bool{"audit_log": true, "audit_checkpoints": true}

// lockOnly 는 서버용 계정에 SELECT, UPDATE 만 주는 테이블이다(감사 체인 머리 잠금 행).
var lockOnly = map[string]bool{"audit_head": true}

func main() {
	addr := flag.String("addr", "127.0.0.1:3306", "MySQL 주소(로컬만)")
	secrets := flag.String("secrets", "deploy/secrets", "비밀 파일 디렉터리")
	dir := flag.String("dir", "migrations", "마이그레이션 디렉터리")
	schemas := flag.String("schemas", "api,signer", "대상 스키마 목록")
	flag.Parse()

	for _, s := range strings.Split(*schemas, ",") {
		if err := run(*addr, *secrets, *dir, s); err != nil {
			fmt.Fprintf(os.Stderr, "실패(%s): %v\n", s, err)
			os.Exit(1)
		}
	}
}

func readSecret(dir, name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "", fmt.Errorf("비밀 파일 %s 읽기: %w", name, err)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("비밀 파일 %s 가 비었다", name)
	}
	return v, nil
}

func open(addr, user, pass, db string, multi bool) (*sql.DB, error) {
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr, cfg.DBName = user, pass, "tcp", addr, db
	cfg.MultiStatements = multi
	cfg.ParseTime = true
	d, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, err
	}
	if err := d.Ping(); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("%s 계정 접속: %w", user, err)
	}
	return d, nil
}

func run(addr, secrets, dir, schema string) error {
	if schema != "api" && schema != "signer" {
		return fmt.Errorf("알 수 없는 스키마: %s", schema)
	}
	migPW, err := readSecret(secrets, schema+"_migrator_password")
	if err != nil {
		return err
	}
	rootPW, err := readSecret(secrets, "mysql_root_password")
	if err != nil {
		return err
	}

	// 1) 마이그레이션
	mdb, err := open(addr, schema+"_migrator", migPW, schema, true)
	if err != nil {
		return err
	}
	defer mdb.Close()
	drv, err := migratemysql.WithInstance(mdb, &migratemysql.Config{DatabaseName: schema})
	if err != nil {
		return fmt.Errorf("마이그레이션 드라이버: %w", err)
	}
	abs, err := filepath.Abs(filepath.Join(dir, schema))
	if err != nil {
		return err
	}
	m, err := migrate.NewWithDatabaseInstance("file://"+abs, schema, drv)
	if err != nil {
		return fmt.Errorf("마이그레이션 준비: %w", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("마이그레이션 실행: %w", err)
	}
	ver, dirty, err := m.Version()
	if err != nil {
		return fmt.Errorf("마이그레이션 버전 조회: %w", err)
	}
	if dirty {
		return fmt.Errorf("마이그레이션 버전 %d 이 dirty 상태다", ver)
	}

	// 2) 서버용 계정 권한(테이블 단위)
	rdb, err := open(addr, "root", rootPW, "", false)
	if err != nil {
		return err
	}
	defer rdb.Close()
	rows, err := rdb.Query(`SELECT table_name FROM information_schema.tables WHERE table_schema = ? AND table_type = 'BASE TABLE' ORDER BY table_name`, schema)
	if err != nil {
		return fmt.Errorf("테이블 목록 조회: %w", err)
	}
	var tables []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			_ = rows.Close()
			return err
		}
		tables = append(tables, t)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_ = rows.Close()

	app := schema + "_app"
	var full, ao, lo, ro []string
	for _, t := range tables {
		var privs string
		switch {
		case t == "schema_migrations":
			privs = "SELECT" // 기동 점검에서 마이그레이션 버전만 확인한다(설계서 15절)
			ro = append(ro, t)
		case appendOnly[t]:
			privs = "SELECT, INSERT"
			ao = append(ao, t)
		case lockOnly[t]:
			privs = "SELECT, UPDATE"
			lo = append(lo, t)
		default:
			privs = "SELECT, INSERT, UPDATE, DELETE"
			full = append(full, t)
		}
		// 식별자는 information_schema 에서 읽은 값이고 백틱으로 감싼다.
		q := fmt.Sprintf("GRANT %s ON `%s`.`%s` TO '%s'@'%%'", privs, schema, strings.ReplaceAll(t, "`", "``"), app)
		if _, err := rdb.Exec(q); err != nil {
			return fmt.Errorf("권한 부여(%s): %w", t, err)
		}
	}
	fmt.Printf("%s: 마이그레이션 버전 %d\n", schema, ver)
	fmt.Printf("  %s 권한 SELECT/INSERT/UPDATE/DELETE: %s\n", app, strings.Join(full, ", "))
	fmt.Printf("  %s 권한 SELECT/INSERT(추가 전용): %s\n", app, strings.Join(ao, ", "))
	fmt.Printf("  %s 권한 SELECT/UPDATE(머리 잠금): %s\n", app, strings.Join(lo, ", "))
	fmt.Printf("  %s 권한 SELECT: %s\n", app, strings.Join(ro, ", "))
	return nil
}
