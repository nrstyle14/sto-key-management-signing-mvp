package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/config"
)

// 서버가 기대하는 마이그레이션 버전. 마이그레이션을 추가하면 같이 올린다.
const (
	APISchemaVersion    = 6
	SignerSchemaVersion = 4
)

// DBConfig 는 MySQL 접속 설정이다. 비밀번호는 파일로만 받는다.
type DBConfig struct {
	Addr         string `yaml:"addr"`
	User         string `yaml:"user"`
	PasswordFile string `yaml:"password_file"`
	Database     string `yaml:"database"`
}

// Validate 는 필수 값을 확인한다.
func (c DBConfig) Validate() error {
	if c.Addr == "" || c.User == "" || c.PasswordFile == "" || c.Database == "" {
		return errors.New("db.addr, db.user, db.password_file, db.database 가 모두 필요하다")
	}
	return nil
}

// Open 은 DB 에 접속하고 Ping 으로 확인한다. DSN 은 메모리에서만 만들고 출력하지 않는다.
func Open(ctx context.Context, c DBConfig) (*sql.DB, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	pw, err := config.ReadSecret(c.PasswordFile)
	if err != nil {
		return nil, err
	}
	mc := mysql.NewConfig()
	mc.User, mc.Passwd, mc.Net, mc.Addr, mc.DBName = c.User, pw, "tcp", c.Addr, c.Database
	mc.ParseTime = true
	mc.Loc = time.UTC
	db, err := sql.Open("mysql", mc.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("DB 열기: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetConnMaxLifetime(30 * time.Minute)
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("DB 접속(%s@%s/%s): %w", c.User, c.Addr, c.Database, err)
	}
	return db, nil
}

// CheckMigration 은 schema_migrations 의 버전이 want 와 같고 dirty 가 아닌지 확인한다(기동 점검).
func CheckMigration(ctx context.Context, db *sql.DB, want uint) error {
	var ver uint
	var dirty bool
	err := db.QueryRowContext(ctx, `SELECT version, dirty FROM schema_migrations LIMIT 1`).Scan(&ver, &dirty)
	if err != nil {
		return fmt.Errorf("마이그레이션 버전 조회: %w", err)
	}
	if dirty {
		return fmt.Errorf("마이그레이션 버전 %d 이 dirty 상태다", ver)
	}
	if ver != want {
		return fmt.Errorf("마이그레이션 버전 %d, 기대 %d (make migrate 필요)", ver, want)
	}
	return nil
}

// DBTX 는 *sql.DB 와 *sql.Tx 가 모두 만족하는 인터페이스다.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}
