package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsUnknownField(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	_ = os.WriteFile(p, []byte("listen: \":1\"\nunknown: 1\n"), 0o600)
	var c struct {
		Listen string `yaml:"listen"`
	}
	if err := Load(p, &c); err == nil {
		t.Fatal("알 수 없는 키가 허용됐다")
	}
}

func TestReadSecret(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "s")
	_ = os.WriteFile(p, []byte("abc\n"), 0o600)
	v, err := ReadSecret(p)
	if err != nil || v != "abc" {
		t.Fatalf("v=%q err=%v", v, err)
	}
	empty := filepath.Join(d, "e")
	_ = os.WriteFile(empty, []byte("\n"), 0o600)
	if _, err := ReadSecret(empty); err == nil {
		t.Fatal("빈 비밀 파일이 허용됐다")
	}
}
