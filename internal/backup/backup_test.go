package backup

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T) []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// 2-of-3: 아무 조각 2개로 복구되고, 1개로는 실패한다(작업지시서 T3.6 완료 기준).
func TestSplitCombine2of3(t *testing.T) {
	key := newKey(t)
	shares, err := Split(key, "cer-1", "wrap-1", []string{"cust-a", "cust-b", "cust-c"}, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]int{{0, 1}, {0, 2}, {1, 2}} {
		got, err := Combine([]Share{shares[pair[0]], shares[pair[1]]})
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("조각 %v 결합: %v", pair, err)
		}
	}
	if all, err := Combine(shares); err != nil || !bytes.Equal(all, key) {
		t.Fatalf("조각 3개 결합: %v", err)
	}
	for i := range shares {
		if _, err := Combine([]Share{shares[i]}); err == nil {
			t.Fatalf("조각 1개(%d)로 복구됐다", i)
		}
		if strings.Contains(shares[i].Value, strings.ToLower(string(key))) {
			t.Fatal("조각에 키가 그대로 들어 있다")
		}
	}
}

func TestCombineRejects(t *testing.T) {
	key := newKey(t)
	a, _ := Split(key, "cer-1", "wrap-1", []string{"x", "y", "z"}, 2, time.Now())
	b, _ := Split(newKey(t), "cer-2", "wrap-2", []string{"x", "y", "z"}, 2, time.Now())
	if _, err := Combine([]Share{a[0], b[1]}); err == nil {
		t.Fatal("다른 의식의 조각이 섞였는데 결합됐다")
	}
	if _, err := Combine([]Share{a[0], a[0]}); err == nil {
		t.Fatal("같은 조각 두 번으로 결합됐다")
	}
	bad := a[1]
	v := []byte(bad.Value)
	if v[2] == '0' {
		v[2] = '1'
	} else {
		v[2] = '0'
	}
	bad.Value = string(v)
	if _, err := Combine([]Share{a[0], bad}); err == nil || !strings.Contains(err.Error(), "약속값") {
		t.Fatalf("손상된 조각: %v", err)
	}
	if _, err := Split(key, "c", "w", []string{"x", "x"}, 2, time.Now()); err == nil {
		t.Fatal("보관자 중복을 받았다")
	}
	if _, err := Split(key, "c", "w", []string{"x", "y"}, 1, time.Now()); err == nil {
		t.Fatal("threshold 1 을 받았다")
	}
}

func TestShareFilePermissionsAndNoOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shares")
	s, _ := Split(newKey(t), "c", "w", []string{"x", "y"}, 2, time.Now())
	p, err := WriteShare(dir, s[0])
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	ds, _ := os.Stat(dir)
	if st.Mode().Perm() != 0o600 || ds.Mode().Perm() != 0o700 {
		t.Fatalf("권한 파일 %v 디렉터리 %v", st.Mode().Perm(), ds.Mode().Perm())
	}
	if _, err := WriteShare(dir, s[0]); err == nil {
		t.Fatal("조각 파일을 덮어썼다")
	}
	got, err := ReadShare(p)
	if err != nil || got != s[0] {
		t.Fatalf("다시 읽기: %v", err)
	}
}
