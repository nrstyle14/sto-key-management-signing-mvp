//go:build integration

// 통합 테스트: 실제 SoftHSM2(PKCS#11)로 토큰별 키 생성·조회·서명·삭제와 추출 불가를 확인한다(T1.2).
// make it 이 SoftHSM2 가 든 컨테이너에서 실행한다. 라이브러리가 없으면 건너뛰지 않고 실패한다.
package hsm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/miekg/pkcs11"
)

func libPath() string {
	if p := os.Getenv("STO_TEST_PKCS11_LIB"); p != "" {
		return p
	}
	return "/usr/lib/softhsm/libsofthsm2.so"
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// newToken 은 무작위 라벨·PIN 으로 새 토큰을 만들고 로그인한다.
func newToken(t *testing.T, m *Module) (*Token, string) {
	t.Helper()
	label := "it-" + randHex(t, 6)
	pin := randHex(t, 12)
	created, err := m.InitToken(label, randHex(t, 12), pin)
	if err != nil || !created {
		t.Fatalf("InitToken(%s): created=%v err=%v", label, created, err)
	}
	tok, err := m.Login(label, pin, 4)
	if err != nil {
		t.Fatalf("Login(%s): %v", label, err)
	}
	return tok, pin
}

func openModule(t *testing.T) *Module {
	t.Helper()
	if _, err := os.Stat(libPath()); err != nil {
		t.Fatalf("PKCS#11 라이브러리가 없다(SoftHSM2 컨테이너에서 make it 으로 실행): %v", err)
	}
	m, err := Open(libPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}

func TestInitTokenIsIdempotent(t *testing.T) {
	m := openModule(t)
	label := "it-" + randHex(t, 6)
	created, err := m.InitToken(label, randHex(t, 12), randHex(t, 12))
	if err != nil || !created {
		t.Fatalf("첫 초기화: created=%v err=%v", created, err)
	}
	created, err = m.InitToken(label, randHex(t, 12), randHex(t, 12))
	if err != nil || created {
		t.Fatalf("두 번째 초기화는 건너뛰어야 한다: created=%v err=%v", created, err)
	}
}

func TestLoginWithWrongPINFails(t *testing.T) {
	m := openModule(t)
	label := "it-" + randHex(t, 6)
	if _, err := m.InitToken(label, randHex(t, 12), randHex(t, 12)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Login(label, "wrong-pin-0000", 1); err == nil {
		t.Fatal("틀린 PIN 으로 로그인됐다")
	}
}

func TestKeysPerTokenAreSeparated(t *testing.T) {
	ctx := context.Background()
	m := openModule(t)
	a, _ := newToken(t, m)
	b, _ := newToken(t, m)

	pubA, err := a.GenerateSecp256k1(ctx, "key-a", KeyAttrs{})
	if err != nil {
		t.Fatal(err)
	}
	pubB, err := b.GenerateSecp256k1(ctx, "key-b", KeyAttrs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pubA) != 65 || pubA[0] != 0x04 || len(pubB) != 65 {
		t.Fatalf("공개키 형식: %x / %x", pubA, pubB)
	}
	got, err := a.PublicKey(ctx, "key-a")
	if err != nil || hex.EncodeToString(got) != hex.EncodeToString(pubA) {
		t.Fatalf("공개키 조회 불일치: err=%v", err)
	}
	if err := a.HasPrivateKey(ctx, "key-a"); err != nil {
		t.Fatal(err)
	}
	// 다른 토큰의 키는 보이지 않는다(FR-2.1).
	if err := a.HasPrivateKey(ctx, "key-b"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("토큰 A 에서 토큰 B 의 키가 보인다: %v", err)
	}
	if _, err := a.SignDigest(ctx, "key-b", make([]byte, 32)); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("토큰 A 로 토큰 B 의 키 서명이 됐다: %v", err)
	}
	// 같은 라벨의 키를 다시 만들 수 없다.
	if _, err := a.GenerateSecp256k1(ctx, "key-a", KeyAttrs{}); err == nil {
		t.Fatal("같은 keyID 로 키가 두 번 만들어졌다")
	}
}

func TestPrivateKeyValueCannotBeRead(t *testing.T) {
	ctx := context.Background()
	m := openModule(t)
	tok, _ := newToken(t, m)
	cases := map[string]KeyAttrs{"operational": {Extractable: false}, "root": {Extractable: true}}
	for name, attrs := range cases {
		keyID := "key-" + name
		if _, err := tok.GenerateSecp256k1(ctx, keyID, attrs); err != nil {
			t.Fatal(err)
		}
		err := tok.withSession(ctx, func(sh pkcs11.SessionHandle) error {
			h, err := tok.one(sh, pkcs11.CKO_PRIVATE_KEY, keyID)
			if err != nil {
				return err
			}
			got, err := m.ctx.GetAttributeValue(sh, h, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil), pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil)})
			if err != nil {
				return err
			}
			if (got[0].Value[0] == 1) != attrs.Extractable || got[1].Value[0] != 1 {
				t.Errorf("%s: CKA_EXTRACTABLE=%v CKA_SENSITIVE=%v", name, got[0].Value, got[1].Value)
			}
			// 개인키 값 읽기는 부류와 관계없이 거부돼야 한다(CKA_SENSITIVE).
			_, err = m.ctx.GetAttributeValue(sh, h, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
			if !isErr(err, pkcs11.CKR_ATTRIBUTE_SENSITIVE) {
				t.Errorf("%s: 개인키 값 읽기가 CKR_ATTRIBUTE_SENSITIVE 로 거부되지 않았다: %v", name, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestConcurrentSignAndDestroy(t *testing.T) {
	ctx := context.Background()
	m := openModule(t)
	tok, _ := newToken(t, m)
	if _, err := tok.GenerateSecp256k1(ctx, "key-c", KeyAttrs{}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := make([]byte, 32)
			_, _ = rand.Read(d)
			if _, err := tok.SignDigest(ctx, "key-c", d); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("동시 서명 실패: %v", err)
	}
	if err := tok.Destroy(ctx, "key-c"); err != nil {
		t.Fatal(err)
	}
	if err := tok.HasPrivateKey(ctx, "key-c"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("삭제 후에도 키가 있다: %v", err)
	}
	if _, err := tok.SignDigest(ctx, "key-c", make([]byte, 32)); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("삭제된 키로 서명됐다: %v", err)
	}
}
