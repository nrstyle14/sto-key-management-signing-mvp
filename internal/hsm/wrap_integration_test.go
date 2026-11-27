//go:build integration

package hsm

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
)

// 루트 키 백업·복구(설계서 6.3): 원본 토큰에서 래핑 → 새 빈 토큰에 같은 래핑 키 주입 → 복원.
// 복원 토큰에서 공개키 조회·서명이 되고, 추출 불가(운영) 키는 래핑이 거부된다.
func TestWrapUnwrapIntoEmptyToken(t *testing.T) {
	m := openModule(t)
	ctx := context.Background()
	src, _ := newToken(t, m)
	wrapKey := make([]byte, 32)
	_, _ = rand.Read(wrapKey)
	if err := src.InjectWrappingKey(ctx, "wrap-1", wrapKey); err != nil {
		t.Fatal(err)
	}
	if err := src.InjectWrappingKey(ctx, "wrap-1", wrapKey); !errors.Is(err, ErrExists) {
		t.Fatalf("같은 라벨 래핑 키 재주입: %v", err)
	}
	if ok, err := src.HasWrappingKey(ctx, "wrap-1"); err != nil || !ok {
		t.Fatalf("래핑 키 확인: %v %v", ok, err)
	}
	pub, err := src.GenerateSecp256k1(ctx, "root-1", KeyAttrs{Extractable: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.GenerateSecp256k1(ctx, "op-1", KeyAttrs{Extractable: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := src.WrapPrivateKey(ctx, "wrap-1", "op-1"); err == nil {
		t.Fatal("추출 불가 키가 래핑됐다")
	}
	wrapped, err := src.WrapPrivateKey(ctx, "wrap-1", "root-1")
	if err != nil {
		t.Fatal(err)
	}
	// 다른 래핑 키로는 복원되지 않는다.
	dst, _ := newToken(t, m)
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	if err := dst.InjectWrappingKey(ctx, "wrap-other", other); err != nil {
		t.Fatal(err)
	}
	if err := dst.UnwrapPrivateKey(ctx, "wrap-other", "root-1", wrapped, pub); err == nil {
		t.Fatal("다른 래핑 키로 복원됐다")
	}
	if n, _ := dst.ObjectCount(ctx, "root-1"); n != 0 {
		t.Fatalf("실패한 복원이 객체 %d개를 남겼다", n)
	}
	if err := dst.InjectWrappingKey(ctx, "wrap-1", wrapKey); err != nil {
		t.Fatal(err)
	}
	if err := dst.UnwrapPrivateKey(ctx, "wrap-1", "root-1", wrapped, pub); err != nil {
		t.Fatal(err)
	}
	if err := dst.UnwrapPrivateKey(ctx, "wrap-1", "root-1", wrapped, pub); !errors.Is(err, ErrExists) {
		t.Fatalf("같은 키 재복원: %v", err)
	}
	got, err := dst.PublicKey(ctx, "root-1")
	if err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("복원 토큰 공개키: %v", err)
	}
	if n, _ := dst.ObjectCount(ctx, "root-1"); n != 2 {
		t.Fatalf("복원 뒤 객체 %d개(기대 개인키·공개키 2)", n)
	}
	digest := make([]byte, 32)
	_, _ = rand.Read(digest)
	if _, err := dst.SignDigest(ctx, "root-1", digest); err != nil {
		t.Fatalf("복원 키 서명: %v", err)
	}
	// 복원한 루트 키는 다시 백업할 수 있다.
	if _, err := dst.WrapPrivateKey(ctx, "wrap-1", "root-1"); err != nil {
		t.Fatalf("복원 키 재백업: %v", err)
	}
}
