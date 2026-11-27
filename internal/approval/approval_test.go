package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignVerify(t *testing.T) {
	pub, priv := keys(t)
	h := sha256.Sum256([]byte("intent-1"))
	sig, err := Sign(priv, h, Approve)
	if err != nil || !Verify(pub, h, Approve, sig) {
		t.Fatal("정상 서명 검증 실패")
	}
}

func TestVerifyRejects(t *testing.T) {
	pub, priv := keys(t)
	otherPub, otherPriv := keys(t)
	h := sha256.Sum256([]byte("intent-1"))
	h2 := sha256.Sum256([]byte("intent-2"))
	sig, _ := Sign(priv, h, Approve)

	forged := append([]byte(nil), sig...)
	forged[10] ^= 0x01
	if Verify(pub, h, Approve, forged) {
		t.Error("위조 서명이 통과했다")
	}
	if Verify(pub, h2, Approve, sig) {
		t.Error("다른 intent 에 대한 서명 재사용이 통과했다")
	}
	rejectSig, _ := Sign(priv, h, Reject)
	if Verify(pub, h, Approve, rejectSig) {
		t.Error("반려(REJECT) 서명이 승인(APPROVE)으로 통과했다")
	}
	if Verify(otherPub, h, Approve, sig) {
		t.Error("다른 승인자 공개키로 통과했다")
	}
	otherSig, _ := Sign(otherPriv, h, Approve)
	if Verify(pub, h, Approve, otherSig) {
		t.Error("다른 승인자의 서명이 통과했다")
	}
	if Verify(pub, h, "MAYBE", sig) {
		t.Error("알 수 없는 결정이 통과했다")
	}
	// 도메인 구분: 같은 키로 도메인 없이 intent_hash 만 서명한 값은 승인이 아니다.
	if Verify(pub, h, Approve, ed25519.Sign(priv, h[:])) {
		t.Error("도메인 없는 서명이 승인으로 통과했다")
	}
}

func TestKeyFile(t *testing.T) {
	pw := []byte("correct horse battery staple")
	kf, pub, err := NewKeyFile("apr-a-02", pw)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := kf.Public(); !got.Equal(pub) {
		t.Fatal("공개키 불일치")
	}
	priv, err := kf.Decrypt(pw)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("x"))
	sig, _ := Sign(priv, h, Approve)
	if !Verify(pub, h, Approve, sig) {
		t.Fatal("복호화한 키의 서명이 공개키로 검증되지 않는다")
	}
	if _, err := kf.Decrypt([]byte("wrong password!!")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("틀린 암호: %v", err)
	}
	tampered := *kf
	tampered.ApproverID = "apr-a-03"
	if _, err := tampered.Decrypt(pw); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("approver_id 를 바꾼 파일이 풀렸다: %v", err)
	}
	other, _ := keys(t)
	tampered = *kf
	tampered.PublicKey = hex.EncodeToString(other)
	if _, err := tampered.Decrypt(pw); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("공개키를 바꾼 파일이 풀렸다: %v", err)
	}
	if _, _, err := NewKeyFile("x", []byte("short")); err == nil {
		t.Fatal("짧은 암호가 허용됐다")
	}
}
