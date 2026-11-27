// Package approval 은 승인자 키와 승인 서명 생성·검증을 다룬다(설계서 5.2, FR-3.1, D-2).
//
// 승인 서명 = Ed25519.Sign(승인자 개인키, "sto-approval-v1" || intent_hash(32바이트) || decision)
package approval

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
)

// Domain 은 승인 서명의 도메인 구분 문자열이다.
const Domain = "sto-approval-v1"

// Decision 은 승인 또는 반려다.
type Decision string

// 결정
const (
	Approve Decision = "APPROVE"
	Reject  Decision = "REJECT"
)

// Valid 는 알려진 결정인지 돌려준다.
func (d Decision) Valid() bool { return d == Approve || d == Reject }

// Message 는 서명 대상 바이트다.
func Message(intentHash [32]byte, d Decision) []byte {
	m := make([]byte, 0, len(Domain)+32+len(d))
	m = append(m, Domain...)
	m = append(m, intentHash[:]...)
	return append(m, d...)
}

// Sign 은 승인 서명을 만든다.
func Sign(priv ed25519.PrivateKey, intentHash [32]byte, d Decision) ([]byte, error) {
	if !d.Valid() {
		return nil, fmt.Errorf("approval: 알 수 없는 결정 %q", d)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("approval: 개인키 길이 오류")
	}
	return ed25519.Sign(priv, Message(intentHash, d)), nil
}

// Verify 는 승인 서명을 확인한다.
func Verify(pub ed25519.PublicKey, intentHash [32]byte, d Decision, sig []byte) bool {
	if !d.Valid() || len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, Message(intentHash, d), sig)
}

// Approval 은 요청에 붙는 승인·반려 한 건이다(전송 형식).
type Approval struct {
	ApproverID string   `json:"approver_id"`
	Decision   Decision `json:"decision"`
	Signature  string   `json:"signature"` // 16진수 64바이트
}

// SignatureBytes 는 서명 바이트다.
func (a Approval) SignatureBytes() ([]byte, error) {
	b, err := hex.DecodeString(a.Signature)
	if err != nil || len(b) != ed25519.SignatureSize {
		return nil, errors.New("approval: 서명은 16진수 64바이트여야 한다")
	}
	return b, nil
}
