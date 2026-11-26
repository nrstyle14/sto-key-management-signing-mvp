package signer

import (
	"context"
	"fmt"
	"math/big"
)

// Purpose 는 키 용도다(FR-2.2).
type Purpose string

// 키 용도
const (
	PurposeIssue         Purpose = "ISSUE"
	PurposeTransfer      Purpose = "TRANSFER"
	PurposeContractAdmin Purpose = "CONTRACT_ADMIN"
	PurposeEmergency     Purpose = "EMERGENCY"
	PurposeAudit         Purpose = "AUDIT"
)

// Class 는 키 부류다(D-3, 설계서 6.1).
type Class string

// 키 부류
const (
	ClassOperational Class = "OPERATIONAL" // 추출 불가, 백업 없음, 분실 시 교체
	ClassRoot        Class = "ROOT"        // 래핑으로만 내보낼 수 있음, 래핑 백업
	ClassAudit       Class = "AUDIT"       // 추출 불가, 교체 시 이전 공개키 보존
)

// ClassOf 는 용도에서 부류를 정한다. 호출자가 부류나 추출 가능 여부를 따로 고를 수 없다.
func ClassOf(p Purpose) (Class, error) {
	switch p {
	case PurposeIssue, PurposeTransfer:
		return ClassOperational, nil
	case PurposeContractAdmin, PurposeEmergency:
		return ClassRoot, nil
	case PurposeAudit:
		return ClassAudit, nil
	}
	return "", fmt.Errorf("signer: 알 수 없는 키 용도 %q", p)
}

// Extractable 은 부류가 래핑 내보내기를 허용하는지 돌려준다.
func (c Class) Extractable() bool { return c == ClassRoot }

// KeySpec 은 만들 키의 명세다.
type KeySpec struct {
	KeyID      string
	TokenLabel string
	Purpose    Purpose
}

// PublicKey 는 65바이트 비압축 secp256k1 공개키(0x04 || X || Y)다.
type PublicKey []byte

// Signer 는 서명기 인터페이스다(설계서 6.4). HSM 과 MPC(M5) 구현이 같은 인터페이스를 쓴다.
type Signer interface {
	// Generate 는 키 쌍을 만들고 공개키를 돌려준다.
	Generate(ctx context.Context, spec KeySpec) (PublicKey, error)
	// SignDigest 는 32바이트 다이제스트에 서명하고 (r, s)를 돌려준다. low-s 정규화는 호출자가 한다.
	SignDigest(ctx context.Context, keyID string, digest [32]byte) (r, s *big.Int, err error)
	// Destroy 는 키를 삭제한다.
	Destroy(ctx context.Context, keyID string) error
}
