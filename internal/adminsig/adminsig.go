// Package adminsig 는 보안관리자 M-of-N 서명 확인이다. 키 작업(D-20)과 정책 변경(D-22)이 같이 쓴다.
// 각 작업은 자기 도메인 문자열을 붙인 서명 대상(msg)을 넘기므로 서로의 서명을 재사용할 수 없다.
package adminsig

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/store"
)

// Signature 는 보안관리자 서명 한 건이다.
type Signature struct {
	AdminID   string `json:"admin_id"`
	Signature string `json:"signature"`
}

// Kind 는 거부 종류다. 호출하는 패키지가 자기 오류 코드로 바꾼다.
type Kind int

// 거부 종류
const (
	KindDuplicate    Kind = iota + 1 // 같은 보안관리자 서명이 두 번
	KindNotAdmin                     // 미등록·비활성·역할 다름·그룹 밖
	KindSignature                    // 서명이 서명 대상과 맞지 않음
	KindInsufficient                 // 서로 다른 보안관리자 수 < M
)

// Failure 는 서명 확인 거부다.
type Failure struct {
	Kind Kind
	Msg  string
}

func (f *Failure) Error() string { return f.Msg }

func failure(k Kind, format string, a ...any) error {
	return &Failure{Kind: k, Msg: fmt.Sprintf(format, a...)}
}

// Verify 는 서로 다른 활성 보안관리자(역할 SECURITY_ADMIN, 그룹 group) M명의 서명이 msg 에 대해 유효한지 확인하고
// 그 ID 목록을 돌려준다. 서명 하나라도 잘못되면 전체를 거부한다(D-14 와 같은 원칙). 거부는 *Failure 다.
func Verify(ctx context.Context, db store.DBTX, group string, m int, msg []byte, sigs []Signature) ([]string, error) {
	seen := map[string]bool{}
	var ids []string
	for _, a := range sigs {
		if seen[a.AdminID] {
			return nil, failure(KindDuplicate, "보안관리자 %s 중복", a.AdminID)
		}
		seen[a.AdminID] = true
		ap, err := approval.Lookup(ctx, db, a.AdminID)
		if errors.Is(err, approval.ErrNotFound) {
			return nil, failure(KindNotAdmin, "등록되지 않은 승인자 %s", a.AdminID)
		}
		if err != nil {
			return nil, err
		}
		inGroup := false
		for _, g := range ap.Groups {
			if g == group {
				inGroup = true
			}
		}
		if ap.Status != "ACTIVE" || ap.Role != "SECURITY_ADMIN" || !inGroup {
			return nil, failure(KindNotAdmin, "%s 는 활성 보안관리자가 아니다", a.AdminID)
		}
		sig, err := hex.DecodeString(a.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ap.PublicKey, msg, sig) {
			return nil, failure(KindSignature, "%s 의 서명이 요청과 맞지 않는다", a.AdminID)
		}
		ids = append(ids, a.AdminID)
	}
	if m < 1 {
		m = 1
	}
	if len(ids) < m {
		return nil, failure(KindInsufficient, "보안관리자 %d명의 서명이 필요하다(받은 서명 %d건)", m, len(ids))
	}
	return ids, nil
}
