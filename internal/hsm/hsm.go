// Package hsm 은 PKCS#11 세션, 키 생성·서명·삭제를 다룬다(설계서 6절). 서명 서버만 import 한다.
//
// 실측(docs/증빙/실측_HSM_서명.md)에 따라:
//   - 슬롯은 ID 가 아니라 토큰 라벨로 찾는다(SoftHSM2 는 초기화 뒤 슬롯 ID 를 다시 배정한다).
//   - CKA_EC_POINT 는 DER OCTET STRING 으로 감싼 65바이트 비압축 점이다(감싸지 않은 값도 받는다).
//   - CKM_ECDSA 서명은 64바이트 r||s 다. low-s 정규화는 호출자(internal/signer)가 한다.
//
// PIN 은 호출자가 비밀 파일에서 읽어 넘긴다. 이 패키지는 PIN 을 저장하거나 출력하지 않는다.
package hsm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// OIDSecp256k1 은 secp256k1 곡선 OID(1.3.132.0.10)의 DER 인코딩이다(CKA_EC_PARAMS).
var OIDSecp256k1 = []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A}

// OIDP256 은 P-256(prime256v1, 1.2.840.10045.3.1.7)의 DER 인코딩이다. Fabric 신원 키(D-26).
var OIDP256 = []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}

// 오류
var (
	ErrKeyNotFound   = errors.New("hsm: 키 객체가 없다")
	ErrKeyDuplicated = errors.New("hsm: 같은 라벨의 키 객체가 여러 개다")
	ErrTokenNotFound = errors.New("hsm: 토큰이 없다")
)

// Module 은 PKCS#11 라이브러리 하나다.
type Module struct {
	ctx *pkcs11.Ctx

	mu     sync.Mutex
	tokens map[string]*Token
}

// Open 은 PKCS#11 라이브러리를 적재하고 초기화한다.
func Open(lib string) (*Module, error) {
	ctx := pkcs11.New(lib)
	if ctx == nil {
		return nil, fmt.Errorf("hsm: PKCS#11 라이브러리를 열 수 없다: %s", lib)
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("hsm: C_Initialize: %w", err)
	}
	return &Module{ctx: ctx, tokens: map[string]*Token{}}, nil
}

// Close 는 모든 세션을 닫고 라이브러리를 해제한다.
func (m *Module) Close() {
	m.mu.Lock()
	for _, t := range m.tokens {
		t.closeAll()
	}
	m.tokens = map[string]*Token{}
	m.mu.Unlock()
	_ = m.ctx.Finalize()
	m.ctx.Destroy()
}

// findSlot 은 라벨이 label 인 초기화된 토큰의 슬롯을 찾는다.
func (m *Module) findSlot(label string) (uint, bool, error) {
	slots, err := m.ctx.GetSlotList(true)
	if err != nil {
		return 0, false, fmt.Errorf("hsm: C_GetSlotList: %w", err)
	}
	for _, s := range slots {
		ti, err := m.ctx.GetTokenInfo(s)
		if err != nil {
			return 0, false, fmt.Errorf("hsm: C_GetTokenInfo: %w", err)
		}
		if ti.Flags&pkcs11.CKF_TOKEN_INITIALIZED != 0 && strings.TrimSpace(ti.Label) == label {
			return s, true, nil
		}
	}
	return 0, false, nil
}

// InitToken 은 라벨이 label 인 토큰이 없으면 빈 슬롯에 만들고 사용자 PIN 을 설정한다.
// 이미 있으면 아무것도 하지 않고 created=false 를 돌려준다(다시 초기화하지 않는다).
func (m *Module) InitToken(label, soPIN, userPIN string) (created bool, err error) {
	if label == "" || len(label) > 32 {
		return false, fmt.Errorf("hsm: 토큰 라벨은 1~32자여야 한다: %q", label)
	}
	if _, ok, err := m.findSlot(label); err != nil {
		return false, err
	} else if ok {
		return false, nil
	}
	slots, err := m.ctx.GetSlotList(true)
	if err != nil {
		return false, fmt.Errorf("hsm: C_GetSlotList: %w", err)
	}
	free, found := uint(0), false
	for _, s := range slots {
		ti, err := m.ctx.GetTokenInfo(s)
		if err != nil {
			return false, fmt.Errorf("hsm: C_GetTokenInfo: %w", err)
		}
		if ti.Flags&pkcs11.CKF_TOKEN_INITIALIZED == 0 {
			free, found = s, true
			break
		}
	}
	if !found {
		return false, errors.New("hsm: 초기화되지 않은 슬롯이 없다")
	}
	if err := m.ctx.InitToken(free, soPIN, label); err != nil {
		return false, fmt.Errorf("hsm: C_InitToken(%s): %w", label, err)
	}
	slot, ok, err := m.findSlot(label)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, fmt.Errorf("hsm: 초기화한 토큰 %s 를 찾지 못했다", label)
	}
	sh, err := m.ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return false, fmt.Errorf("hsm: C_OpenSession: %w", err)
	}
	defer m.ctx.CloseSession(sh)
	if err := m.ctx.Login(sh, pkcs11.CKU_SO, soPIN); err != nil {
		return false, fmt.Errorf("hsm: C_Login(SO): %w", err)
	}
	defer m.ctx.Logout(sh)
	if err := m.ctx.InitPIN(sh, userPIN); err != nil {
		return false, fmt.Errorf("hsm: C_InitPIN: %w", err)
	}
	return true, nil
}

// Login 은 토큰에 사용자로 로그인하고 poolSize 개의 세션을 연다. 같은 라벨로 다시 부르면 기존 토큰을 돌려준다.
func (m *Module) Login(label, pin string, poolSize int) (*Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tokens[label]; ok {
		return t, nil
	}
	if poolSize < 1 {
		poolSize = 1
	}
	slot, ok, err := m.findSlot(label)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrTokenNotFound, label)
	}
	t := &Token{m: m, label: label, slot: slot, pool: make(chan pkcs11.SessionHandle, poolSize)}
	for i := 0; i < poolSize; i++ {
		sh, err := m.ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			t.closeAll()
			return nil, fmt.Errorf("hsm: C_OpenSession(%s): %w", label, err)
		}
		if i == 0 {
			// PKCS#11 로그인 상태는 같은 슬롯의 모든 세션에 적용된다.
			if err := m.ctx.Login(sh, pkcs11.CKU_USER, pin); err != nil && !isErr(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				_ = m.ctx.CloseSession(sh)
				t.closeAll()
				return nil, fmt.Errorf("hsm: C_Login(%s): %w", label, err)
			}
		}
		t.all = append(t.all, sh)
		t.pool <- sh
	}
	m.tokens[label] = t
	return t, nil
}

// Token 은 로그인된 토큰과 세션 풀이다.
type Token struct {
	m     *Module
	label string
	slot  uint
	pool  chan pkcs11.SessionHandle
	all   []pkcs11.SessionHandle
}

// Label 은 토큰 라벨이다.
func (t *Token) Label() string { return t.label }

func (t *Token) closeAll() {
	for _, sh := range t.all {
		_ = t.m.ctx.CloseSession(sh)
	}
	t.all = nil
}

// withSession 은 세션 하나를 독점해서 f 를 실행한다. 한 세션의 연산(SignInit/Sign 등)이 섞이지 않게 한다.
func (t *Token) withSession(ctx context.Context, f func(pkcs11.SessionHandle) error) error {
	var sh pkcs11.SessionHandle
	select {
	case sh = <-t.pool:
	case <-ctx.Done():
		return fmt.Errorf("hsm: 세션 대기: %w", ctx.Err())
	}
	defer func() { t.pool <- sh }()
	return f(sh)
}

// Ping 은 세션 상태를 조회해 토큰이 응답하는지 확인한다.
func (t *Token) Ping(ctx context.Context) error {
	return t.withSession(ctx, func(sh pkcs11.SessionHandle) error {
		info, err := t.m.ctx.GetSessionInfo(sh)
		if err != nil {
			return fmt.Errorf("hsm: C_GetSessionInfo(%s): %w", t.label, err)
		}
		if info.State != pkcs11.CKS_RW_USER_FUNCTIONS {
			return fmt.Errorf("hsm: 토큰 %s 세션이 사용자 로그인 상태가 아니다(state=%d)", t.label, info.State)
		}
		return nil
	})
}

// KeyAttrs 는 키 생성 속성이다. Extractable 은 키 부류(D-3)에서 정해 넘긴다.
type KeyAttrs struct {
	// Extractable 이 true 면 래핑으로만 내보낼 수 있는 루트 키다(CKA_SENSITIVE 는 항상 true).
	Extractable bool
	// ECParams 는 곡선(CKA_EC_PARAMS)이다. 비우면 secp256k1.
	ECParams []byte
}

// GenerateSecp256k1 은 EC 키 쌍(기본 secp256k1, attrs.ECParams 로 P-256)을 토큰 객체로 만들고 65바이트 비압축 공개키를 돌려준다.
// 같은 라벨(keyID)의 객체가 이미 있으면 거부한다.
func (t *Token) GenerateSecp256k1(ctx context.Context, keyID string, attrs KeyAttrs) ([]byte, error) {
	if keyID == "" {
		return nil, errors.New("hsm: keyID 가 비었다")
	}
	params := attrs.ECParams
	if params == nil {
		params = OIDSecp256k1
	}
	var pub []byte
	err := t.withSession(ctx, func(sh pkcs11.SessionHandle) error {
		for _, cls := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY} {
			hs, err := t.find(sh, cls, keyID)
			if err != nil {
				return err
			}
			if len(hs) > 0 {
				return fmt.Errorf("hsm: 키 %s 가 토큰 %s 에 이미 있다", keyID, t.label)
			}
		}
		pubTpl := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, params),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
			pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(keyID)),
		}
		privTpl := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, attrs.Extractable),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
			pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(keyID)),
		}
		ph, _, err := t.m.ctx.GenerateKeyPair(sh,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}, pubTpl, privTpl)
		if err != nil {
			return fmt.Errorf("hsm: C_GenerateKeyPair(%s): %w", keyID, err)
		}
		pub, err = t.ecPoint(sh, ph)
		return err
	})
	return pub, err
}

// PublicKey 는 keyID 공개키 객체의 65바이트 비압축 공개키를 돌려준다.
func (t *Token) PublicKey(ctx context.Context, keyID string) ([]byte, error) {
	var pub []byte
	err := t.withSession(ctx, func(sh pkcs11.SessionHandle) error {
		h, err := t.one(sh, pkcs11.CKO_PUBLIC_KEY, keyID)
		if err != nil {
			return err
		}
		pub, err = t.ecPoint(sh, h)
		return err
	})
	return pub, err
}

// HasPrivateKey 는 keyID 개인키 객체가 정확히 하나 있는지 확인한다.
func (t *Token) HasPrivateKey(ctx context.Context, keyID string) error {
	return t.withSession(ctx, func(sh pkcs11.SessionHandle) error {
		_, err := t.one(sh, pkcs11.CKO_PRIVATE_KEY, keyID)
		return err
	})
}

// SignDigest 는 keyID 개인키로 32바이트 다이제스트에 CKM_ECDSA 서명하고 64바이트 r||s 를 돌려준다.
func (t *Token) SignDigest(ctx context.Context, keyID string, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("hsm: 다이제스트 길이 %d (기대 32)", len(digest))
	}
	var sig []byte
	err := t.withSession(ctx, func(sh pkcs11.SessionHandle) error {
		h, err := t.one(sh, pkcs11.CKO_PRIVATE_KEY, keyID)
		if err != nil {
			return err
		}
		if err := t.m.ctx.SignInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, h); err != nil {
			return fmt.Errorf("hsm: C_SignInit(%s): %w", keyID, err)
		}
		sig, err = t.m.ctx.Sign(sh, digest)
		if err != nil {
			return fmt.Errorf("hsm: C_Sign(%s): %w", keyID, err)
		}
		if len(sig) != 64 {
			return fmt.Errorf("hsm: 서명 길이 %d (기대 64)", len(sig))
		}
		return nil
	})
	return sig, err
}

// Destroy 는 keyID 의 개인키·공개키 객체를 삭제하고, 남은 객체가 없는지 확인한다.
func (t *Token) Destroy(ctx context.Context, keyID string) error {
	return t.withSession(ctx, func(sh pkcs11.SessionHandle) error {
		found := 0
		for _, cls := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY} {
			hs, err := t.find(sh, cls, keyID)
			if err != nil {
				return err
			}
			for _, h := range hs {
				if err := t.m.ctx.DestroyObject(sh, h); err != nil {
					return fmt.Errorf("hsm: C_DestroyObject(%s): %w", keyID, err)
				}
				found++
			}
		}
		if found == 0 {
			return fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
		}
		for _, cls := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY} {
			hs, err := t.find(sh, cls, keyID)
			if err != nil {
				return err
			}
			if len(hs) != 0 {
				return fmt.Errorf("hsm: 삭제 후에도 키 %s 객체가 남아 있다", keyID)
			}
		}
		return nil
	})
}

// ObjectCount 는 keyID 라벨의 개인키·공개키 객체 수다(폐기 증적: 삭제 뒤 0 이어야 한다).
func (t *Token) ObjectCount(ctx context.Context, keyID string) (int, error) {
	n := 0
	err := t.withSession(ctx, func(sh pkcs11.SessionHandle) error {
		for _, cls := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY} {
			hs, err := t.find(sh, cls, keyID)
			if err != nil {
				return err
			}
			n += len(hs)
		}
		return nil
	})
	return n, err
}

func (t *Token) find(sh pkcs11.SessionHandle, class uint, label string) ([]pkcs11.ObjectHandle, error) {
	tpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := t.m.ctx.FindObjectsInit(sh, tpl); err != nil {
		return nil, fmt.Errorf("hsm: C_FindObjectsInit: %w", err)
	}
	hs, _, err := t.m.ctx.FindObjects(sh, 8)
	ferr := t.m.ctx.FindObjectsFinal(sh)
	if err != nil {
		return nil, fmt.Errorf("hsm: C_FindObjects: %w", err)
	}
	if ferr != nil {
		return nil, fmt.Errorf("hsm: C_FindObjectsFinal: %w", ferr)
	}
	return hs, nil
}

func (t *Token) one(sh pkcs11.SessionHandle, class uint, label string) (pkcs11.ObjectHandle, error) {
	hs, err := t.find(sh, class, label)
	if err != nil {
		return 0, err
	}
	switch len(hs) {
	case 0:
		return 0, fmt.Errorf("%w: %s (토큰 %s)", ErrKeyNotFound, label, t.label)
	case 1:
		return hs[0], nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrKeyDuplicated, label)
	}
}

func (t *Token) ecPoint(sh pkcs11.SessionHandle, h pkcs11.ObjectHandle) ([]byte, error) {
	attrs, err := t.m.ctx.GetAttributeValue(sh, h, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil)})
	if err != nil {
		return nil, fmt.Errorf("hsm: CKA_EC_POINT 조회: %w", err)
	}
	return ParseECPoint(attrs[0].Value)
}

// ParseECPoint 는 CKA_EC_POINT 값에서 65바이트 비압축 공개키를 꺼낸다.
func ParseECPoint(v []byte) ([]byte, error) {
	switch {
	case len(v) == 67 && v[0] == 0x04 && v[1] == 0x41 && v[2] == 0x04:
		return append([]byte(nil), v[2:]...), nil
	case len(v) == 65 && v[0] == 0x04:
		return append([]byte(nil), v...), nil
	}
	return nil, fmt.Errorf("hsm: 알 수 없는 CKA_EC_POINT 형식(길이 %d)", len(v))
}

func isErr(err error, code uint) bool {
	var pe pkcs11.Error
	return errors.As(err, &pe) && uint(pe) == code
}
