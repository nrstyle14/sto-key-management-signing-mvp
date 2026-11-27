package hsm

import (
	"context"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

// 루트 키 백업·복구(설계서 6.3, D-11). 실측(docs/증빙/실측_HSM_래핑.md)으로 확정한 방식만 쓴다:
//   - 래핑 메커니즘 CKM_AES_KEY_WRAP_PAD, 래핑 키는 AES-256 토큰 객체(추출 불가, WRAP·UNWRAP 만)
//   - C_UnwrapKey 는 개인키 객체만 만든다. 공개키 객체는 백업 파일의 공개키로 따로 만든다.

// WrapMechanism 은 백업 파일에 기록하는 래핑 메커니즘 이름이다.
const WrapMechanism = "CKM_AES_KEY_WRAP_PAD"

// ErrExists 는 같은 라벨의 객체가 이미 있다는 뜻이다.
var ErrExists = errors.New("hsm: 같은 라벨의 객체가 이미 있다")

// InjectWrappingKey 는 AES-256 래핑 키를 추출 불가 토큰 객체로 넣는다. 같은 라벨이 있으면 거부한다.
// key 는 호출자가 사용 뒤 지운다.
func (t *Token) InjectWrappingKey(ctx context.Context, label string, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("hsm: 래핑 키는 32바이트(AES-256)여야 한다(%d)", len(key))
	}
	return t.withSession(ctx, func(sh pkcs11.SessionHandle) error {
		hs, err := t.find(sh, pkcs11.CKO_SECRET_KEY, label)
		if err != nil {
			return err
		}
		if len(hs) > 0 {
			return fmt.Errorf("%w: 래핑 키 %s (토큰 %s)", ErrExists, label, t.label)
		}
		_, err = t.m.ctx.CreateObject(sh, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, key),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
			pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, false),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, false),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		})
		if err != nil {
			return fmt.Errorf("hsm: 래핑 키 주입(C_CreateObject): %w", err)
		}
		return nil
	})
}

// HasWrappingKey 는 라벨의 AES 래핑 키 객체가 있는지다.
func (t *Token) HasWrappingKey(ctx context.Context, label string) (bool, error) {
	var ok bool
	err := t.withSession(ctx, func(sh pkcs11.SessionHandle) error {
		hs, err := t.find(sh, pkcs11.CKO_SECRET_KEY, label)
		ok = len(hs) == 1
		if len(hs) > 1 {
			return fmt.Errorf("%w: %s", ErrKeyDuplicated, label)
		}
		return err
	})
	return ok, err
}

// WrapPrivateKey 는 keyID 개인키를 래핑 키로 C_WrapKey 한 암호문을 돌려준다. 추출 불가 키는 HSM 이 거부한다.
func (t *Token) WrapPrivateKey(ctx context.Context, wrapLabel, keyID string) ([]byte, error) {
	var out []byte
	err := t.withSession(ctx, func(sh pkcs11.SessionHandle) error {
		w, err := t.one(sh, pkcs11.CKO_SECRET_KEY, wrapLabel)
		if err != nil {
			return fmt.Errorf("래핑 키: %w", err)
		}
		k, err := t.one(sh, pkcs11.CKO_PRIVATE_KEY, keyID)
		if err != nil {
			return err
		}
		out, err = t.m.ctx.WrapKey(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP_PAD, nil)}, w, k)
		if err != nil {
			return fmt.Errorf("hsm: C_WrapKey(%s): %w", keyID, err)
		}
		return nil
	})
	return out, err
}

// UnwrapPrivateKey 는 암호문을 래핑 키로 C_UnwrapKey 해 keyID 개인키 객체를 만들고, pub(65바이트 비압축)로 공개키 객체를 만든다.
// 같은 라벨의 키 객체가 있으면 거부한다. 복원한 개인키는 다시 백업할 수 있게 추출 가능(래핑으로만)으로 둔다(실측 문서).
func (t *Token) UnwrapPrivateKey(ctx context.Context, wrapLabel, keyID string, wrapped, pub []byte) error {
	if len(pub) != 65 || pub[0] != 0x04 {
		return errors.New("hsm: 공개키는 65바이트 비압축 형식이어야 한다")
	}
	return t.withSession(ctx, func(sh pkcs11.SessionHandle) error {
		for _, cls := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY} {
			hs, err := t.find(sh, cls, keyID)
			if err != nil {
				return err
			}
			if len(hs) > 0 {
				return fmt.Errorf("%w: 키 %s (토큰 %s)", ErrExists, keyID, t.label)
			}
		}
		w, err := t.one(sh, pkcs11.CKO_SECRET_KEY, wrapLabel)
		if err != nil {
			return fmt.Errorf("래핑 키: %w", err)
		}
		priv, err := t.m.ctx.UnwrapKey(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP_PAD, nil)}, w, wrapped, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
			pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(keyID)),
		})
		if err != nil {
			return fmt.Errorf("hsm: C_UnwrapKey(%s): %w", keyID, err)
		}
		// 공개키 객체: CKA_EC_POINT 는 DER OCTET STRING(04 41 ‖ 65바이트)으로 넣는다(생성한 키와 같은 형식).
		point := append([]byte{0x04, 0x41}, pub...)
		if _, err := t.m.ctx.CreateObject(sh, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, OIDSecp256k1),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, point),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
			pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(keyID)),
		}); err != nil {
			_ = t.m.ctx.DestroyObject(sh, priv)
			return fmt.Errorf("hsm: 공개키 객체(C_CreateObject %s): %w", keyID, err)
		}
		return nil
	})
}
