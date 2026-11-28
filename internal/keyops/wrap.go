package keyops

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/backup"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

// secret 은 요청의 래핑 키 값을 약속값과 대조해 돌려준다. 호출자가 사용 뒤 지운다.
func secret(r Request) ([]byte, error) {
	key, err := hex.DecodeString(r.Secret)
	if err != nil || len(key) != 32 {
		return nil, fail(CodeSecret, "래핑 키는 16진수 32바이트여야 한다")
	}
	want, err := hex.DecodeString(r.SecretSHA256)
	got := sha256.Sum256(key)
	if err != nil || subtle.ConstantTimeCompare(got[:], want) != 1 {
		clear(key)
		return nil, fail(CodeSecret, "래핑 키가 서명된 약속값(secret_sha256)과 다르다")
	}
	return key, nil
}

func (e *Executor) wrapInstall(ctx context.Context, r Request, admins []string) (*Result, error) {
	tok, err := keyreg.TokenFor(ctx, e.DB, r.LedgerID, r.InstitutionID)
	if err != nil {
		return nil, fail(CodeInvalid, "%v", err)
	}
	key, err := secret(r)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if ok, err := e.Wrap.HasWrappingKey(ctx, tok.Label, r.KeyID); err != nil {
		return nil, fail(CodeHSM, "HSM 조회: %v", err)
	} else if !ok {
		if err := e.Wrap.InjectWrappingKey(ctx, tok.Label, r.KeyID, key); err != nil {
			return nil, fail(CodeHSM, "래핑 키 주입: %v", err)
		}
	}
	return &Result{OpID: r.OpID, Type: r.Type, KeyID: r.KeyID, Status: "INSTALLED"}, e.finish(ctx, r.OpID, audit.Entry{Actor: "signerd", Action: "KEY_WRAP_INSTALLED", Subject: r.KeyID,
		Payload: map[string]any{"request_id": r.OpID, "key_id": r.KeyID, "token": tok.Label, "commitment": r.SecretSHA256, "approvers": admins, "reason": r.Reason}})
}

func (e *Executor) backup(ctx context.Context, r Request, admins []string) (*Result, error) {
	k, err := keyreg.Get(ctx, e.DB, r.KeyID)
	if errors.Is(err, keyreg.ErrKeyNotFound) {
		return nil, fail(CodeKeyNotFound, "키 %s 가 없다", r.KeyID)
	}
	if err != nil {
		return nil, err
	}
	if k.Class != signer.ClassRoot {
		return nil, fail(CodeKeyState, "키 %s 는 %s 키다(루트 키만 백업, D-3)", k.KeyID, k.Class)
	}
	if k.Status != keyreg.StatusActive && k.Status != keyreg.StatusFrozen && k.Status != keyreg.StatusPending {
		return nil, fail(CodeKeyState, "키 %s 는 %s 다", k.KeyID, k.Status)
	}
	ct, err := e.Wrap.WrapPrivateKey(ctx, k.TokenLabel, r.WrapKeyID, k.KeyID)
	if err != nil {
		return nil, fail(CodeHSM, "%v", err)
	}
	f := &backup.File{Version: backup.BackupVersion, KeyID: k.KeyID, LedgerID: k.LedgerID, InstitutionID: k.InstitutionID,
		Purpose: string(k.Purpose), PublicKey: hex.EncodeToString(k.PublicKey), Address: k.Address.Hex(), Mechanism: backup.Mechanism,
		WrapKeyID: r.WrapKeyID, Ciphertext: hex.EncodeToString(ct), CreatedAt: time.Now().UTC().Format(backup.TimeLayout)}
	ctHash := sha256.Sum256(ct)
	if err := e.finish(ctx, r.OpID, audit.Entry{Actor: "signerd", Action: "KEY_BACKED_UP", Subject: k.KeyID, Payload: map[string]any{
		"request_id": r.OpID, "key_id": k.KeyID, "token": k.TokenLabel, "address": k.Address.Hex(), "target": r.WrapKeyID,
		"commitment": hex.EncodeToString(ctHash[:]), "approvers": admins, "reason": r.Reason}}); err != nil {
		return nil, err
	}
	return &Result{OpID: r.OpID, Type: r.Type, KeyID: k.KeyID, Status: string(k.Status), Address: k.Address.Hex(), Backup: f}, nil
}

// restore 는 레지스트리에 있지만 HSM 객체가 없어진(토큰 분실·재초기화) 루트 키를 백업에서 복원한다.
// 복원한 키로 서명한 뒤 공개키를 복구해 레지스트리 주소와 같은지 확인한다(Shamir·래핑에는 무결성 검사가 없다).
func (e *Executor) restore(ctx context.Context, r Request, admins []string) (*Result, error) {
	f := r.Backup
	if err := f.Validate(); err != nil {
		return nil, fail(CodeBackup, "%v", err)
	}
	if f.Hash() != r.BackupSHA256 || f.KeyID != r.KeyID || f.WrapKeyID != r.WrapKeyID || f.Mechanism != backup.Mechanism {
		return nil, fail(CodeBackup, "백업 파일이 서명된 요청(backup_sha256, key_id, wrap_key_id)과 다르다")
	}
	k, err := keyreg.Get(ctx, e.DB, r.KeyID)
	if errors.Is(err, keyreg.ErrKeyNotFound) {
		return nil, fail(CodeKeyNotFound, "키 %s 가 레지스트리에 없다", r.KeyID)
	}
	if err != nil {
		return nil, err
	}
	if k.Status == keyreg.StatusRetired || k.Status == keyreg.StatusDestroyed {
		return nil, fail(CodeKeyState, "키 %s 는 %s 다(복원하지 않는다)", k.KeyID, k.Status)
	}
	if k.Backend == signer.BackendMPC {
		return nil, fail(CodeKeyState, "키 %s 는 MPC 키다(백업·복원은 HSM 키만, D-25)", k.KeyID)
	}
	if k.Address != common.HexToAddress(f.Address) || hex.EncodeToString(k.PublicKey) != f.PublicKey {
		return nil, fail(CodeBackup, "백업 파일의 공개키가 레지스트리와 다르다")
	}
	n, err := e.HSM.ObjectCount(ctx, k.TokenLabel, k.KeyID)
	if err != nil {
		return nil, fail(CodeHSM, "HSM 조회: %v", err)
	}
	if n > 0 {
		return nil, fail(CodeKeyState, "키 %s 객체가 토큰에 이미 있다(복원 불필요)", k.KeyID)
	}
	if ok, err := e.Wrap.HasWrappingKey(ctx, k.TokenLabel, r.WrapKeyID); err != nil {
		return nil, fail(CodeHSM, "HSM 조회: %v", err)
	} else if !ok {
		key, err := secret(r)
		if err != nil {
			return nil, err
		}
		err = e.Wrap.InjectWrappingKey(ctx, k.TokenLabel, r.WrapKeyID, key)
		clear(key)
		if err != nil {
			return nil, fail(CodeHSM, "래핑 키 주입: %v", err)
		}
	}
	if err := e.Wrap.UnwrapPrivateKey(ctx, k.TokenLabel, r.WrapKeyID, k.KeyID, f.CiphertextBytes(), f.PublicKeyBytes()); err != nil {
		return nil, fail(CodeHSM, "%v", err)
	}
	if err := VerifyByRecover(ctx, e.Wrap, k.KeyID, k.PublicKey); err != nil {
		_ = e.HSM.DestroyIn(ctx, k.TokenLabel, k.KeyID) // 맞지 않는 키를 남기지 않는다
		return nil, fail(CodeRestore, "%v", err)
	}
	if err := e.finish(ctx, r.OpID, audit.Entry{Actor: "signerd", Action: "KEY_RESTORED", Subject: k.KeyID, Payload: map[string]any{
		"request_id": r.OpID, "key_id": k.KeyID, "token": k.TokenLabel, "address": k.Address.Hex(), "target": r.WrapKeyID,
		"approvers": admins, "reason": r.Reason}}); err != nil {
		return nil, err
	}
	return &Result{OpID: r.OpID, Type: r.Type, KeyID: k.KeyID, Status: string(k.Status), Address: k.Address.Hex()}, nil
}

// VerifyByRecover 는 keyID 로 무작위 다이제스트에 서명하고, (r, s) 에서 공개키를 복구해 want 공개키의 주소와 같은지 확인한다.
func VerifyByRecover(ctx context.Context, s interface {
	SignDigest(ctx context.Context, keyID string, digest [32]byte) (*big.Int, *big.Int, error)
}, keyID string, want signer.PublicKey) error {
	addr, err := want.Address()
	if err != nil {
		return err
	}
	var d [32]byte
	if _, err := rand.Read(d[:]); err != nil {
		return err
	}
	r, sv, err := s.SignDigest(ctx, keyID, d)
	if err != nil {
		return err
	}
	sig, err := signer.CompleteEVM(d, r, sv, want)
	if err != nil {
		return err
	}
	pub, err := crypto.SigToPub(d[:], sig[:])
	if err != nil {
		return err
	}
	if crypto.PubkeyToAddress(*pub) != addr {
		return errors.New("복원한 키의 서명에서 복구한 주소가 다르다")
	}
	return nil
}

// finish 는 key_ops 를 끝내고 감사 기록을 같은 트랜잭션으로 남긴다.
func (e *Executor) finish(ctx context.Context, opID string, entry audit.Entry) error {
	tx, err := e.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := done(ctx, tx, opID); err != nil {
		return err
	}
	if _, err := audit.Append(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}
