package approval

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/scrypt"
)

// KeyFile 은 암호로 보호한 승인자 개인키 파일이다(설계서 5.2).
// 개인키(Ed25519 seed 32바이트)를 scrypt 로 유도한 키로 AES-256-GCM 암호화한다.
// approver_id 와 공개키를 AAD 로 묶어 파일의 어느 필드든 바꾸면 복호화가 실패한다.
type KeyFile struct {
	Version    int    `json:"version"`
	ApproverID string `json:"approver_id"`
	PublicKey  string `json:"public_key"`
	KDF        struct {
		Name string `json:"name"`
		N    int    `json:"n"`
		R    int    `json:"r"`
		P    int    `json:"p"`
		Salt string `json:"salt"`
	} `json:"kdf"`
	Cipher struct {
		Name       string `json:"name"`
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	} `json:"cipher"`
}

const (
	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
	aadTag  = "sto-approver-key-v1"
)

// ErrWrongPassword 는 암호가 틀렸거나 파일이 변조된 경우다.
var ErrWrongPassword = errors.New("approval: 키 파일을 풀 수 없다(암호가 틀렸거나 파일이 변조됨)")

func aad(id string, pub []byte) []byte {
	return []byte(aadTag + "|" + id + "|" + hex.EncodeToString(pub))
}

func deriveAEAD(password, salt []byte, n, r, p int) (cipher.AEAD, error) {
	k, err := scrypt.Key(password, salt, n, r, p, 32)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// NewKeyFile 은 새 Ed25519 키를 만들어 암호화한 파일 내용과 공개키를 돌려준다.
func NewKeyFile(approverID string, password []byte) (*KeyFile, ed25519.PublicKey, error) {
	if approverID == "" {
		return nil, nil, errors.New("approval: approver_id 가 필요하다")
	}
	if len(password) < 12 {
		return nil, nil, errors.New("approval: 암호는 12자 이상이어야 한다")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	seed := priv.Seed()
	defer clear(seed)
	defer clear(priv)
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	aead, err := deriveAEAD(password, salt, scryptN, scryptR, scryptP)
	if err != nil {
		return nil, nil, err
	}
	kf := &KeyFile{Version: 1, ApproverID: approverID, PublicKey: hex.EncodeToString(pub)}
	kf.KDF.Name, kf.KDF.N, kf.KDF.R, kf.KDF.P, kf.KDF.Salt = "scrypt", scryptN, scryptR, scryptP, hex.EncodeToString(salt)
	kf.Cipher.Name, kf.Cipher.Nonce = "AES-256-GCM", hex.EncodeToString(nonce)
	kf.Cipher.Ciphertext = hex.EncodeToString(aead.Seal(nil, nonce, seed, aad(approverID, pub)))
	return kf, pub, nil
}

// Public 은 파일의 공개키다(암호 없이 읽는다).
func (kf *KeyFile) Public() (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(kf.PublicKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("approval: 공개키 형식 오류")
	}
	return b, nil
}

// Decrypt 는 개인키를 푼다. 호출자는 다 쓴 뒤 clear 로 지운다.
func (kf *KeyFile) Decrypt(password []byte) (ed25519.PrivateKey, error) {
	if kf.Version != 1 || kf.KDF.Name != "scrypt" || kf.Cipher.Name != "AES-256-GCM" {
		return nil, errors.New("approval: 지원하지 않는 키 파일 형식")
	}
	pub, err := kf.Public()
	if err != nil {
		return nil, err
	}
	salt, err1 := hex.DecodeString(kf.KDF.Salt)
	nonce, err2 := hex.DecodeString(kf.Cipher.Nonce)
	ct, err3 := hex.DecodeString(kf.Cipher.Ciphertext)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, fmt.Errorf("approval: 키 파일 형식 오류: %w", err)
	}
	aead, err := deriveAEAD(password, salt, kf.KDF.N, kf.KDF.R, kf.KDF.P)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, ErrWrongPassword
	}
	seed, err := aead.Open(nil, nonce, ct, aad(kf.ApproverID, pub))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, ErrWrongPassword
	}
	defer clear(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	if !priv.Public().(ed25519.PublicKey).Equal(pub) {
		clear(priv)
		return nil, ErrWrongPassword
	}
	return priv, nil
}

// ReadKeyFile 은 파일을 읽는다.
func ReadKeyFile(path string) (*KeyFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf KeyFile
	if err := json.Unmarshal(b, &kf); err != nil {
		return nil, fmt.Errorf("approval: 키 파일 해석: %w", err)
	}
	return &kf, nil
}

// WriteKeyFile 은 파일을 소유자 전용(0600)으로 새로 쓴다. 이미 있으면 덮어쓰지 않는다.
func WriteKeyFile(path string, kf *KeyFile) error {
	b, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
