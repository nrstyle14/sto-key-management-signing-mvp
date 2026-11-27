// Package backup 은 루트 키 백업 파일과 래핑 키 조각(Shamir) 형식이다(설계서 6.3, FR-5.4, D-21).
//
//   - 래핑 키 의식: AES-256 래핑 키를 메모리에서 만들고 Shamir k-of-n 으로 나눠 보관자별 조각 파일로 내보낸다.
//     조각에는 래핑 키의 SHA-256 약속값(commitment)을 함께 적어, 합친 결과가 맞는지 바로 확인한다.
//     (Shamir 결합 자체에는 무결성 검사가 없다. 최종 확인은 복원한 키의 주소 일치다.)
//   - 백업 파일: C_WrapKey 암호문과 키 ID·공개키·주소·메커니즘·래핑 키 ID·생성 시각.
//
// Shamir 분할·결합은 검증된 공개 구현(OpenBao SDK helper/shamir, HashiCorp Vault 구현을 이어받음)을 쓴다.
// 이 패키지는 cgo·HSM 에 의존하지 않는다.
package backup

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
)

// 형식 버전
const (
	ShareVersion  = "sto-wrap-share-v1"
	BackupVersion = "sto-key-backup-v1"
	TimeLayout    = "2006-01-02T15:04:05Z"
	// Mechanism 은 래핑 메커니즘이다(D-11 실측으로 확정, 같은 HSM 구현으로만 복원한다고 가정).
	Mechanism = "CKM_AES_KEY_WRAP_PAD"
)

// Share 는 래핑 키 조각 파일 하나다(보관자 한 명).
type Share struct {
	Version    string `json:"version"`
	CeremonyID string `json:"ceremony_id"`
	WrapKeyID  string `json:"wrap_key_id"`
	Custodian  string `json:"custodian"`
	Threshold  int    `json:"threshold"`
	Total      int    `json:"total"`
	// Commitment 는 래핑 키의 SHA-256 이다(합친 결과 확인용).
	Commitment string `json:"commitment"`
	// Value 는 Shamir 조각(16진수)이다. 화면·로그에 내보내지 않는다.
	Value     string `json:"value"`
	CreatedAt string `json:"created_at"`
}

// File 은 루트 키 백업 파일이다.
type File struct {
	Version       string `json:"version"`
	KeyID         string `json:"key_id"`
	LedgerID      string `json:"ledger_id"`
	InstitutionID string `json:"institution_id"`
	Purpose       string `json:"purpose"`
	PublicKey     string `json:"public_key"` // 65바이트 비압축(16진수)
	Address       string `json:"address"`
	Mechanism     string `json:"mechanism"`
	WrapKeyID     string `json:"wrap_key_id"`
	Ciphertext    string `json:"ciphertext"` // C_WrapKey 결과(16진수)
	CreatedAt     string `json:"created_at"`
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Commitment 는 래핑 키의 SHA-256(16진수)다.
func Commitment(key []byte) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:])
}

// Split 은 래핑 키를 보관자 수만큼 나눈다. 조각 threshold 개가 있어야 다시 합칠 수 있다.
func Split(key []byte, ceremonyID, wrapKeyID string, custodians []string, threshold int, now time.Time) ([]Share, error) {
	if len(key) != 32 {
		return nil, errors.New("backup: 래핑 키는 32바이트여야 한다")
	}
	if !idRe.MatchString(wrapKeyID) {
		return nil, fmt.Errorf("backup: 래핑 키 ID 형식 %q", wrapKeyID)
	}
	seen := map[string]bool{}
	for _, c := range custodians {
		if !idRe.MatchString(c) || seen[c] {
			return nil, fmt.Errorf("backup: 보관자 ID %q 형식 오류 또는 중복", c)
		}
		seen[c] = true
	}
	if threshold < 2 || threshold > len(custodians) {
		return nil, fmt.Errorf("backup: threshold %d (2 이상, 보관자 수 %d 이하)", threshold, len(custodians))
	}
	parts, err := shamir.Split(key, len(custodians), threshold)
	if err != nil {
		return nil, fmt.Errorf("backup: Shamir 분할: %w", err)
	}
	commit := Commitment(key)
	out := make([]Share, len(custodians))
	for i, c := range custodians {
		out[i] = Share{Version: ShareVersion, CeremonyID: ceremonyID, WrapKeyID: wrapKeyID, Custodian: c, Threshold: threshold,
			Total: len(custodians), Commitment: commit, Value: hex.EncodeToString(parts[i]), CreatedAt: now.UTC().Format(TimeLayout)}
		clear(parts[i])
	}
	return out, nil
}

// Combine 은 같은 의식의 조각들을 합쳐 래핑 키를 돌려준다. 조각 수가 threshold 보다 적거나,
// 의식·래핑 키가 섞였거나, 합친 결과가 약속값과 다르면 실패한다. 돌려준 키는 호출자가 사용 뒤 지운다.
func Combine(shares []Share) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("backup: 조각이 없다")
	}
	first := shares[0]
	seen := map[string]bool{}
	parts := make([][]byte, 0, len(shares))
	defer func() {
		for _, p := range parts {
			clear(p)
		}
	}()
	for _, s := range shares {
		if s.Version != ShareVersion || s.CeremonyID != first.CeremonyID || s.WrapKeyID != first.WrapKeyID ||
			s.Commitment != first.Commitment || s.Threshold != first.Threshold || s.Total != first.Total {
			return nil, errors.New("backup: 서로 다른 의식·래핑 키의 조각이 섞였다")
		}
		if seen[s.Custodian] {
			return nil, fmt.Errorf("backup: 보관자 %s 의 조각이 중복됐다", s.Custodian)
		}
		seen[s.Custodian] = true
		b, err := hex.DecodeString(s.Value)
		if err != nil {
			return nil, fmt.Errorf("backup: 조각 %s 형식: %w", s.Custodian, err)
		}
		parts = append(parts, b)
	}
	if len(parts) < first.Threshold {
		return nil, fmt.Errorf("backup: 조각 %d개로는 복구할 수 없다(필요 %d개)", len(parts), first.Threshold)
	}
	key, err := shamir.Combine(parts)
	if err != nil {
		return nil, fmt.Errorf("backup: Shamir 결합: %w", err)
	}
	want, _ := hex.DecodeString(first.Commitment)
	got := sha256.Sum256(key)
	if len(key) != 32 || subtle.ConstantTimeCompare(got[:], want) != 1 {
		clear(key)
		return nil, errors.New("backup: 합친 래핑 키가 약속값과 다르다(조각이 손상됐거나 바뀌었다)")
	}
	return key, nil
}

// WriteShare 는 조각을 보관자별 파일(0600, 디렉터리 0700)로 쓴다. 같은 파일이 있으면 덮어쓰지 않는다.
func WriteShare(dir string, s Share) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, s.Custodian+".share")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return "", err
	}
	return path, f.Close()
}

// ReadShare 는 조각 파일을 읽는다.
func ReadShare(path string) (Share, error) {
	var s Share
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("backup: 조각 파일 %s: %w", path, err)
	}
	return s, nil
}

// Validate 는 백업 파일 형식과 공개키·주소 일치를 확인한다.
func (f *File) Validate() error {
	if f.Version != BackupVersion || f.Mechanism == "" || !idRe.MatchString(f.KeyID) || !idRe.MatchString(f.WrapKeyID) {
		return errors.New("backup: 백업 파일 형식 오류")
	}
	pub, err := hex.DecodeString(f.PublicKey)
	if err != nil || len(pub) != 65 || pub[0] != 0x04 {
		return errors.New("backup: 공개키 형식 오류")
	}
	pk, err := crypto.UnmarshalPubkey(pub)
	if err != nil {
		return fmt.Errorf("backup: 공개키: %w", err)
	}
	if crypto.PubkeyToAddress(*pk) != common.HexToAddress(f.Address) || !common.IsHexAddress(f.Address) {
		return errors.New("backup: 주소가 공개키와 맞지 않는다")
	}
	if _, err := hex.DecodeString(f.Ciphertext); err != nil || f.Ciphertext == "" {
		return errors.New("backup: 암호문 형식 오류")
	}
	return nil
}

// PublicKeyBytes 와 CiphertextBytes 는 Validate 를 통과한 파일에서만 쓴다.
func (f *File) PublicKeyBytes() []byte  { b, _ := hex.DecodeString(f.PublicKey); return b }
func (f *File) CiphertextBytes() []byte { b, _ := hex.DecodeString(f.Ciphertext); return b }

// Hash 는 백업 파일 정규 JSON 의 SHA-256(16진수)이다(키 작업 서명 대상에 넣는다).
func (f *File) Hash() string {
	b, _ := json.Marshal(f)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// WriteFile 은 백업 파일을 쓴다(0600). 같은 파일이 있으면 덮어쓰지 않는다.
func WriteFile(path string, f *File) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return err
	}
	return out.Close()
}

// ReadFile 은 백업 파일을 읽고 검증한다.
func ReadFile(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("backup: %s: %w", path, err)
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}
