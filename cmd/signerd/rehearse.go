package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/backup"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/hsm"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

// RehearsalKey 는 키 하나의 복구 리허설 결과다.
type RehearsalKey struct {
	KeyID           string `json:"key_id"`
	Purpose         string `json:"purpose"`
	BackupAddress   string `json:"backup_address"`
	RestoredAddress string `json:"restored_address"`
	AddressMatch    bool   `json:"address_match"`
	SignatureValid  bool   `json:"signature_valid"`
	Objects         int    `json:"objects"`
	Millis          int64  `json:"millis"`
}

// RehearsalResult 는 복구 리허설 결과다(비밀 없음: 키·조각·PIN 을 담지 않는다).
type RehearsalResult struct {
	StartedAt  string         `json:"started_at"`
	FinishedAt string         `json:"finished_at"`
	Token      string         `json:"token"`
	CeremonyID string         `json:"ceremony_id"`
	WrapKeyID  string         `json:"wrap_key_id"`
	Threshold  int            `json:"threshold"`
	Total      int            `json:"total"`
	Custodians []string       `json:"custodians_used"`
	Mechanism  string         `json:"mechanism"`
	Keys       []RehearsalKey `json:"keys"`
	OK         bool           `json:"ok"`
}

// rehearseCmd 는 복구 리허설이다(설계서 6.3 의 3, T3.6). 빈 토큰을 새로 만들어 조각으로 래핑 키를 복원·주입하고
// 백업 파일의 루트 키를 C_UnwrapKey 로 복원한 뒤, 복원한 키로 서명해 같은 주소가 나오는지 확인한다.
// 운영 토큰 볼륨이 아닌 일회용 토큰 디렉터리(scripts/rehearsal-restore.sh 의 tmpfs)에서만 실행한다.
// DB·네트워크를 쓰지 않는다. 래핑 키와 PIN 은 메모리에만 두고 끝나면 지운다.
func rehearseCmd() *cobra.Command {
	var lib, out string
	var backups, shares []string
	c := &cobra.Command{
		Use:   "rehearse-restore",
		Short: "복구 리허설: 일회용 빈 토큰에 조각으로 래핑 키를 복원하고 백업한 루트 키를 복원·검증한다",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := rehearse(cmd.Context(), lib, backups, shares)
			if res != nil {
				b, _ := json.MarshalIndent(res, "", "  ")
				if out != "" {
					if werr := os.WriteFile(out, append(b, '\n'), 0o644); werr != nil {
						return werr
					}
				} else {
					fmt.Println(string(b))
				}
			}
			return err
		},
	}
	c.Flags().StringVar(&lib, "library", "/usr/lib/softhsm/libsofthsm2.so", "PKCS#11 라이브러리")
	c.Flags().StringArrayVar(&backups, "backup", nil, "백업 파일(여러 번)")
	c.Flags().StringArrayVar(&shares, "share", nil, "래핑 키 조각 파일(여러 번)")
	c.Flags().StringVar(&out, "out", "", "결과 JSON 파일(비우면 표준 출력)")
	_ = c.MarkFlagRequired("backup")
	_ = c.MarkFlagRequired("share")
	return c
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func rehearse(ctx context.Context, lib string, backupPaths, sharePaths []string) (*RehearsalResult, error) {
	res := &RehearsalResult{StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Mechanism: backup.Mechanism}
	var list []backup.Share
	for _, p := range sharePaths {
		s, err := backup.ReadShare(p)
		if err != nil {
			return nil, err
		}
		list = append(list, s)
		res.Custodians = append(res.Custodians, s.Custodian)
	}
	if len(list) > 0 {
		res.CeremonyID, res.WrapKeyID, res.Threshold, res.Total = list[0].CeremonyID, list[0].WrapKeyID, list[0].Threshold, list[0].Total
	}
	key, err := backup.Combine(list)
	if err != nil {
		return res, fmt.Errorf("래핑 키 복원 실패: %w", err)
	}
	defer clear(key)

	m, err := hsm.Open(lib)
	if err != nil {
		return res, err
	}
	defer m.Close()
	suffix, _ := randHex(4)
	label := "rehearsal-" + suffix
	so, err := randHex(16)
	if err != nil {
		return res, err
	}
	pin, err := randHex(16)
	if err != nil {
		return res, err
	}
	if created, err := m.InitToken(label, so, pin); err != nil || !created {
		return res, fmt.Errorf("빈 토큰 초기화: created=%v %v", created, err)
	}
	tok, err := m.Login(label, pin, 2)
	if err != nil {
		return res, err
	}
	res.Token = label
	if err := tok.InjectWrappingKey(ctx, res.WrapKeyID, key); err != nil {
		return res, err
	}
	clear(key)

	res.OK = true
	for _, p := range backupPaths {
		f, err := backup.ReadFile(p)
		if err != nil {
			return res, err
		}
		if f.WrapKeyID != res.WrapKeyID {
			return res, fmt.Errorf("백업 %s 의 래핑 키 %s 가 조각의 %s 와 다르다", f.KeyID, f.WrapKeyID, res.WrapKeyID)
		}
		start := time.Now()
		k := RehearsalKey{KeyID: f.KeyID, Purpose: f.Purpose, BackupAddress: f.Address}
		if err := tok.UnwrapPrivateKey(ctx, f.WrapKeyID, f.KeyID, f.CiphertextBytes(), f.PublicKeyBytes()); err != nil {
			return res, fmt.Errorf("%s 복원: %w", f.KeyID, err)
		}
		k.Objects, _ = tok.ObjectCount(ctx, f.KeyID)
		var d [32]byte
		_, _ = rand.Read(d[:])
		raw, err := tok.SignDigest(ctx, f.KeyID, d[:])
		if err != nil {
			return res, fmt.Errorf("%s 서명: %w", f.KeyID, err)
		}
		r, s := new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])
		sig, err := signer.CompleteEVM(d, r, s, signer.PublicKey(f.PublicKeyBytes()))
		if err == nil {
			if pub, perr := crypto.SigToPub(d[:], sig[:]); perr == nil {
				k.RestoredAddress = crypto.PubkeyToAddress(*pub).Hex()
				k.SignatureValid = crypto.VerifySignature(crypto.FromECDSAPub(pub), d[:], sig[:64])
			}
		}
		k.AddressMatch = k.RestoredAddress != "" && common.HexToAddress(k.RestoredAddress) == common.HexToAddress(f.Address)
		k.Millis = time.Since(start).Milliseconds()
		if !k.AddressMatch || !k.SignatureValid || k.Objects != 2 {
			res.OK = false
		}
		res.Keys = append(res.Keys, k)
	}
	res.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if !res.OK {
		return res, fmt.Errorf("복원 확인 실패")
	}
	return res, nil
}
