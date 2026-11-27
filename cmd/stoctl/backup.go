package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/backup"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyops"
)

// ceremonyCmd 는 래핑 키 의식이다(설계서 6.3 의 1, D-21).
// AES-256 래핑 키를 이 프로세스 메모리에서 만들고 Shamir k-of-n 으로 나눠 보관자별 조각 파일(0600)로 내보낸 뒤,
// 보안관리자 M명 서명으로 서명 서버에 보내 (원장, 기관) 토큰에 추출 불가 객체로 넣는다. 키와 조각은 화면에 출력하지 않는다.
func ceremonyCmd(g *globals) *cobra.Command {
	var ledger, inst, out, reason string
	var custodians []string
	var threshold int
	var appr approverSet
	c := &cobra.Command{
		Use:   "ceremony",
		Short: "래핑 키 의식: 래핑 키 생성 → Shamir 분할(보관자별 조각 파일) → HSM 주입",
		RunE: func(cmd *cobra.Command, _ []string) error {
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return err
			}
			defer clear(key)
			ceremonyID := ulid.Make().String()
			wrapID := "wrap-" + inst + "-" + strings.ToLower(ceremonyID)
			dir := filepath.Join(out, strings.ToLower(ceremonyID))
			shares, err := backup.Split(key, ceremonyID, wrapID, custodians, threshold, time.Now())
			if err != nil {
				return err
			}
			var written []string
			for _, s := range shares {
				p, err := backup.WriteShare(dir, s)
				if err != nil {
					return err
				}
				written = append(written, p)
			}
			r := keyops.New(keyops.TypeWrapInstall, time.Now())
			r.LedgerID, r.InstitutionID, r.KeyID, r.Reason = ledger, inst, wrapID, reason
			r.SecretSHA256 = backup.Commitment(key)
			r.Secret = hex.EncodeToString(key)
			res, err := g.keyOp(cmd.Context(), r, &appr)
			r.Secret = ""
			if err != nil {
				for _, p := range written { // 주입하지 못한 래핑 키의 조각은 남기지 않는다
					_ = os.Remove(p)
				}
				return fmt.Errorf("래핑 키 주입: %w", err)
			}
			fmt.Printf("의식 %s: 래핑 키 %s 를 (%s, %s) 토큰에 넣었다(%s)\n", ceremonyID, res.KeyID, ledger, inst, res.Status)
			fmt.Printf("조각 %d-of-%d, 보관자별 파일:\n", threshold, len(custodians))
			for _, p := range written {
				fmt.Println("  " + p)
			}
			fmt.Printf("WRAP_KEY=%s\nSHARES_DIR=%s\n", wrapID, dir)
			return nil
		},
	}
	c.Flags().StringVar(&ledger, "ledger", "besu-local", "원장 ID")
	c.Flags().StringVar(&inst, "institution", "platform", "루트 키가 든 토큰의 기관")
	c.Flags().StringArrayVar(&custodians, "custodian", []string{"custodian-1", "custodian-2", "custodian-3"}, "보관자 ID(여러 번)")
	c.Flags().IntVar(&threshold, "threshold", 2, "복구에 필요한 조각 수")
	c.Flags().StringVar(&out, "out", "deploy/ceremony", "조각 파일 상위 디렉터리(커밋 금지)")
	c.Flags().StringVar(&reason, "reason", "래핑 키 의식", "사유")
	appr.flags(c)
	return c
}

func backupCmd(g *globals) *cobra.Command {
	var keyID, wrapID, out, reason string
	var appr approverSet
	c := &cobra.Command{
		Use:   "backup",
		Short: "루트 키를 래핑 키로 C_WrapKey 해 백업 파일로 저장한다(설계서 6.3 의 2)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := keyops.New(keyops.TypeBackup, time.Now())
			r.KeyID, r.WrapKeyID, r.Reason = keyID, wrapID, reason
			res, err := g.keyOp(cmd.Context(), r, &appr)
			if err != nil {
				return err
			}
			if res.Backup == nil {
				return fmt.Errorf("서명 서버 응답에 백업이 없다")
			}
			if err := res.Backup.Validate(); err != nil {
				return err
			}
			if out == "" {
				out = filepath.Join("deploy/backups", keyID+"-"+time.Now().UTC().Format("20060102T150405Z")+".json")
			}
			if err := backup.WriteFile(out, res.Backup); err != nil {
				return err
			}
			fmt.Printf("백업 %s (%s, 주소 %s, %s) → %s\nBACKUP=%s\n", keyID, res.Backup.Purpose, res.Backup.Address, res.Backup.Mechanism, out, out)
			return nil
		},
	}
	c.Flags().StringVar(&keyID, "key", "", "루트 키 ID")
	c.Flags().StringVar(&wrapID, "wrap-key", "", "래핑 키 ID")
	c.Flags().StringVar(&out, "out", "", "백업 파일 경로(비우면 deploy/backups/<키>-<시각>.json, 커밋 금지)")
	c.Flags().StringVar(&reason, "reason", "루트 키 백업", "사유")
	appr.flags(c)
	_ = c.MarkFlagRequired("key")
	_ = c.MarkFlagRequired("wrap-key")
	return c
}

func restoreCmd(g *globals) *cobra.Command {
	var file, reason string
	var sharePaths []string
	var appr approverSet
	c := &cobra.Command{
		Use:   "restore",
		Short: "백업 파일을 토큰에 복원한다(토큰을 잃은 루트 키). 래핑 키가 토큰에 없으면 조각을 합쳐 함께 보낸다",
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := backup.ReadFile(file)
			if err != nil {
				return err
			}
			r := keyops.New(keyops.TypeRestore, time.Now())
			r.KeyID, r.WrapKeyID, r.Reason, r.Backup, r.BackupSHA256 = f.KeyID, f.WrapKeyID, reason, f, f.Hash()
			if len(sharePaths) > 0 {
				var shares []backup.Share
				for _, p := range sharePaths {
					s, err := backup.ReadShare(p)
					if err != nil {
						return err
					}
					shares = append(shares, s)
				}
				key, err := backup.Combine(shares)
				if err != nil {
					return err
				}
				r.SecretSHA256, r.Secret = backup.Commitment(key), hex.EncodeToString(key)
				clear(key)
			}
			res, err := g.keyOp(cmd.Context(), r, &appr)
			r.Secret = ""
			if err != nil {
				return err
			}
			return printJSON(res)
		},
	}
	c.Flags().StringVar(&file, "backup", "", "백업 파일")
	c.Flags().StringArrayVar(&sharePaths, "share", nil, "래핑 키 조각 파일(토큰에 래핑 키가 없을 때, threshold 개 이상)")
	c.Flags().StringVar(&reason, "reason", "루트 키 복원", "사유")
	appr.flags(c)
	_ = c.MarkFlagRequired("backup")
	return c
}
