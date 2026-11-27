package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
)

// readPassword 는 암호를 파일이나 터미널 입력에서 읽는다. 명령행 인자·환경 변수로는 받지 않는다.
func readPassword(file, prompt string) ([]byte, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("암호 파일: %w", err)
		}
		pw := []byte(strings.TrimRight(string(b), "\r\n"))
		if len(pw) == 0 {
			return nil, errors.New("암호 파일이 비었다")
		}
		return pw, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("암호는 --password-file 또는 터미널 입력으로만 받는다")
	}
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return pw, err
}

// loadApproverKey 는 키 파일을 풀어 개인키를 돌려준다. 호출자는 다 쓴 뒤 clear 한다.
func loadApproverKey(keyFile, passwordFile string) (string, ed25519.PrivateKey, error) {
	kf, err := approval.ReadKeyFile(keyFile)
	if err != nil {
		return "", nil, err
	}
	pw, err := readPassword(passwordFile, kf.ApproverID+" 암호: ")
	if err != nil {
		return "", nil, err
	}
	defer clear(pw)
	priv, err := kf.Decrypt(pw)
	if err != nil {
		return "", nil, err
	}
	return kf.ApproverID, priv, nil
}

func approverCmd() *cobra.Command {
	c := &cobra.Command{Use: "approver", Short: "승인자 키"}

	var id, out, pwFile string
	keygen := &cobra.Command{
		Use:   "keygen",
		Short: "암호로 보호한 Ed25519 승인자 키 파일을 만든다(공개키만 출력)",
		RunE: func(*cobra.Command, []string) error {
			pw, err := readPassword(pwFile, id+" 새 암호: ")
			if err != nil {
				return err
			}
			defer clear(pw)
			kf, pub, err := approval.NewKeyFile(id, pw)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
				return err
			}
			if err := approval.WriteKeyFile(out, kf); err != nil {
				return err
			}
			fmt.Println(hex.EncodeToString(pub))
			return nil
		},
	}
	keygen.Flags().StringVar(&id, "id", "", "승인자 ID")
	keygen.Flags().StringVar(&out, "out", "", "키 파일 경로(이미 있으면 실패)")
	keygen.Flags().StringVar(&pwFile, "password-file", "", "암호 파일(없으면 터미널 입력)")
	_ = keygen.MarkFlagRequired("id")
	_ = keygen.MarkFlagRequired("out")

	var keyFile string
	pubkey := &cobra.Command{
		Use:   "pubkey",
		Short: "키 파일의 공개키(16진수)를 출력한다",
		RunE: func(*cobra.Command, []string) error {
			kf, err := approval.ReadKeyFile(keyFile)
			if err != nil {
				return err
			}
			pub, err := kf.Public()
			if err != nil {
				return err
			}
			fmt.Println(hex.EncodeToString(pub))
			return nil
		},
	}
	pubkey.Flags().StringVar(&keyFile, "key", "", "키 파일")
	_ = pubkey.MarkFlagRequired("key")

	var tmpl, keysDir, renderOut string
	render := &cobra.Command{
		Use:   "render-bootstrap",
		Short: "부트스트랩 템플릿의 @key:<승인자ID> 자리에 키 파일의 공개키를 넣는다",
		RunE: func(*cobra.Command, []string) error {
			b, err := os.ReadFile(tmpl)
			if err != nil {
				return err
			}
			re := regexp.MustCompile(`@key:([a-z0-9][a-z0-9._-]*)`)
			var rerr error
			outB := re.ReplaceAllFunc(b, func(m []byte) []byte {
				id := string(re.FindSubmatch(m)[1])
				kf, err := approval.ReadKeyFile(filepath.Join(keysDir, id+".json"))
				if err != nil {
					rerr = errors.Join(rerr, fmt.Errorf("%s: %w", id, err))
					return m
				}
				if kf.ApproverID != id {
					rerr = errors.Join(rerr, fmt.Errorf("%s: 키 파일의 approver_id 가 %s", id, kf.ApproverID))
				}
				return []byte(kf.PublicKey)
			})
			if rerr != nil {
				return rerr
			}
			if err := os.MkdirAll(filepath.Dir(renderOut), 0o700); err != nil {
				return err
			}
			return os.WriteFile(renderOut, outB, 0o600)
		},
	}
	render.Flags().StringVar(&tmpl, "template", "deploy/signerd/bootstrap.tmpl.yaml", "템플릿")
	render.Flags().StringVar(&keysDir, "keys", "deploy/approvers", "승인자 키 파일 디렉터리(<id>.json)")
	render.Flags().StringVar(&renderOut, "out", "deploy/signerd/generated/bootstrap.yaml", "출력 파일")

	c.AddCommand(keygen, pubkey, render)
	return c
}
