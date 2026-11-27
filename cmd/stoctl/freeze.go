package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/freeze"
)

// freezeCmd 는 서명 서버를 직접 호출한다(업무 서버가 죽어 있어도 동작, 설계서 7.3).
func freezeCmd(g *globals) *cobra.Command {
	c := &cobra.Command{Use: "freeze", Short: "키·기관·원장 서명 동결과 해제(서명 서버 직접 호출)"}
	for _, s := range []struct {
		use   string
		scope freeze.Scope
	}{{"key", freeze.ScopeKey}, {"institution", freeze.ScopeInstitution}, {"ledger", freeze.ScopeLedger}} {
		scope := s.scope
		var reason, keyFile, pwFile string
		cmd := &cobra.Command{
			Use: s.use + " <대상>", Short: fmt.Sprintf("%s 범위를 즉시 동결한다(보안관리자 1인 서명)", scope), Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, a []string) error {
				adminID, priv, err := loadApproverKey(keyFile, pwFile)
				if err != nil {
					return err
				}
				defer clear(priv)
				req := freeze.NewRequest(scope, a[0], reason, adminID, priv, time.Now())
				cl, err := g.client(g.signerURL)
				if err != nil {
					return err
				}
				var out map[string]any
				if err := cl.do(cmd.Context(), "POST", "/v1/freezes", req, &out); err != nil {
					return err
				}
				fmt.Printf("동결: freeze_id=%s %s %s (보안관리자 %s)\n", req.FreezeID, scope, a[0], adminID)
				return nil
			},
		}
		cmd.Flags().StringVar(&reason, "reason", "", "사유")
		cmd.Flags().StringVar(&keyFile, "key", "", "보안관리자 키 파일")
		cmd.Flags().StringVar(&pwFile, "password-file", "", "암호 파일(없으면 터미널 입력)")
		_ = cmd.MarkFlagRequired("reason")
		_ = cmd.MarkFlagRequired("key")
		c.AddCommand(cmd)
	}

	var keys, pws []string
	release := &cobra.Command{
		Use: "release <freeze_id>", Short: "동결을 해제한다(보안관리자 M명 서명: --key 를 여러 번)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, a []string) error {
			if len(pws) != 0 && len(pws) != len(keys) {
				return errors.New("--password-file 은 --key 와 같은 수만큼 준다")
			}
			req := freeze.NewRelease(a[0], time.Now())
			for i, k := range keys {
				pw := ""
				if len(pws) > 0 {
					pw = pws[i]
				}
				id, priv, err := loadApproverKey(k, pw)
				if err != nil {
					return err
				}
				req.SignRelease(id, priv)
				clear(priv)
			}
			cl, err := g.client(g.signerURL)
			if err != nil {
				return err
			}
			if err := cl.do(cmd.Context(), "POST", "/v1/freezes/"+a[0]+"/release", req, nil); err != nil {
				return err
			}
			fmt.Printf("해제: freeze_id=%s (서명 %d건)\n", a[0], len(req.Approvals))
			return nil
		},
	}
	release.Flags().StringArrayVar(&keys, "key", nil, "보안관리자 키 파일(여러 번)")
	release.Flags().StringArrayVar(&pws, "password-file", nil, "암호 파일(--key 순서대로)")
	_ = release.MarkFlagRequired("key")

	list := &cobra.Command{
		Use: "list", Short: "동결 목록",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cl, err := g.client(g.signerURL)
			if err != nil {
				return err
			}
			var v struct {
				Freezes []freeze.Entry `json:"freezes"`
			}
			if err := cl.do(cmd.Context(), "GET", "/v1/freezes", nil, &v); err != nil {
				return err
			}
			for _, f := range v.Freezes {
				state := "동결 중"
				if f.ReleasedAt != nil {
					state = "해제 " + f.ReleasedAt.Format(time.RFC3339)
				}
				fmt.Printf("%s  %-11s %-28s %-8s %s (%s)\n", f.FreezeID, f.Scope, f.Target, f.FrozenBy, state, f.Reason)
			}
			return nil
		},
	}
	c.AddCommand(release, list)
	return c
}
