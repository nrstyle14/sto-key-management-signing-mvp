// Command stoctl 은 관리 CLI 다: 기안, 승인(승인자 키로 서명), 키 작업, 동결, 감사 검증(설계서 2절).
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/version"
)

type globals struct {
	certs     string
	signerURL string
	apidURL   string
}

func main() {
	g := &globals{}
	root := &cobra.Command{Use: "stoctl", Short: "토큰증권 키 관리·서명 시스템 관리 CLI", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().StringVar(&g.certs, "certs", "deploy/certs", "mTLS 인증서 디렉터리(ca.crt, stoctl.crt, stoctl.key)")
	root.PersistentFlags().StringVar(&g.signerURL, "signerd", "https://127.0.0.1:8443", "서명 서버 주소")
	root.PersistentFlags().StringVar(&g.apidURL, "apid", "https://127.0.0.1:9443", "업무 서버 주소")
	root.AddCommand(
		&cobra.Command{Use: "version", Run: func(*cobra.Command, []string) { fmt.Println(version.String("stoctl")) }},
		auditCmd(g),
		approverCmd(),
		requestCmd(g),
		freezeCmd(g),
		securityCmd(g),
		registryCmd(g),
		keyCmd(g),
	)
	if err := root.ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "오류:", err)
		os.Exit(1)
	}
}
