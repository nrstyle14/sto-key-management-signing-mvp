package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/linked"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/policy"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/policychange"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
)

// accountCmd 는 연계장부 계좌(설계서 11절, T4.1)다.
func accountCmd(g *globals) *cobra.Command {
	c := &cobra.Command{Use: "account", Short: "연계장부 계좌 등록·조회와 보유 수량(설계서 11절)"}

	var in linked.RegisterInput
	reg := &cobra.Command{
		Use:   "register",
		Short: "계좌를 만들고(무작위 온체인 주소) 그 종목에 원장 계좌 등록 요청을 기안한다. 권리자 이름은 원장에 가지 않는다",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cl, err := g.client(g.apidURL)
			if err != nil {
				return err
			}
			var out struct {
				Account linked.Account   `json:"account"`
				Request workflow.Request `json:"request"`
			}
			if err := cl.do(cmd.Context(), "POST", "/v1/accounts", in, &out); err != nil {
				return err
			}
			return printJSON(map[string]any{"account_no": out.Account.AccountNo, "institution_id": out.Account.InstitutionID,
				"onchain_address": out.Account.OnchainAddress, "status": out.Account.Status, "request_id": out.Request.RequestID,
				"request_status": out.Request.Status})
		},
	}
	reg.Flags().StringVar(&in.AccountNo, "account-no", "", "계좌번호(비우면 업무 서버가 만든다)")
	reg.Flags().StringVar(&in.InstitutionID, "institution", "", "계좌관리기관")
	reg.Flags().StringVar(&in.HolderName, "holder", "", "모의 권리자 이름(연계장부에만 저장)")
	reg.Flags().StringVar(&in.IssueCode, "security", "", "원장에 등록할 종목 코드")
	reg.Flags().StringVar(&in.DrafterID, "drafter", "", "기안자(그 기관 담당자)")
	for _, f := range []string{"institution", "holder", "security", "drafter"} {
		_ = reg.MarkFlagRequired(f)
	}

	var regSec, regDrafter string
	addReg := &cobra.Command{
		Use: "add-registration <계좌번호>", Short: "기존 계좌를 다른 종목에 등록하는 요청을 기안한다", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := g.client(g.apidURL)
			if err != nil {
				return err
			}
			var r workflow.Request
			if err := cl.do(cmd.Context(), "POST", "/v1/accounts/"+url.PathEscape(args[0])+"/registrations",
				map[string]string{"issue_code": regSec, "drafter_id": regDrafter}, &r); err != nil {
				return err
			}
			return printJSON(map[string]any{"request_id": r.RequestID, "status": r.Status})
		},
	}
	addReg.Flags().StringVar(&regSec, "security", "", "종목 코드")
	addReg.Flags().StringVar(&regDrafter, "drafter", "", "기안자")
	_ = addReg.MarkFlagRequired("security")
	_ = addReg.MarkFlagRequired("drafter")

	show := &cobra.Command{
		Use: "show <계좌번호>", Short: "계좌와 보유 수량", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := g.client(g.apidURL)
			if err != nil {
				return err
			}
			var a linked.Account
			if err := cl.do(cmd.Context(), "GET", "/v1/accounts/"+url.PathEscape(args[0]), nil, &a); err != nil {
				return err
			}
			return printJSON(a)
		},
	}

	var inst string
	list := &cobra.Command{
		Use: "list", Short: "계좌 목록(계좌번호, 기관, 주소, 상태)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cl, err := g.client(g.apidURL)
			if err != nil {
				return err
			}
			var out struct {
				Accounts []linked.Account `json:"accounts"`
			}
			if err := cl.do(cmd.Context(), "GET", "/v1/accounts?institution="+url.QueryEscape(inst), nil, &out); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			for _, a := range out.Accounts {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.AccountNo, a.InstitutionID, a.OnchainAddress, a.Status)
			}
			return tw.Flush()
		},
	}
	list.Flags().StringVar(&inst, "institution", "", "기관(비우면 전체)")

	var hSec, hAcc string
	holdings := &cobra.Command{
		Use: "holdings", Short: "보유 수량(종목, 계좌, 수량)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cl, err := g.client(g.apidURL)
			if err != nil {
				return err
			}
			var out struct {
				Holdings []linked.Holding `json:"holdings"`
			}
			q := url.Values{"security": {hSec}, "account": {hAcc}}
			if err := cl.do(cmd.Context(), "GET", "/v1/holdings?"+q.Encode(), nil, &out); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			for _, h := range out.Holdings {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", h.IssueCode, h.AccountNo, h.Quantity)
			}
			return tw.Flush()
		},
	}
	holdings.Flags().StringVar(&hSec, "security", "", "종목 코드")
	holdings.Flags().StringVar(&hAcc, "account", "", "계좌번호")

	c.AddCommand(reg, addReg, show, list, holdings)
	return c
}

// policyCmd 는 정책 조회와 정책 변경(화이트리스트 추가, D-22)이다.
func policyCmd(g *globals) *cobra.Command {
	c := &cobra.Command{Use: "policy", Short: "정책 조회와 화이트리스트 추가(보안관리자 M명 서명, 설계서 7.2)"}

	list := &cobra.Command{
		Use: "list", Short: "ACTIVE 정책(정책 ID, 범위, 화이트리스트 사용 여부와 주소 수)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pols, err := g.policies(cmd)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			for _, p := range pols {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\twhitelist=%v\t%d\n", p.PolicyID, p.LedgerID, p.InstitutionID, p.KeyPurpose, p.Body.RecipientWhitelist, len(p.Whitelist))
			}
			return tw.Flush()
		},
	}

	var addr, account, reason string
	var policyIDs []string
	var s approverSet
	wl := &cobra.Command{
		Use:   "whitelist-add",
		Short: "주소(또는 연계장부 계좌의 주소)를 정책 화이트리스트에 추가한다. --policy 를 비우면 화이트리스트를 쓰는 ACTIVE 정책 전부",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if (addr == "") == (account == "") {
				return fmt.Errorf("--address 와 --account 중 하나만 준다")
			}
			if account != "" {
				cl, err := g.client(g.apidURL)
				if err != nil {
					return err
				}
				var a linked.Account
				if err := cl.do(ctx, "GET", "/v1/accounts/"+url.PathEscape(account), nil, &a); err != nil {
					return err
				}
				addr = a.OnchainAddress
				if reason == "" {
					reason = "연계장부 계좌 " + a.AccountNo + "(" + a.InstitutionID + ") 수신 허용"
				}
			}
			if !common.IsHexAddress(addr) {
				return fmt.Errorf("주소 %q 형식", addr)
			}
			if reason == "" {
				return fmt.Errorf("--reason 이 필요하다")
			}
			if len(policyIDs) == 0 {
				pols, err := g.policies(cmd)
				if err != nil {
					return err
				}
				for _, p := range pols {
					if p.Body.RecipientWhitelist {
						policyIDs = append(policyIDs, p.PolicyID)
					}
				}
			}
			r := policychange.NewWhitelistAdd(policyIDs, common.HexToAddress(addr), reason, time.Now())
			if err := s.sign(&r); err != nil {
				return err
			}
			cl, err := g.client(g.signerURL)
			if err != nil {
				return err
			}
			var res policychange.Result
			if err := cl.do(ctx, "POST", "/v1/policy-changes", r, &res); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "화이트리스트 추가 %s: 정책 %s (새로 추가 %d)\n", res.Address, strings.Join(res.PolicyIDs, ","), res.Added)
			return printJSON(res)
		},
	}
	wl.Flags().StringVar(&addr, "address", "", "추가할 주소")
	wl.Flags().StringVar(&account, "account", "", "연계장부 계좌번호(그 계좌의 온체인 주소를 추가)")
	wl.Flags().StringArrayVar(&policyIDs, "policy", nil, "정책 ID(여러 번)")
	wl.Flags().StringVar(&reason, "reason", "", "사유(--account 면 기본값이 있다)")
	s.flags(wl)

	c.AddCommand(list, wl)
	return c
}

func (g *globals) policies(cmd *cobra.Command) ([]policy.Policy, error) {
	cl, err := g.client(g.signerURL)
	if err != nil {
		return nil, err
	}
	var out struct {
		Policies []policy.Policy `json:"policies"`
	}
	if err := cl.do(cmd.Context(), "GET", "/v1/policies", nil, &out); err != nil {
		return nil, err
	}
	return out.Policies, nil
}
