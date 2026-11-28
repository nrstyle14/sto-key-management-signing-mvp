package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
)

func requestCmd(g *globals) *cobra.Command {
	c := &cobra.Command{Use: "request", Short: "업무 요청 기안·승인·반려·조회"}

	var d workflow.DraftInput
	var args string
	draft := &cobra.Command{
		Use:   "draft",
		Short: "요청을 기안한다(업무 서버가 request_id 와 만료 시각을 정한다)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if args != "" {
				d.Args = strings.Split(args, ",")
			}
			cl, err := g.client(g.apidURL)
			if err != nil {
				return err
			}
			var r workflow.Request
			if err := cl.do(cmd.Context(), "POST", "/v1/requests", d, &r); err != nil {
				return err
			}
			return printJSON(r)
		},
	}
	draft.Flags().StringVar(&d.InstitutionID, "institution", "", "기관 ID")
	draft.Flags().StringVar(&d.KeyPurpose, "purpose", "", "키 용도(ISSUE, TRANSFER, CONTRACT_ADMIN, EMERGENCY)")
	draft.Flags().StringVar(&d.Contract, "contract", "", "컨트랙트 주소(EIP-55). FABRIC_TX 는 <채널>/<체인코드>")
	draft.Flags().StringVar(&d.Function, "function", "", `함수 서명(예: "issue(address,uint256)")`)
	draft.Flags().StringVar(&args, "args", "", "인자(쉼표로 구분)")
	draft.Flags().StringVar(&d.DrafterID, "drafter", "", "기안자 ID")
	draft.Flags().IntVar(&d.ExpiresInSeconds, "expires-in", 3600, "만료까지 초")
	for _, f := range []string{"institution", "purpose", "contract", "function", "drafter"} {
		_ = draft.MarkFlagRequired(f)
	}

	draft.Flags().StringVar(&d.Type, "type", "TX", "요청 유형(TX, DEPLOY, FABRIC_TX)")
	draft.Flags().StringVar(&d.CodeHash, "code-hash", "", "DEPLOY 의 생성 바이트코드 keccak256")
	c.AddCommand(draft, decideCmd(g, approval.Approve), decideCmd(g, approval.Reject), waitCmd(g))

	show := &cobra.Command{
		Use: "show <request_id>", Short: "요청을 조회한다", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, a []string) error {
			cl, err := g.client(g.apidURL)
			if err != nil {
				return err
			}
			var r workflow.Request
			if err := cl.do(cmd.Context(), "GET", "/v1/requests/"+a[0], nil, &r); err != nil {
				return err
			}
			return printJSON(r)
		},
	}
	var status string
	list := &cobra.Command{
		Use: "list", Short: "요청 목록",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cl, err := g.client(g.apidURL)
			if err != nil {
				return err
			}
			var v struct {
				Requests []workflow.Request `json:"requests"`
			}
			if err := cl.do(cmd.Context(), "GET", "/v1/requests?status="+status, nil, &v); err != nil {
				return err
			}
			for _, r := range v.Requests {
				fmt.Printf("%s  %-16s %-8s %-10s %s\n", r.RequestID, r.Status, r.InstitutionID, r.DrafterID, r.TxHash)
			}
			return nil
		},
	}
	list.Flags().StringVar(&status, "status", "", "상태로 거르기")
	c.AddCommand(show, list)
	return c
}

// decideCmd 는 승인·반려 명령이다. 업무 서버가 준 해시에 서명하지 않고, intent 를 보여 준 뒤 로컬에서 해시를 다시 계산해 서명한다.
func decideCmd(g *globals, d approval.Decision) *cobra.Command {
	use, short := "approve", "요청을 승인한다(승인자 키로 서명)"
	if d == approval.Reject {
		use, short = "reject", "요청을 반려한다(승인자 키로 서명)"
	}
	var keyFile, pwFile string
	c := &cobra.Command{
		Use: use + " <request_id>", Short: short, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, a []string) error {
			return decide(cmd.Context(), g, a[0], d, keyFile, pwFile)
		},
	}
	c.Flags().StringVar(&keyFile, "key", "", "승인자 키 파일")
	c.Flags().StringVar(&pwFile, "password-file", "", "암호 파일(없으면 터미널 입력)")
	_ = c.MarkFlagRequired("key")
	return c
}

func decide(ctx context.Context, g *globals, id string, d approval.Decision, keyFile, pwFile string) error {
	cl, err := g.client(g.apidURL)
	if err != nil {
		return err
	}
	var r workflow.Request
	if err := cl.do(ctx, "GET", "/v1/requests/"+id, nil, &r); err != nil {
		return err
	}
	in, err := intent.Parse(r.Intent)
	if err != nil {
		return fmt.Errorf("intent 해석: %w", err)
	}
	if in.RequestID != id {
		return errors.New("요청 ID 와 intent 의 request_id 가 다르다")
	}
	h, err := in.Hash()
	if err != nil {
		return err
	}
	if hex.EncodeToString(h[:]) != r.IntentHash {
		return errors.New("업무 서버가 준 intent_hash 가 intent 에서 다시 계산한 값과 다르다(서명하지 않음)")
	}
	fmt.Printf("요청 %s (%s, %s)\n  원장 %s / 기관 %s / 키 용도 %s\n  컨트랙트 %s\n  함수 %s\n  인자 %s\n  기안자 %s, 만료 %s\n  intent_hash %x\n",
		in.RequestID, in.Type, r.Status, in.LedgerID, in.InstitutionID, in.KeyPurpose, in.Contract, in.Function,
		strings.Join(in.Args, ", "), in.DrafterID, in.ExpiresAt, h[:8])
	if in.Type == intent.TypeDeploy {
		fmt.Printf("  배포 바이트코드 keccak256 %s\n", in.CodeHash)
	}
	approverID, priv, err := loadApproverKey(keyFile, pwFile)
	if err != nil {
		return err
	}
	defer clear(priv)
	sig, err := approval.Sign(priv, h, d)
	if err != nil {
		return err
	}
	var out workflow.Request
	if err := cl.do(ctx, "POST", "/v1/requests/"+id+"/approvals",
		approval.Approval{ApproverID: approverID, Decision: d, Signature: hex.EncodeToString(sig)}, &out); err != nil {
		return err
	}
	fmt.Printf("%s %s → 상태 %s (승인·반려 %d건)\n", approverID, d, out.Status, len(out.Approvals))
	return nil
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
