package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/recon"
)

// reconCmd 는 대사(설계서 11절, T4.2)다.
func reconCmd(g *globals) *cobra.Command {
	c := &cobra.Command{Use: "recon", Short: "연계장부·원장 대사 실행과 결과 조회(설계서 11절)"}

	var sec string
	var asJSON bool
	run := &cobra.Command{
		Use:   "run",
		Short: "대사를 실행한다(--security 를 비우면 전체 종목). 불일치가 있으면 결과를 보여 주고 종료 코드 3",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cl, err := g.client(g.apidURL)
			if err != nil {
				return err
			}
			var r recon.Run
			if err := cl.do(cmd.Context(), "POST", "/v1/recon/run", map[string]string{"issue_code": sec}, &r); err != nil {
				return err
			}
			if err := report(os.Stdout, &r, asJSON); err != nil {
				return err
			}
			if r.Status == recon.StatusMismatch {
				os.Exit(3)
			}
			return nil
		},
	}
	run.Flags().StringVar(&sec, "security", "", "종목 코드(비우면 전체)")
	run.Flags().BoolVar(&asJSON, "json", false, "JSON 으로 출력")

	show := &cobra.Command{
		Use: "show [run_id]", Short: "대사 결과와 불일치 상세(비우면 가장 최근)", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := "latest"
			if len(args) == 1 {
				if _, err := strconv.ParseUint(args[0], 10, 64); err != nil {
					return fmt.Errorf("run_id 형식: %s", args[0])
				}
				id = args[0]
			}
			cl, err := g.client(g.apidURL)
			if err != nil {
				return err
			}
			var r recon.Run
			if err := cl.do(cmd.Context(), "GET", "/v1/recon/runs/"+id, nil, &r); err != nil {
				return err
			}
			return report(os.Stdout, &r, asJSON)
		},
	}
	show.Flags().BoolVar(&asJSON, "json", false, "JSON 으로 출력")

	list := &cobra.Command{
		Use: "list", Short: "최근 대사 실행(run_id, 범위, 상태, 불일치 수, 시각)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cl, err := g.client(g.apidURL)
			if err != nil {
				return err
			}
			var out struct {
				Runs []recon.Run `json:"runs"`
			}
			if err := cl.do(cmd.Context(), "GET", "/v1/recon/runs", nil, &out); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			for _, r := range out.Runs {
				scope := r.Scope
				if scope == "" {
					scope = "(전체)"
				}
				fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%s\n", r.RunID, scope, r.Status, r.DiffCount, r.StartedAt.Format("2006-01-02T15:04:05Z"))
			}
			return tw.Flush()
		},
	}
	c.AddCommand(run, show, list)
	return c
}

// report 는 대사 결과를 사람이 읽기 쉽게 쓴다.
func report(w io.Writer, r *recon.Run, asJSON bool) error {
	if asJSON {
		return printJSON(r)
	}
	scope := r.Scope
	if scope == "" {
		scope = "전체 종목"
	}
	fmt.Fprintf(w, "대사 #%d (%s): %s, 불일치 %d건\n", r.RunID, scope, r.Status, r.DiffCount)
	if r.Error != "" {
		fmt.Fprintf(w, "  오류: %s\n", r.Error)
	}
	for _, s := range r.Securities {
		fmt.Fprintf(w, "  %s 블록 %d: 총발행량 %s, 연계장부 합계 %s, 계좌 %d, 불일치 %d\n", s.IssueCode, s.BlockNumber, s.TotalSupply, s.Holdings, s.Accounts, s.Diffs)
	}
	if len(r.Diffs) == 0 {
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "  종목\t비교\t계좌\t주소\t원장(기대)\t연계장부(실제)\t블록")
	for _, d := range r.Diffs {
		acc, addr := d.AccountNo, d.Address
		if acc == "" {
			acc = "-"
		}
		if addr == "" {
			addr = "-"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%d\n", d.IssueCode, d.Kind, acc, addr, d.Expected, d.Actual, d.BlockNumber)
	}
	return tw.Flush()
}
