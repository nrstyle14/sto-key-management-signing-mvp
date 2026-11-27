package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
)

// fetchRecords 는 서버의 감사 기록을 처음부터 끝까지 받는다.
func fetchRecords(ctx context.Context, c *client) ([]audit.Record, error) {
	var out []audit.Record
	from := uint64(1)
	for {
		var page struct {
			Records []audit.Record `json:"records"`
		}
		if err := c.do(ctx, "GET", fmt.Sprintf("/v1/audit/records?from=%d&limit=1000", from), nil, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Records...)
		if len(page.Records) < 1000 {
			return out, nil
		}
		from = page.Records[len(page.Records)-1].Seq + 1
	}
}

// trailCmd 는 한 요청(또는 대상)에 대한 두 감사 체인의 기록을 순서대로 보여 준다.
// --require 로 꼭 있어야 하는 action 을 주면 하나라도 없을 때 실패한다(스크립트의 증적 확인용).
func trailCmd(g *globals) *cobra.Command {
	var require string
	c := &cobra.Command{
		Use: "trail <request_id|subject>", Short: "요청 하나의 감사 기록(signer·api 두 체인)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, a []string) error {
			id := a[0]
			seen := map[string]bool{}
			for _, ch := range []struct{ name, url string }{{"api", g.apidURL}, {"signer", g.signerURL}} {
				cl, err := g.client(ch.url)
				if err != nil {
					return err
				}
				recs, err := fetchRecords(cmd.Context(), cl)
				if err != nil {
					return fmt.Errorf("%s 감사 기록: %w", ch.name, err)
				}
				for _, r := range recs {
					var p map[string]any
					_ = json.Unmarshal([]byte(r.PayloadJSON), &p)
					if r.Subject != id && p["request_id"] != id {
						continue
					}
					fmt.Printf("%-6s seq %-6d %s %-24s %-10s %s\n", ch.name, r.Seq, r.TS.UTC().Format("15:04:05.000"), r.Action, r.Actor, r.Subject)
					seen[ch.name+":"+r.Action] = true
					seen[r.Action] = true
				}
			}
			var missing []string
			for _, want := range strings.Split(require, ",") {
				if want = strings.TrimSpace(want); want != "" && !seen[want] {
					missing = append(missing, want)
				}
			}
			if len(missing) > 0 {
				return fmt.Errorf("감사 기록에 없다: %s", strings.Join(missing, ", "))
			}
			return nil
		},
	}
	c.Flags().StringVar(&require, "require", "", "꼭 있어야 하는 action 목록(쉼표, 체인을 지정하려면 api:ACTION·signer:ACTION)")
	return c
}

// headCmd 는 두 감사 체인의 머리 seq 다(스크립트의 단계별 감사 위치 기록용).
func headCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use: "head", Short: "두 감사 체인(signer, api)의 머리 seq",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var parts []string
			for _, ch := range []struct{ name, url string }{{"signer", g.signerURL}, {"api", g.apidURL}} {
				cl, err := g.client(ch.url)
				if err != nil {
					return err
				}
				var v struct {
					Seq uint64 `json:"seq"`
				}
				if err := cl.do(cmd.Context(), "GET", "/v1/audit/head", nil, &v); err != nil {
					return fmt.Errorf("%s 머리: %w", ch.name, err)
				}
				parts = append(parts, fmt.Sprintf("%s=%d", ch.name, v.Seq))
			}
			fmt.Println(strings.Join(parts, " "))
			return nil
		},
	}
}
