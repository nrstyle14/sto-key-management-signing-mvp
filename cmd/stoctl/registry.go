package main

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/registry"
)

func registryCmd(g *globals) *cobra.Command {
	c := &cobra.Command{Use: "registry", Short: "보존된 원장 이벤트(전자등록정보) 조회(설계서 10.4)"}
	var contract string
	events := &cobra.Command{
		Use: "events", Short: "종목의 원장 이벤트를 블록·로그 순서로 보여 준다",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cl, err := g.client(g.apidURL)
			if err != nil {
				return err
			}
			after := uint64(0)
			for {
				var v struct {
					Events []registry.Event `json:"events"`
				}
				q := url.Values{"contract": {contract}, "after": {fmt.Sprint(after)}, "limit": {"1000"}}
				if err := cl.do(cmd.Context(), "GET", "/v1/registry-events?"+q.Encode(), nil, &v); err != nil {
					return err
				}
				for _, e := range v.Events {
					keys := make([]string, 0, len(e.Payload))
					for k := range e.Payload {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					parts := make([]string, 0, len(keys))
					for _, k := range keys {
						parts = append(parts, k+"="+e.Payload[k])
					}
					fmt.Printf("%-8d %-4d %s %-26s %s\n", e.BlockNumber, e.LogIndex, e.BlockTime.Format("15:04:05"), e.Event, strings.Join(parts, " "))
					after = e.ID
				}
				if len(v.Events) < 1000 {
					return nil
				}
			}
		},
	}
	events.Flags().StringVar(&contract, "contract", "", "종목 컨트랙트 주소(비우면 전체)")
	c.AddCommand(events)
	return c
}
