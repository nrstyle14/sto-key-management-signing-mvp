package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
)

func auditCmd(g *globals) *cobra.Command {
	c := &cobra.Command{Use: "audit", Short: "감사로그"}
	c.AddCommand(&cobra.Command{
		Use:   "verify",
		Short: "두 감사 체인(signer, api)을 받아 해시를 다시 계산하고 체크포인트 서명·머리를 확인한다",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return auditVerify(cmd.Context(), g)
		},
	}, &cobra.Command{
		Use:   "checkpoint",
		Short: "서명 서버에 지금 체크포인트를 만들게 한다",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cl, err := g.client(g.signerURL)
			if err != nil {
				return err
			}
			var v struct {
				Created []audit.Checkpoint `json:"created"`
			}
			if err := cl.do(cmd.Context(), "POST", "/v1/audit/checkpoints", nil, &v); err != nil {
				return err
			}
			for _, cp := range v.Created {
				fmt.Printf("체크포인트 #%d %-6s seq %d hash %x (키 %s)\n", cp.ID, cp.Chain, cp.Seq, cp.HeadHash[:8], cp.KeyID)
			}
			if len(v.Created) == 0 {
				fmt.Println("새 체크포인트 없음(머리가 바뀌지 않았다)")
			}
			return nil
		},
	})
	return c
}

// fetchChain 은 서버의 감사 기록을 처음부터 끝까지 페이지 단위로 받아 검증기에 넣는다.
func fetchChain(ctx context.Context, c *client) (*audit.Verifier, error) {
	v := audit.NewVerifier()
	from := uint64(1)
	for {
		var page struct {
			Records []audit.Record `json:"records"`
		}
		if err := c.do(ctx, "GET", fmt.Sprintf("/v1/audit/records?from=%d&limit=1000", from), nil, &page); err != nil {
			return nil, err
		}
		for _, r := range page.Records {
			v.Add(r)
		}
		if len(page.Records) < 1000 {
			break
		}
		from = page.Records[len(page.Records)-1].Seq + 1
	}
	return v, nil
}

func auditVerify(ctx context.Context, g *globals) error {
	failed := false
	hashes := map[string]map[uint64]audit.Hash{}
	for _, ch := range []struct{ name, url string }{{"signer", g.signerURL}, {"api", g.apidURL}} {
		c, err := g.client(ch.url)
		if err != nil {
			return err
		}
		v, err := fetchChain(ctx, c)
		if err != nil {
			return fmt.Errorf("%s 체인 조회: %w", ch.name, err)
		}
		res := v.Result()
		hashes[ch.name] = v.Hashes
		if res.OK {
			fmt.Printf("%-6s 체인: 정상 (레코드 %d, 머리 seq %d, hash %x)\n", ch.name, res.Count, res.HeadSeq, res.HeadHash[:8])
		} else {
			failed = true
			fmt.Printf("%-6s 체인: 실패 — 첫 오류 seq %d: %s (정상 레코드 %d)\n", ch.name, res.FirstBadSeq, res.Reason, res.Count)
		}
	}

	// 체크포인트: 서명은 레지스트리의 AUDIT 공개키로, 머리는 다시 계산한 체인으로 확인한다.
	sc, err := g.client(g.signerURL)
	if err != nil {
		return err
	}
	var cps struct {
		Checkpoints []audit.Checkpoint `json:"checkpoints"`
	}
	if err := sc.do(ctx, "GET", "/v1/audit/checkpoints", nil, &cps); err != nil {
		return fmt.Errorf("체크포인트 조회: %w", err)
	}
	var keys struct {
		Keys []struct {
			KeyID     string `json:"key_id"`
			Purpose   string `json:"purpose"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}
	if err := sc.do(ctx, "GET", "/v1/keys", nil, &keys); err != nil {
		return fmt.Errorf("키 조회: %w", err)
	}
	pubs := map[string][]byte{}
	for _, k := range keys.Keys {
		if k.Purpose == "AUDIT" {
			if b, err := hex.DecodeString(k.PublicKey); err == nil {
				pubs[k.KeyID] = b
			}
		}
	}
	bad := 0
	for _, chain := range []string{"signer", "api"} {
		var list []audit.Checkpoint
		for _, cp := range cps.Checkpoints {
			if cp.Chain == chain {
				list = append(list, cp)
			}
		}
		for _, r := range audit.VerifyCheckpoints(list, hashes[chain], pubs) {
			if !r.OK {
				bad++
				fmt.Printf("체크포인트 #%d %-6s seq %d: 실패 — %s\n", r.Checkpoint.ID, chain, r.Checkpoint.Seq, r.Reason)
			}
		}
		if len(list) > 0 {
			fmt.Printf("%-6s 체크포인트: %d건 확인 (마지막 seq %d)\n", chain, len(list), list[len(list)-1].Seq)
		} else {
			fmt.Printf("%-6s 체크포인트: 없음\n", chain)
		}
	}
	if bad > 0 {
		failed = true
	}
	if failed {
		return errors.New("감사 검증 실패")
	}
	return nil
}
