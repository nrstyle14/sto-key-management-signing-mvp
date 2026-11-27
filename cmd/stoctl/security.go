package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger/besu"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger/besu/sectoken"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
)

// 컨트랙트 역할 이름 → bytes32(설계서 10.2). DEFAULT_ADMIN_ROLE 은 0 이다.
var contractRoles = map[string]common.Hash{
	"DEFAULT_ADMIN":  {},
	"ISSUER":         crypto.Keccak256Hash([]byte("ISSUER_ROLE")),
	"TRANSFER_AGENT": crypto.Keccak256Hash([]byte("TRANSFER_AGENT_ROLE")),
	"CONTROLLER":     crypto.Keccak256Hash([]byte("CONTROLLER_ROLE")),
}

// keyInfo 는 서명 서버 키 레지스트리의 공개 정보다.
type keyInfo struct {
	KeyID         string `json:"key_id"`
	LedgerID      string `json:"ledger_id"`
	InstitutionID string `json:"institution_id"`
	Purpose       string `json:"purpose"`
	Address       string `json:"address"`
	Status        string `json:"status"`
}

func (g *globals) keys(ctx context.Context) ([]keyInfo, error) {
	cl, err := g.client(g.signerURL)
	if err != nil {
		return nil, err
	}
	var v struct {
		Keys []keyInfo `json:"keys"`
	}
	if err := cl.do(ctx, "GET", "/v1/keys", nil, &v); err != nil {
		return nil, fmt.Errorf("키 조회: %w", err)
	}
	return v.Keys, nil
}

// keyByID 는 key_id 의 키다.
func (g *globals) keyByID(ctx context.Context, id string) (*keyInfo, error) {
	list, err := g.keys(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].KeyID == id {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("키 %s 가 레지스트리에 없다", id)
}

// activeKey 는 (원장, 기관, 용도)의 ACTIVE 키 하나다.
func (g *globals) activeKey(ctx context.Context, ledger, inst, purpose string) (*keyInfo, error) {
	list, err := g.keys(ctx)
	if err != nil {
		return nil, err
	}
	var found []keyInfo
	for _, k := range list {
		if k.LedgerID == ledger && k.InstitutionID == inst && k.Purpose == purpose && k.Status == "ACTIVE" {
			found = append(found, k)
		}
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("(%s, %s, %s) 의 ACTIVE 키가 %d개다", ledger, inst, purpose, len(found))
	}
	return &found[0], nil
}

// resolveKey 는 키 ID 또는 "기관/용도"(그 범위의 ACTIVE 키)를 찾는다.
func (g *globals) resolveKey(ctx context.Context, ledger, ref string) (*keyInfo, error) {
	if inst, purpose, ok := strings.Cut(ref, "/"); ok {
		return g.activeKey(ctx, ledger, inst, purpose)
	}
	return g.keyByID(ctx, ref)
}

func (g *globals) draft(ctx context.Context, d workflow.DraftInput) (*workflow.Request, error) {
	cl, err := g.client(g.apidURL)
	if err != nil {
		return nil, err
	}
	var r workflow.Request
	if err := cl.do(ctx, "POST", "/v1/requests", d, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func securityCmd(g *globals) *cobra.Command {
	c := &cobra.Command{Use: "security", Short: "종목 배포·역할 부여 요청 기안과 종목 조회(설계서 10.2, T3.3)"}
	var ledger, drafter string
	var expires int
	c.PersistentFlags().StringVar(&ledger, "ledger", "besu-local", "원장 ID")
	c.PersistentFlags().StringVar(&drafter, "drafter", "", "기안자 ID(플랫폼 보안관리자)")
	c.PersistentFlags().IntVar(&expires, "expires-in", 3600, "만료까지 초")

	var name, code string
	deploy := &cobra.Command{
		Use:   "deploy",
		Short: "종목 배포 요청(DEPLOY)을 기안한다. 관리자는 플랫폼 CONTRACT_ADMIN 키, code_hash 는 커밋된 바인딩의 바이트코드다",
		RunE: func(cmd *cobra.Command, _ []string) error {
			admin, err := g.activeKey(cmd.Context(), ledger, "platform", "CONTRACT_ADMIN")
			if err != nil {
				return err
			}
			r, err := g.draft(cmd.Context(), workflow.DraftInput{
				Type: intent.TypeDeploy, InstitutionID: "platform", KeyPurpose: "CONTRACT_ADMIN", Contract: intent.ZeroAddress,
				Function: "constructor(string,string,address)", Args: []string{name, code, admin.Address},
				CodeHash: besu.SecurityTokenCodeHash().Hex(), DrafterID: drafter, ExpiresInSeconds: expires,
			})
			if err != nil {
				return err
			}
			fmt.Println(r.RequestID)
			return nil
		},
	}
	deploy.Flags().StringVar(&name, "name", "", "종목명")
	deploy.Flags().StringVar(&code, "code", "", "종목 코드")
	for _, f := range []string{"name", "code"} {
		_ = deploy.MarkFlagRequired(f)
	}

	var contract, role, keyID, revoke string
	grant := &cobra.Command{
		Use:   "grant-role",
		Short: "역할 부여(grantRole) 요청을 기안한다. --revoke 면 회수(revokeRole)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			h, ok := contractRoles[strings.ToUpper(role)]
			if !ok {
				return fmt.Errorf("알 수 없는 역할 %q (ISSUER, TRANSFER_AGENT, CONTROLLER, DEFAULT_ADMIN)", role)
			}
			k, err := g.resolveKey(cmd.Context(), ledger, keyID)
			if err != nil {
				return err
			}
			fn := "grantRole(bytes32,address)"
			if revoke == "true" {
				fn = "revokeRole(bytes32,address)"
			}
			r, err := g.draft(cmd.Context(), workflow.DraftInput{
				InstitutionID: "platform", KeyPurpose: "CONTRACT_ADMIN", Contract: common.HexToAddress(contract).Hex(),
				Function: fn, Args: []string{"0x" + strings.ToLower(common.Bytes2Hex(h[:])), k.Address},
				DrafterID: drafter, ExpiresInSeconds: expires,
			})
			if err != nil {
				return err
			}
			fmt.Println(r.RequestID)
			return nil
		},
	}
	grant.Flags().StringVar(&contract, "contract", "", "종목 컨트랙트 주소")
	grant.Flags().StringVar(&role, "role", "", "역할(ISSUER, TRANSFER_AGENT, CONTROLLER, DEFAULT_ADMIN)")
	grant.Flags().StringVar(&keyID, "key", "", `역할을 받을 키: 키 ID 또는 "기관/용도"(그 범위의 ACTIVE 키)`)
	grant.Flags().StringVar(&revoke, "revoke", "false", "true 면 회수")

	var inst string
	var clearAgent bool
	agent := &cobra.Command{
		Use:   "set-agent",
		Short: "기관 키 주소와 기관의 대응(setAgentInstitution) 요청을 기안한다(D-17)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			k, err := g.resolveKey(cmd.Context(), ledger, keyID)
			if err != nil {
				return err
			}
			if clearAgent {
				inst = "" // 대응 해제(역할 회수·도난 대응)
			} else if inst == "" {
				inst = k.InstitutionID
			}
			r, err := g.draft(cmd.Context(), workflow.DraftInput{
				InstitutionID: "platform", KeyPurpose: "CONTRACT_ADMIN", Contract: common.HexToAddress(contract).Hex(),
				Function: "setAgentInstitution(address,string)", Args: []string{k.Address, inst},
				DrafterID: drafter, ExpiresInSeconds: expires,
			})
			if err != nil {
				return err
			}
			fmt.Println(r.RequestID)
			return nil
		},
	}
	agent.Flags().StringVar(&contract, "contract", "", "종목 컨트랙트 주소")
	agent.Flags().StringVar(&keyID, "key", "", `키 ID 또는 "기관/용도"`)
	agent.Flags().StringVar(&inst, "institution", "", "기관 ID(비우면 키의 기관)")
	agent.Flags().BoolVar(&clearAgent, "clear", false, "기관 대응을 지운다")

	for _, cc := range []*cobra.Command{grant, agent} {
		_ = cc.MarkFlagRequired("contract")
		_ = cc.MarkFlagRequired("key")
	}
	for _, cc := range []*cobra.Command{deploy, grant, agent} {
		_ = cc.MarkFlagRequired("drafter")
	}

	list := &cobra.Command{
		Use: "list", Short: "종목 목록(종목 코드, 컨트랙트 주소, 유통 상태, 종목명을 탭으로 구분)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			secs, err := g.securities(cmd.Context())
			if err != nil {
				return err
			}
			for _, s := range secs {
				fmt.Printf("%s\t%s\t%s\t%s\n", s.IssueCode, s.ContractAddress, s.CirculationStatus, s.Name)
			}
			return nil
		},
	}
	var rpcURL, require string
	roles := &cobra.Command{
		Use:   "roles",
		Short: "레지스트리의 키마다 종목 컨트랙트의 역할과 기관 대응을 원장에서 읽는다(읽기 전용)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return showRoles(cmd.Context(), g, ledger, rpcURL, common.HexToAddress(contract), require)
		},
	}
	roles.Flags().StringVar(&contract, "contract", "", "종목 컨트랙트 주소")
	roles.Flags().StringVar(&rpcURL, "rpc", "http://127.0.0.1:8545", "원장 JSON-RPC 주소(로컬만)")
	roles.Flags().StringVar(&require, "require", "", `꼭 있어야 하는 "키참조=역할" 목록(쉼표). 키참조는 키 ID 또는 "기관/용도"`)
	_ = roles.MarkFlagRequired("contract")
	c.AddCommand(deploy, grant, agent, list, roles)
	return c
}

func showRoles(ctx context.Context, g *globals, ledgerID, rpcURL string, contract common.Address, require string) error {
	eth, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return err
	}
	defer eth.Close()
	tok, err := sectoken.NewSecurityTokenCaller(contract, eth)
	if err != nil {
		return err
	}
	keys, err := g.keys(ctx)
	if err != nil {
		return err
	}
	opts := &bind.CallOpts{Context: ctx}
	has := map[string]bool{} // "key_id=ROLE"
	names := []string{"DEFAULT_ADMIN", "ISSUER", "TRANSFER_AGENT", "CONTROLLER"}
	for _, k := range keys {
		if k.LedgerID != ledgerID {
			continue
		}
		addr := common.HexToAddress(k.Address)
		var held []string
		for _, n := range names {
			ok, err := tok.HasRole(opts, contractRoles[n], addr)
			if err != nil {
				return fmt.Errorf("hasRole(%s, %s): %w", n, k.KeyID, err)
			}
			if ok {
				held = append(held, n)
				has[k.KeyID+"="+n] = true
			}
		}
		inst, err := tok.AgentInstitution(opts, addr)
		if err != nil {
			return err
		}
		if inst != "" {
			has[k.KeyID+"=@"+inst] = true
		}
		fmt.Printf("%-28s %-8s %-15s %-8s 역할=%s 기관대응=%s\n", k.KeyID, k.InstitutionID, k.Purpose, k.Status, strings.Join(held, "|"), inst)
	}
	var missing []string
	for _, want := range strings.Split(require, ",") {
		want = strings.TrimSpace(want)
		if want == "" {
			continue
		}
		ref, role, ok := strings.Cut(want, "=")
		if !ok {
			return fmt.Errorf("--require 형식: 키참조=역할 (%q)", want)
		}
		k, err := g.resolveKey(ctx, ledgerID, ref)
		if err != nil {
			return err
		}
		if !has[k.KeyID+"="+role] {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("원장에 없는 역할·기관 대응: %s", strings.Join(missing, ", "))
	}
	return nil
}

// waitCmd 는 요청이 기대 상태(또는 끝 상태)가 될 때까지 기다린다. 기대와 다른 끝 상태면 오류다.
func waitCmd(g *globals) *cobra.Command {
	var want string
	var timeout time.Duration
	c := &cobra.Command{
		Use: "wait <request_id>", Short: "요청이 기대 상태가 될 때까지 기다린다(기본 CONFIRMED)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, a []string) error {
			cl, err := g.client(g.apidURL)
			if err != nil {
				return err
			}
			deadline := time.Now().Add(timeout)
			final := map[workflow.Status]bool{workflow.StatusConfirmed: true, workflow.StatusFailed: true,
				workflow.StatusRejected: true, workflow.StatusExpired: true}
			for {
				var r workflow.Request
				if err := cl.do(cmd.Context(), "GET", "/v1/requests/"+a[0], nil, &r); err != nil {
					return err
				}
				if string(r.Status) == strings.ToUpper(want) {
					return printJSON(r)
				}
				if final[r.Status] {
					_ = printJSON(r)
					return fmt.Errorf("요청 %s 가 %s 로 끝났다(기대 %s): %s", r.RequestID, r.Status, want, r.Error)
				}
				if time.Now().After(deadline) {
					return fmt.Errorf("요청 %s 상태 %s (기대 %s, %s 대기)", r.RequestID, r.Status, want, timeout)
				}
				time.Sleep(500 * time.Millisecond)
			}
		},
	}
	c.Flags().StringVar(&want, "status", "CONFIRMED", "기대 상태")
	c.Flags().DurationVar(&timeout, "timeout", 60*time.Second, "최대 대기")
	return c
}
