package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyops"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
)

// approverSet 은 키 작업과 온체인 단계 승인에 쓰는 보안관리자 키 파일들이다.
// 키 파일은 <keys-dir>/<ID>.json, 암호는 <passwords-dir>/approver_<ID>_password(비우면 터미널 입력).
type approverSet struct {
	ids       []string
	keysDir   string
	passwords string
}

func (s *approverSet) flags(c *cobra.Command) {
	c.Flags().StringArrayVar(&s.ids, "approver", nil, "보안관리자 ID(여러 번)")
	c.Flags().StringVar(&s.keysDir, "keys-dir", "deploy/approvers", "승인자 키 파일 디렉터리")
	c.Flags().StringVar(&s.passwords, "passwords-dir", "deploy/secrets", "승인자 암호 파일 디렉터리(비우면 터미널 입력, 시연용 설계서 14절)")
	_ = c.MarkFlagRequired("approver")
}

func (s *approverSet) keyFile(id string) string { return filepath.Join(s.keysDir, id+".json") }
func (s *approverSet) pwFile(id string) string {
	if s.passwords == "" {
		return ""
	}
	return filepath.Join(s.passwords, "approver_"+id+"_password")
}

// sign 은 키 작업 요청에 보안관리자마다 서명한다. 개인키는 서명 뒤 지운다.
func (s *approverSet) sign(r *keyops.Request) error {
	for _, id := range s.ids {
		got, priv, err := loadApproverKey(s.keyFile(id), s.pwFile(id))
		if err != nil {
			return err
		}
		if got != id {
			clear(priv)
			return fmt.Errorf("키 파일 %s 의 승인자 ID 가 %s 다", s.keyFile(id), got)
		}
		r.Sign(id, ed25519.PrivateKey(priv))
		clear(priv)
	}
	return nil
}

// approve 는 업무 요청을 보안관리자마다 승인한다(intent 를 보여 주고 로컬에서 해시를 다시 계산한다).
func (s *approverSet) approve(ctx context.Context, g *globals, id string) error {
	for _, a := range s.ids {
		if err := decide(ctx, g, id, approval.Approve, s.keyFile(a), s.pwFile(a)); err != nil {
			return err
		}
	}
	return nil
}

func (g *globals) keyOp(ctx context.Context, r keyops.Request, s *approverSet) (*keyops.Result, error) {
	if err := s.sign(&r); err != nil {
		return nil, err
	}
	cl, err := g.client(g.signerURL)
	if err != nil {
		return nil, err
	}
	var res keyops.Result
	if err := cl.do(ctx, "POST", "/v1/key-ops", r, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// waitStatus 는 요청이 want 가 될 때까지 기다린다. 다른 끝 상태면 오류다.
func (g *globals) waitStatus(ctx context.Context, id string, want workflow.Status, timeout time.Duration) (*workflow.Request, error) {
	cl, err := g.client(g.apidURL)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	final := map[workflow.Status]bool{workflow.StatusConfirmed: true, workflow.StatusFailed: true, workflow.StatusRejected: true, workflow.StatusExpired: true}
	for {
		var r workflow.Request
		if err := cl.do(ctx, "GET", "/v1/requests/"+id, nil, &r); err != nil {
			return nil, err
		}
		if r.Status == want {
			return &r, nil
		}
		if final[r.Status] {
			return &r, fmt.Errorf("요청 %s 가 %s 로 끝났다(기대 %s): %s", r.RequestID, r.Status, want, r.Error)
		}
		if time.Now().After(deadline) {
			return &r, fmt.Errorf("요청 %s 상태 %s (기대 %s, %s 대기)", r.RequestID, r.Status, want, timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// newKeyID 는 교체·추가 키 ID 를 만든다: key-<기관>-<용도>-<ULID 소문자>.
func newKeyID(inst string, p signer.Purpose) string {
	return fmt.Sprintf("key-%s-%s-%s", inst, strings.ToLower(strings.ReplaceAll(string(p), "_", "-")), strings.ToLower(ulid.Make().String()))
}

// purposeRole 은 키 용도가 종목 컨트랙트에서 갖는 역할이다(설계서 10.2). agent 는 기관 대응(D-17)이 필요한지다.
func purposeRole(p signer.Purpose) (role string, agent bool, err error) {
	switch p {
	case signer.PurposeIssue:
		return "ISSUER", true, nil
	case signer.PurposeTransfer:
		return "TRANSFER_AGENT", true, nil
	case signer.PurposeEmergency:
		return "CONTROLLER", false, nil
	case signer.PurposeContractAdmin:
		return "DEFAULT_ADMIN", false, nil
	}
	return "", false, fmt.Errorf("%s 키는 컨트랙트 역할이 없다(온체인 단계 없이 key generate/retire 를 쓴다)", p)
}

func keyCmd(g *globals) *cobra.Command {
	c := &cobra.Command{Use: "key", Short: "키 레지스트리 조회와 키 작업(생성·퇴역·폐기·교체, 설계서 9절)"}

	list := &cobra.Command{
		Use: "list", Short: "키 레지스트리(공개 정보)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			keys, err := g.keys(cmd.Context())
			if err != nil {
				return err
			}
			for _, k := range keys {
				fmt.Printf("%-44s %-10s %-9s %-15s %-9s %s\n", k.KeyID, k.LedgerID, k.InstitutionID, k.Purpose, k.Status, k.Address)
			}
			return nil
		},
	}

	var ledger, inst, purpose, keyID, rotatedFrom, successor, reason string
	var gen approverSet
	generate := &cobra.Command{
		Use: "generate", Short: "새 키를 만든다(같은 범위에 ACTIVE 키가 있거나 --rotated-from 이면 PENDING)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if keyID == "" {
				keyID = newKeyID(inst, signer.Purpose(purpose))
			}
			r := keyops.New(keyops.TypeGenerate, time.Now())
			r.LedgerID, r.InstitutionID, r.Purpose, r.KeyID, r.RotatedFrom, r.Reason = ledger, inst, signer.Purpose(purpose), keyID, rotatedFrom, reason
			res, err := g.keyOp(cmd.Context(), r, &gen)
			if err != nil {
				return err
			}
			return printJSON(res)
		},
	}
	generate.Flags().StringVar(&ledger, "ledger", "besu-local", "원장 ID")
	generate.Flags().StringVar(&inst, "institution", "", "기관 ID")
	generate.Flags().StringVar(&purpose, "purpose", "", "용도")
	generate.Flags().StringVar(&keyID, "key-id", "", "새 키 ID(비우면 자동)")
	generate.Flags().StringVar(&rotatedFrom, "rotated-from", "", "교체 대상 키 ID")
	generate.Flags().StringVar(&reason, "reason", "", "사유")
	gen.flags(generate)

	var ret approverSet
	retire := &cobra.Command{
		Use: "retire", Short: "키를 퇴역시킨다. --successor 를 주면 같은 트랜잭션에서 그 PENDING 키를 ACTIVE 로 바꾼다",
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := keyops.New(keyops.TypeRetire, time.Now())
			r.KeyID, r.Successor, r.Reason = keyID, successor, reason
			res, err := g.keyOp(cmd.Context(), r, &ret)
			if err != nil {
				return err
			}
			return printJSON(res)
		},
	}
	retire.Flags().StringVar(&keyID, "key", "", "퇴역시킬 키 ID")
	retire.Flags().StringVar(&successor, "successor", "", "활성화할 PENDING 후속 키 ID")
	retire.Flags().StringVar(&reason, "reason", "", "사유")
	ret.flags(retire)

	var des approverSet
	destroy := &cobra.Command{
		Use: "destroy", Short: "RETIRED 키의 HSM 객체를 지우고 남은 객체가 없는지 확인한다(폐기 증적)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := keyops.New(keyops.TypeDestroy, time.Now())
			r.KeyID, r.Reason = keyID, reason
			res, err := g.keyOp(cmd.Context(), r, &des)
			if err != nil {
				return err
			}
			return printJSON(res)
		},
	}
	destroy.Flags().StringVar(&keyID, "key", "", "폐기할 키 ID")
	destroy.Flags().StringVar(&reason, "reason", "", "사유")
	des.flags(destroy)
	for _, cc := range []*cobra.Command{generate, retire, destroy} {
		_ = cc.MarkFlagRequired("reason")
	}
	_ = generate.MarkFlagRequired("institution")
	_ = generate.MarkFlagRequired("purpose")
	_ = retire.MarkFlagRequired("key")
	_ = destroy.MarkFlagRequired("key")

	c.AddCommand(list, generate, retire, destroy, rotateCmd(g), ceremonyCmd(g), backupCmd(g), restoreCmd(g))
	return c
}

// rotateCmd 는 키 교체를 순서대로 진행한다(설계서 9절):
//
//	generate 새 키 생성(PENDING) → grant 종목마다 새 키에 역할 부여·기관 대응 → revoke 종목마다 이전 키 역할 회수·기관 대응 해제
//	→ retire 이전 키 퇴역과 새 키 활성화(한 트랜잭션)
//
// 온체인 단계는 모두 승인이 붙은 TX 요청이고(플랫폼 CONTRACT_ADMIN 키), 키 작업은 보안관리자 M명 서명이다.
// --until 로 단계 사이에서 멈출 수 있다(나머지는 --resume 으로 이어서, 또는 key retire 로 마무리).
func rotateCmd(g *globals) *cobra.Command {
	var ledger, inst, purpose, drafter, until, resume, reason string
	var only []string
	var appr approverSet
	var timeout time.Duration
	c := &cobra.Command{
		Use:   "rotate",
		Short: "키 교체: 새 키 생성 → 역할 부여 → 이전 역할 회수 → 이전 키 퇴역(새 키 활성화)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			p := signer.Purpose(purpose)
			role, agent, err := purposeRole(p)
			if err != nil {
				return err
			}
			old, err := g.activeKey(ctx, ledger, inst, purpose)
			if err != nil {
				return err
			}
			stop := func(phase string) bool {
				if until == phase {
					fmt.Printf("--until %s: 여기서 멈춘다. 이어서: stoctl key rotate ... --resume %s\n", phase, resume)
					return true
				}
				return false
			}
			phases := map[string]int{"": 0, "generate": 1, "grant": 2, "revoke": 3}
			start := 0
			if resume != "" {
				// --resume <새 키 ID>[@단계]: 그 단계 다음부터
				id, ph, _ := strings.Cut(resume, "@")
				resume = id
				start = phases[ph]
				k, err := g.keyByID(ctx, id)
				if err != nil {
					return err
				}
				if k.Status != "PENDING" {
					return fmt.Errorf("새 키 %s 가 PENDING 이 아니다(%s)", id, k.Status)
				}
			}
			fmt.Printf("교체 대상 %s (%s)\n", old.KeyID, old.Address)

			if start < 1 {
				r := keyops.New(keyops.TypeGenerate, time.Now())
				r.LedgerID, r.InstitutionID, r.Purpose, r.KeyID, r.RotatedFrom, r.Reason = ledger, inst, p, newKeyID(inst, p), old.KeyID, reason
				res, err := g.keyOp(ctx, r, &appr)
				if err != nil {
					return fmt.Errorf("새 키 생성: %w", err)
				}
				resume = res.KeyID + "@generate"
				fmt.Printf("1. 새 키 %s (%s) %s\n", res.KeyID, res.Address, res.Status)
				if stop("generate") {
					return nil
				}
				resume = res.KeyID
			}
			newKey, err := g.keyByID(ctx, resume)
			if err != nil {
				return err
			}
			secs, err := g.securities(ctx)
			if err != nil {
				return err
			}
			if len(only) > 0 {
				keep := map[string]bool{}
				for _, c := range only {
					keep[c] = true
				}
				var sel []security
				for _, s := range secs {
					if keep[s.IssueCode] {
						sel = append(sel, s)
					}
				}
				if len(sel) != len(keep) {
					return fmt.Errorf("--security 로 준 종목 중 없는 것이 있다")
				}
				secs = sel
			}
			run := func(label string, d workflow.DraftInput) error {
				d.InstitutionID, d.KeyPurpose, d.DrafterID, d.ExpiresInSeconds = "platform", "CONTRACT_ADMIN", drafter, 3600
				r, err := g.draft(ctx, d)
				if err != nil {
					return fmt.Errorf("%s 기안: %w", label, err)
				}
				if err := appr.approve(ctx, g, r.RequestID); err != nil {
					return fmt.Errorf("%s 승인: %w", label, err)
				}
				done, err := g.waitStatus(ctx, r.RequestID, workflow.StatusConfirmed, timeout)
				if err != nil {
					return fmt.Errorf("%s: %w", label, err)
				}
				fmt.Printf("   %-52s %s block=%d\n", label, r.RequestID, *done.BlockNumber)
				return nil
			}
			roleArg := contractRoles[role].Hex() // 소문자 0x + 64자(intent 의 bytes32 정규형)
			if start < 2 {
				fmt.Printf("2. 새 키에 역할 부여(종목 %d개)\n", len(secs))
				for _, s := range secs {
					if err := run(s.IssueCode+" grantRole "+role, workflow.DraftInput{Contract: s.ContractAddress,
						Function: "grantRole(bytes32,address)", Args: []string{roleArg, newKey.Address}}); err != nil {
						return err
					}
					if agent {
						if err := run(s.IssueCode+" setAgentInstitution "+inst, workflow.DraftInput{Contract: s.ContractAddress,
							Function: "setAgentInstitution(address,string)", Args: []string{newKey.Address, inst}}); err != nil {
							return err
						}
					}
				}
				resume = newKey.KeyID + "@grant"
				if stop("grant") {
					return nil
				}
			}
			if start < 3 {
				fmt.Printf("3. 이전 키 역할 회수(종목 %d개)\n", len(secs))
				for _, s := range secs {
					fn := "revokeRole(bytes32,address)"
					if p == signer.PurposeContractAdmin {
						fn = "renounceRole(bytes32,address)" // 관리 키는 스스로 포기한다(새 관리 키에 먼저 부여, 설계서 9절)
					}
					if err := run(s.IssueCode+" "+strings.SplitN(fn, "(", 2)[0]+" "+role, workflow.DraftInput{Contract: s.ContractAddress,
						Function: fn, Args: []string{roleArg, old.Address}}); err != nil {
						return err
					}
					if agent {
						if err := run(s.IssueCode+" setAgentInstitution 해제", workflow.DraftInput{Contract: s.ContractAddress,
							Function: "setAgentInstitution(address,string)", Args: []string{old.Address, ""}}); err != nil {
							return err
						}
					}
				}
				resume = newKey.KeyID + "@revoke"
				if stop("revoke") {
					return nil
				}
			}
			r := keyops.New(keyops.TypeRetire, time.Now())
			r.KeyID, r.Successor, r.Reason = old.KeyID, newKey.KeyID, reason
			res, err := g.keyOp(ctx, r, &appr)
			if err != nil {
				return fmt.Errorf("이전 키 퇴역: %w", err)
			}
			fmt.Printf("4. 이전 키 %s %s, 새 키 %s ACTIVE\n", res.KeyID, res.Status, res.Activate)
			fmt.Printf("NEW_KEY=%s\nOLD_KEY=%s\n", newKey.KeyID, old.KeyID)
			return nil
		},
	}
	c.Flags().StringVar(&ledger, "ledger", "besu-local", "원장 ID")
	c.Flags().StringVar(&inst, "institution", "", "기관 ID")
	c.Flags().StringVar(&purpose, "purpose", "", "용도(ISSUE, TRANSFER, EMERGENCY, CONTRACT_ADMIN)")
	c.Flags().StringVar(&drafter, "drafter", "", "온체인 단계 기안자(플랫폼 보안관리자, 승인자와 달라야 한다)")
	c.Flags().StringVar(&until, "until", "", "이 단계 뒤에 멈춘다(generate, grant, revoke)")
	c.Flags().StringVar(&resume, "resume", "", "이어서 진행: <새 키 ID>@<마친 단계>")
	c.Flags().StringVar(&reason, "reason", "키 교체", "사유")
	c.Flags().DurationVar(&timeout, "timeout", 120*time.Second, "요청마다 확정 대기")
	c.Flags().StringArrayVar(&only, "security", nil, "이 종목만(여러 번, 비우면 모든 종목). 빠진 종목에는 이전 키 역할이 남는다")
	appr.flags(c)
	for _, f := range []string{"institution", "purpose", "drafter"} {
		_ = c.MarkFlagRequired(f)
	}
	return c
}

type security struct {
	IssueCode         string `json:"issue_code"`
	Name              string `json:"name"`
	ContractAddress   string `json:"contract_address"`
	CirculationStatus string `json:"circulation_status"`
}

func (g *globals) securities(ctx context.Context) ([]security, error) {
	cl, err := g.client(g.apidURL)
	if err != nil {
		return nil, err
	}
	var v struct {
		Securities []security `json:"securities"`
	}
	if err := cl.do(ctx, "GET", "/v1/securities", nil, &v); err != nil {
		return nil, err
	}
	return v.Securities, nil
}
