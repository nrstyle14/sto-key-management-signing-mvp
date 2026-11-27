package policy

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
)

var (
	whitelisted = common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").Hex()
	stranger    = common.HexToAddress("0x00000000000000000000000000000000000000aA").Hex()
	contract    = common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3").Hex()
)

func pol() *Policy {
	return &Policy{PolicyID: "pol-inst-a-issue", Version: 1, LedgerID: "besu-local", InstitutionID: "inst-a", KeyPurpose: "ISSUE",
		Body: Body{AllowedFunctions: []string{"issue(address,uint256)", "redeem(address,uint256)"}, MaxAmount: "100000",
			RecipientWhitelist: true, RequiredApprovals: 2, ApproverGroup: "inst-a-approvers", GasLimitCap: 500000},
		Whitelist: []string{whitelisted}}
}

func in(fn string, args ...string) *intent.Intent {
	return &intent.Intent{LedgerID: "besu-local", InstitutionID: "inst-a", KeyPurpose: "ISSUE", Contract: contract, Function: fn, Args: args}
}

func code(err error) string {
	var v *Violation
	if errors.As(err, &v) {
		return v.Code
	}
	if err == nil {
		return ""
	}
	return "?" + err.Error()
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name string
		p    func(*Policy)
		in   *intent.Intent
		gas  uint64
		want string
	}{
		{"통과", nil, in("issue(address,uint256)", whitelisted, "1000"), 100000, ""},
		{"한도와 같은 수량은 통과", nil, in("issue(address,uint256)", whitelisted, "100000"), 100000, ""},
		{"수량 한도 초과", nil, in("issue(address,uint256)", whitelisted, "100001"), 100000, CodeAmountExceeded},
		{"매우 큰 수량(uint256 근처)", nil, in("issue(address,uint256)", whitelisted, "115792089237316195423570985008687907853269984665640564039457584007913129639935"), 100000, CodeAmountExceeded},
		{"화이트리스트 밖 수신 계좌", nil, in("issue(address,uint256)", stranger, "1"), 100000, CodeRecipientNotListed},
		{"허용되지 않은 함수", nil, in("transferByAgent(address,address,uint256)", whitelisted, whitelisted, "1"), 100000, CodeFunctionNotAllowed},
		{"가스 한도 상한 초과", nil, in("issue(address,uint256)", whitelisted, "1"), 500001, CodeGasLimitExceeded},
		{"redeem 은 수신 계좌 검사 없음", nil, in("redeem(address,uint256)", stranger, "5"), 100000, ""},
		{"매핑 없는 함수 + 한도", func(p *Policy) { p.Body.AllowedFunctions = append(p.Body.AllowedFunctions, "mint(address,uint256)") },
			in("mint(address,uint256)", whitelisted, "1"), 100000, CodeFunctionUnmapped},
		{"매핑 없는 함수 + 한도·화이트리스트 없음", func(p *Policy) {
			p.Body.AllowedFunctions = []string{"mint(address,uint256)"}
			p.Body.MaxAmount, p.Body.RecipientWhitelist = "", false
		}, in("mint(address,uint256)", stranger, "1"), 100000, ""},
		{"정책 범위 불일치(용도)", func(p *Policy) { p.KeyPurpose = "TRANSFER" }, in("issue(address,uint256)", whitelisted, "1"), 100000, CodeScopeMismatch},
		{"정책 범위 불일치(기관)", func(p *Policy) { p.InstitutionID = "inst-b" }, in("issue(address,uint256)", whitelisted, "1"), 100000, CodeScopeMismatch},
		{"화이트리스트 끈 정책", func(p *Policy) { p.Body.RecipientWhitelist = false }, in("issue(address,uint256)", stranger, "1"), 100000, ""},
		{"transferByAgent 수신 계좌는 두 번째 인자", func(p *Policy) {
			p.Body.AllowedFunctions = []string{"transferByAgent(address,address,uint256)"}
		}, in("transferByAgent(address,address,uint256)", whitelisted, stranger, "1"), 100000, CodeRecipientNotListed},
	}
	for _, c := range cases {
		p := pol()
		if c.p != nil {
			c.p(p)
		}
		if got := code(Evaluate(p, c.in, c.gas)); got != c.want {
			t.Errorf("%s: %q, 기대 %q", c.name, got, c.want)
		}
	}
}

func TestCheckApprovals(t *testing.T) {
	a := func(id, inst, decision string, groups ...string) ApproverRef {
		return ApproverRef{ApproverID: id, InstitutionID: inst, Groups: groups, Decision: decision}
	}
	g := "inst-a-approvers"
	cases := []struct {
		name string
		refs []ApproverRef
		want string
	}{
		{"2명 승인 통과", []ApproverRef{a("apr-a-02", "inst-a", "APPROVE", g), a("apr-a-03", "inst-a", "APPROVE", g)}, ""},
		{"승인 수 부족", []ApproverRef{a("apr-a-02", "inst-a", "APPROVE", g)}, CodeApprovalInsufficient},
		{"승인 없음", nil, CodeApprovalInsufficient},
		{"기안자 자기 승인", []ApproverRef{a("apr-a-01", "inst-a", "APPROVE", g), a("apr-a-02", "inst-a", "APPROVE", g)}, CodeApprovalSelf},
		{"같은 승인자 중복", []ApproverRef{a("apr-a-02", "inst-a", "APPROVE", g), a("apr-a-02", "inst-a", "APPROVE", g)}, CodeApprovalDuplicate},
		{"다른 기관 승인자", []ApproverRef{a("apr-a-02", "inst-a", "APPROVE", g), a("apr-b-01", "inst-b", "APPROVE", g)}, CodeApprovalInstitution},
		{"그룹 밖 승인자", []ApproverRef{a("apr-a-02", "inst-a", "APPROVE", g), a("apr-a-09", "inst-a", "APPROVE", "other")}, CodeApprovalGroup},
		{"반려 포함", []ApproverRef{a("apr-a-02", "inst-a", "APPROVE", g), a("apr-a-03", "inst-a", "REJECT", g)}, CodeApprovalRejected},
	}
	for _, c := range cases {
		if got := code(CheckApprovals(pol(), "apr-a-01", "inst-a", c.refs)); got != c.want {
			t.Errorf("%s: %q, 기대 %q", c.name, got, c.want)
		}
	}
}

func TestParseBody(t *testing.T) {
	ok := `{"allowed_functions":["issue(address,uint256)"],"max_amount":"100000","recipient_whitelist":true,"required_approvals":2,"approver_group":"g","gas_limit_cap":500000}`
	b, err := ParseBody([]byte(ok))
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := b.Canonical(); string(c) != ok {
		t.Fatalf("정규화: %s", c)
	}
	bad := map[string]string{
		"알 수 없는 필드":       `{"allowed_functions":["f()"],"required_approvals":1,"approver_group":"g","gas_limit_cap":1,"nonce":1}`,
		"숫자 max_amount":   `{"allowed_functions":["f()"],"max_amount":100000,"required_approvals":1,"approver_group":"g","gas_limit_cap":1}`,
		"선행 0 max_amount": `{"allowed_functions":["f()"],"max_amount":"0100","required_approvals":1,"approver_group":"g","gas_limit_cap":1}`,
		"소수 max_amount":   `{"allowed_functions":["f()"],"max_amount":"1.5","required_approvals":1,"approver_group":"g","gas_limit_cap":1}`,
		"승인 수 0":          `{"allowed_functions":["f()"],"required_approvals":0,"approver_group":"g","gas_limit_cap":1}`,
		"함수 서명 공백":        `{"allowed_functions":["f(address, uint256)"],"required_approvals":1,"approver_group":"g","gas_limit_cap":1}`,
		"그룹 없음":           `{"allowed_functions":["f()"],"required_approvals":1,"gas_limit_cap":1}`,
	}
	for name, raw := range bad {
		if _, err := ParseBody([]byte(raw)); err == nil {
			t.Errorf("%s: 허용됐다", name)
		}
	}
}

func TestHighAmount(t *testing.T) {
	p := pol()
	for amt, want := range map[string]bool{"79999": false, "80000": true, "100000": true, "1": false} {
		if got := HighAmount(p, in("issue(address,uint256)", whitelisted, amt)); got != want {
			t.Errorf("%s: %v", amt, got)
		}
	}
}
