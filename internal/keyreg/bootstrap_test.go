package keyreg

import (
	"strings"
	"testing"
)

func scopesForTest() map[string]TokenScope {
	return map[string]TokenScope{
		"besu-local.inst-a": {Label: "besu-local.inst-a", LedgerID: "besu-local", InstitutionID: "inst-a"},
	}
}

func TestBootstrapValidate(t *testing.T) {
	ok := BootstrapFile{
		Tokens: []BootstrapToken{{Label: "besu-local.inst-a"}},
		Keys:   []BootstrapKey{{KeyID: "k1", Token: "besu-local.inst-a", Purpose: "ISSUE"}},
	}
	if err := ok.Validate(scopesForTest()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]BootstrapFile{
		"설정에 없는 토큰":  {Tokens: []BootstrapToken{{Label: "nope"}}, Keys: ok.Keys},
		"목록 밖 토큰의 키": {Tokens: ok.Tokens, Keys: []BootstrapKey{{KeyID: "k1", Token: "other", Purpose: "ISSUE"}}},
		"알 수 없는 용도":  {Tokens: ok.Tokens, Keys: []BootstrapKey{{KeyID: "k1", Token: "besu-local.inst-a", Purpose: "MINT"}}},
		"key_id 중복":  {Tokens: ok.Tokens, Keys: append(ok.Keys, ok.Keys[0])},
		"승인자 공개키 길이": {Tokens: ok.Tokens, Keys: ok.Keys, Approvers: []BootstrapApprover{{ApproverID: "a", Name: "n", InstitutionID: "inst-a", Role: "APPROVER", Ed25519Pubkey: "abcd"}}},
		"승인자 역할":     {Tokens: ok.Tokens, Keys: ok.Keys, Approvers: []BootstrapApprover{{ApproverID: "a", Name: "n", InstitutionID: "inst-a", Role: "ROOT", Ed25519Pubkey: strings.Repeat("00", 32)}}},
	}
	for name, f := range cases {
		if err := f.Validate(scopesForTest()); err == nil {
			t.Errorf("%s: 검증을 통과했다", name)
		}
	}
}

func TestCompactJSONSortedNoEscape(t *testing.T) {
	b, err := compactJSON(map[string]any{"b": "<x>", "a": []any{"1"}})
	if err != nil || string(b) != `{"a":["1"],"b":"<x>"}` {
		t.Fatalf("%s %v", b, err)
	}
}
