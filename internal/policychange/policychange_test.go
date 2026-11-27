package policychange

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyops"
)

var testAddr = common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

// 서명 대상은 도메인으로 시작하고 모든 필드에 묶인다(승인 목록은 대상이 아니다).
func TestMessageBindsFieldsAndDomain(t *testing.T) {
	r := NewWhitelistAdd([]string{"pol-b", "pol-a"}, testAddr, "계좌 추가", time.Now())
	if strings.Join(r.PolicyIDs, ",") != "pol-a,pol-b" || r.Address != testAddr.Hex() || r.Type != TypeWhitelistAdd {
		t.Fatalf("NewWhitelistAdd 정규화: %+v", r)
	}
	base := r.Message()
	if !bytes.HasPrefix(base, []byte(Domain)) {
		t.Fatal("서명 대상에 도메인이 없다")
	}
	for name, mut := range map[string]func(*Request){
		"change_id": func(x *Request) { x.ChangeID = "01ARZ3NDEKTSV4RRFFQ69G5FAV" },
		"type":      func(x *Request) { x.Type = "WHITELIST_REMOVE" },
		"policy":    func(x *Request) { x.PolicyIDs = []string{"pol-a"} },
		"address":   func(x *Request) { x.Address = common.HexToAddress("0x01").Hex() },
		"reason":    func(x *Request) { x.Reason = "x" },
		"time":      func(x *Request) { x.RequestedAt = "2000-01-01T00:00:00Z" },
	} {
		c := r
		c.PolicyIDs = append([]string(nil), r.PolicyIDs...)
		mut(&c)
		if bytes.Equal(c.Message(), base) {
			t.Errorf("%s 를 바꿔도 서명 대상이 같다", name)
		}
	}
	c := r
	c.Approvals = append(c.Approvals, c.Approvals...)
	if !bytes.Equal(c.Message(), base) {
		t.Error("승인 목록이 서명 대상에 들어갔다")
	}
	// 키 작업 서명 대상과 도메인이 다르다
	k := keyops.New(keyops.TypeDestroy, time.Now())
	if bytes.HasPrefix(k.Message(), []byte(Domain)) || bytes.HasPrefix(base, []byte(keyops.Domain)) {
		t.Fatal("정책 변경과 키 작업의 도메인이 겹친다")
	}
}

func TestValidate(t *testing.T) {
	now := time.Date(2026, 11, 28, 0, 0, 0, 0, time.UTC)
	e := &Executor{}
	ok := NewWhitelistAdd([]string{"pol-a"}, testAddr, "계좌 추가", now)
	if err := e.validate(ok, now); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		mut  func(*Request)
		code string
	}{
		"change_id 소문자":     {func(r *Request) { r.ChangeID = strings.ToLower(r.ChangeID) }, CodeInvalid},
		"알 수 없는 종류":         {func(r *Request) { r.Type = "POLICY_BODY" }, CodeInvalid},
		"사유 없음":             {func(r *Request) { r.Reason = "" }, CodeInvalid},
		"정책 없음":             {func(r *Request) { r.PolicyIDs = nil }, CodeInvalid},
		"정책 정렬 안 됨":         {func(r *Request) { r.PolicyIDs = []string{"pol-b", "pol-a"} }, CodeInvalid},
		"정책 중복":             {func(r *Request) { r.PolicyIDs = []string{"pol-a", "pol-a"} }, CodeInvalid},
		"정책 ID 형식":          {func(r *Request) { r.PolicyIDs = []string{"Pol A"} }, CodeInvalid},
		"주소 소문자(EIP-55 아님)": {func(r *Request) { r.Address = strings.ToLower(r.Address) }, CodeInvalid},
		"0 주소":              {func(r *Request) { r.Address = common.Address{}.Hex() }, CodeInvalid},
		"시각 형식":             {func(r *Request) { r.RequestedAt = "2026-11-28T00:00:00.5Z" }, CodeInvalid},
		"6분 전":              {func(r *Request) { r.RequestedAt = now.Add(-6 * time.Minute).Format(TimeLayout) }, CodeStale},
		"6분 뒤":              {func(r *Request) { r.RequestedAt = now.Add(6 * time.Minute).Format(TimeLayout) }, CodeStale},
	}
	for name, c := range cases {
		r := ok
		r.PolicyIDs = append([]string(nil), ok.PolicyIDs...)
		c.mut(&r)
		var pe *Error
		if err := e.validate(r, now); !errors.As(err, &pe) || pe.Code != c.code {
			t.Errorf("%s: 기대 %s, 받은 %v", name, c.code, err)
		}
	}
}
