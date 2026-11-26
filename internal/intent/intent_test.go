package intent

import (
	"encoding/hex"
	"strings"
	"testing"
)

// 고정 테스트 벡터. 기대값은 Go 구현과 별개로 계산했다:
//
//	정규화·해시: python3 json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False) + hashlib.sha256
//	calldata   : cast calldata "issue(address,uint256)" 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 1000
const vectorJSON = `{
  "request_id": "01JDQ8Z3V4N6P7R8S9T0W1X2Y3",
  "type": "TX",
  "ledger_id": "besu-local",
  "institution_id": "inst-a",
  "key_purpose": "ISSUE",
  "contract": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
  "function": "issue(address,uint256)",
  "args": ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "1000"],
  "drafter_id": "apr-a-01",
  "expires_at": "2026-12-01T09:00:00Z"
}`

const (
	vectorCanonical = `{"args":["0x70997970C51812dc3A010C7d01b50e0d17dc79C8","1000"],"contract":"0x5FbDB2315678afecb367f032d93F642f64180aa3","drafter_id":"apr-a-01","expires_at":"2026-12-01T09:00:00Z","function":"issue(address,uint256)","institution_id":"inst-a","key_purpose":"ISSUE","ledger_id":"besu-local","request_id":"01JDQ8Z3V4N6P7R8S9T0W1X2Y3","type":"TX"}`
	vectorHash      = "18604f5d75800a4a39943ca05dfc4011170ce7666e1aae4a0eca4b68b91990b4"
	vectorCalldata  = "867904b400000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c800000000000000000000000000000000000000000000000000000000000003e8"
)

func TestVector(t *testing.T) {
	in, err := Parse([]byte(vectorJSON))
	if err != nil {
		t.Fatal(err)
	}
	c, err := in.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(c) != vectorCanonical {
		t.Fatalf("정규화 불일치\n got=%s\nwant=%s", c, vectorCanonical)
	}
	h, _ := in.Hash()
	if hex.EncodeToString(h[:]) != vectorHash {
		t.Fatalf("해시 불일치: %x", h)
	}
	cd, err := in.Calldata()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(cd) != vectorCalldata {
		t.Fatalf("calldata 불일치: %x", cd)
	}
	// 키 순서·공백이 달라도 같은 해시다.
	in2, err := Parse([]byte(vectorCanonical))
	if err != nil {
		t.Fatal(err)
	}
	if h2, _ := in2.Hash(); h2 != h {
		t.Fatal("같은 내용의 해시가 다르다")
	}
}

func TestParseRejectsNonCanonical(t *testing.T) {
	cases := map[string][2]string{
		"알 수 없는 필드":    {`"type": "TX",`, `"type": "TX", "nonce": "1",`},
		"소문자 주소":       {`0x5FbDB2315678afecb367f032d93F642f64180aa3`, `0x5fbdb2315678afecb367f032d93f642f64180aa3`},
		"인자 주소 체크섬 오류": {`0x70997970C51812dc3A010C7d01b50e0d17dc79C8`, `0x70997970c51812dc3A010C7d01b50e0d17dc79C8`},
		"선행 0":         {`"1000"`, `"01000"`},
		"숫자 타입":        {`"1000"`, `1000`},
		"음수":           {`"1000"`, `"-1"`},
		"16진수 수량":      {`"1000"`, `"0x3e8"`},
		"함수 서명 공백":     {`issue(address,uint256)`, `issue(address, uint256)`},
		"함수 서명 별칭":     {`issue(address,uint256)`, `issue(address,uint)`},
		"인자 수 불일치":     {`"1000"]`, `"1000", "1"]`},
		"시각 형식(소수점)":   {`2026-12-01T09:00:00Z`, `2026-12-01T09:00:00.000Z`},
		"시각 형식(시간대)":   {`2026-12-01T09:00:00Z`, `2026-12-01T18:00:00+09:00`},
		"소문자 ULID":     {`01JDQ8Z3V4N6P7R8S9T0W1X2Y3`, `01jdq8z3v4n6p7r8s9t0w1x2y3`},
		"알 수 없는 용도":    {`"ISSUE"`, `"MINT"`},
		"알 수 없는 유형":    {`"type": "TX"`, `"type": "KEY_GENERATE"`},
		"대문자 기관 ID":    {`"inst-a"`, `"INST-A"`},
		"uint8 범위 초과":  {`issue(address,uint256)`, `issue(address,uint8)`},
	}
	for name, c := range cases {
		raw := strings.Replace(vectorJSON, c[0], c[1], 1)
		if raw == vectorJSON {
			t.Fatalf("%s: 시험 입력이 바뀌지 않았다", name)
		}
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: 비정규 intent 가 허용됐다", name)
		}
	}
	missing := strings.Replace(vectorJSON, `"drafter_id": "apr-a-01",`, ``, 1)
	if _, err := Parse([]byte(missing)); err == nil {
		t.Error("필드가 빠진 intent 가 허용됐다")
	}
	if _, err := Parse([]byte(vectorJSON + `{}`)); err == nil {
		t.Error("뒤에 값이 붙은 JSON 이 허용됐다")
	}
}

func TestCanonicalNoHTMLEscape(t *testing.T) {
	in, _ := Parse([]byte(vectorJSON))
	in.Function = "note(string)"
	in.Args = []string{"<a&b>"}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	c, _ := in.Canonical()
	if !strings.Contains(string(c), `"args":["<a&b>"]`) {
		t.Fatalf("HTML 이스케이프가 들어갔다: %s", c)
	}
}
