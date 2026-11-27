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

// DEPLOY 테스트 벡터(T3.3, D-19). 기대값은 python3(정규화·SHA-256)와 cast abi-encode 로 따로 계산했다.
const (
	deployJSON      = `{"request_id":"01JDQ8Z3V4N6P7R8S9T0W1X2Y3","type":"DEPLOY","ledger_id":"besu-local","institution_id":"platform","key_purpose":"CONTRACT_ADMIN","contract":"0x0000000000000000000000000000000000000000","function":"constructor(string,string,address)","args":["데모 채권 1","KRDEMO000001","0x70997970C51812dc3A010C7d01b50e0d17dc79C8"],"drafter_id":"sec-01","expires_at":"2026-12-01T09:00:00Z","code_hash":"0xabababababababababababababababababababababababababababababababab"}`
	deployCanonical = `{"args":["데모 채권 1","KRDEMO000001","0x70997970C51812dc3A010C7d01b50e0d17dc79C8"],"code_hash":"0xabababababababababababababababababababababababababababababababab","contract":"0x0000000000000000000000000000000000000000","drafter_id":"sec-01","expires_at":"2026-12-01T09:00:00Z","function":"constructor(string,string,address)","institution_id":"platform","key_purpose":"CONTRACT_ADMIN","ledger_id":"besu-local","request_id":"01JDQ8Z3V4N6P7R8S9T0W1X2Y3","type":"DEPLOY"}`
	deployHash      = "19703087eac8dab357f94352a3263ab9ae1ec7b5c1ad7bace13d6a006e81b23d"
	deployArgs      = "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000000feb8db0ebaaa820ecb184eab68c20310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4b5244454d4f3030303030310000000000000000000000000000000000000000"
)

func TestDeployVector(t *testing.T) {
	in, err := Parse([]byte(deployJSON))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := in.Canonical()
	if string(c) != deployCanonical {
		t.Fatalf("정규화 불일치\n got=%s\nwant=%s", c, deployCanonical)
	}
	if h, _ := in.Hash(); hex.EncodeToString(h[:]) != deployHash {
		t.Fatalf("해시 불일치: %x", h)
	}
	a, err := in.ConstructorArgs()
	if err != nil || hex.EncodeToString(a) != deployArgs {
		t.Fatalf("생성자 인자 %x %v", a, err)
	}
	if _, err := in.Calldata(); err == nil {
		t.Fatal("DEPLOY 에 calldata 가 만들어졌다")
	}
	// 정규화 바이트를 다시 해석해도 같은 해시
	in2, err := Parse(c)
	if err != nil {
		t.Fatal(err)
	}
	if h1, _ := in.Hash(); func() bool { h2, _ := in2.Hash(); return h1 != h2 }() {
		t.Fatal("다시 해석한 DEPLOY 의 해시가 다르다")
	}
}

func TestDeployRejects(t *testing.T) {
	tx := vectorJSON
	cases := map[string]string{
		"TX 에 code_hash":         strings.Replace(tx, `"expires_at"`, `"code_hash":"0x`+strings.Repeat("ab", 32)+`","expires_at"`, 1),
		"DEPLOY 에 code_hash 없음":  strings.Replace(deployJSON, `,"code_hash":"0x`+strings.Repeat("ab", 32)+`"`, "", 1),
		"DEPLOY contract 가 0 아님": strings.Replace(deployJSON, ZeroAddress, "0x5FbDB2315678afecb367f032d93F642f64180aa3", 1),
		"DEPLOY 함수가 생성자 아님":      strings.Replace(deployJSON, `"constructor(string,string,address)"`, `"init(string,string,address)"`, 1),
		"code_hash 대문자":          strings.Replace(deployJSON, strings.Repeat("ab", 32), strings.Repeat("AB", 32), 1),
		"code_hash 길이":           strings.Replace(deployJSON, strings.Repeat("ab", 32), strings.Repeat("ab", 31), 1),
		"code_hash 중복":           strings.Replace(deployJSON, `"type":"DEPLOY"`, `"code_hash":"0x`+strings.Repeat("ab", 32)+`","type":"DEPLOY"`, 1),
		"TX 가 0 주소":              strings.Replace(tx, "0x5FbDB2315678afecb367f032d93F642f64180aa3", ZeroAddress, 1),
		"TX 가 생성자":               strings.Replace(tx, `"issue(address,uint256)"`, `"constructor(address,uint256)"`, 1),
	}
	for name, raw := range cases {
		if raw == tx || raw == deployJSON {
			t.Fatalf("%s: 변형이 적용되지 않았다", name)
		}
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: 거부되지 않았다", name)
		}
	}
}
