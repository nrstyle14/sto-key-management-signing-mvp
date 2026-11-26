package intent

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/oklog/ulid/v2"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

// Type 은 요청 유형이다. M1 에서는 TX 만 있다.
const TypeTX = "TX"

// TimeLayout 은 expires_at 의 정규 형식이다(UTC, 초 단위, 소수점 없음).
const TimeLayout = "2006-01-02T15:04:05Z"

// Intent 는 사람이 승인하는 업무 의미다(설계서 5.2). 모든 값은 문자열이고 정규 형식만 받는다.
type Intent struct {
	RequestID     string         `json:"request_id"`
	Type          string         `json:"type"`
	LedgerID      string         `json:"ledger_id"`
	InstitutionID string         `json:"institution_id"`
	KeyPurpose    signer.Purpose `json:"key_purpose"`
	Contract      string         `json:"contract"`
	Function      string         `json:"function"`
	Args          []string       `json:"args"`
	DrafterID     string         `json:"drafter_id"`
	ExpiresAt     string         `json:"expires_at"`
}

// Error 는 intent 검증 오류다.
type Error struct{ Field, Msg string }

func (e *Error) Error() string { return fmt.Sprintf("intent: %s: %s", e.Field, e.Msg) }

func bad(field, format string, a ...any) error {
	return &Error{Field: field, Msg: fmt.Sprintf(format, a...)}
}

var (
	idRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	fnRe   = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\(([a-z0-9,]*)\)$`)
	uintRe = regexp.MustCompile(`^uint(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)$`)
)

// Parse 는 JSON 을 엄격하게 해석하고 검증한다. 알 수 없는 필드, 빠진 필드, 비정규 값은 거부한다.
func Parse(raw []byte) (*Intent, error) {
	// encoding/json 은 필드 이름을 대소문자 구분 없이 맞추고 중복 키는 뒤 값을 쓴다.
	// 그래서 최상위 키를 직접 읽어 정확히 열 개의 소문자 키가 한 번씩만 있는지 먼저 확인한다.
	if err := checkKeys(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var in Intent
	if err := dec.Decode(&in); err != nil {
		return nil, bad("(json)", "%v", err)
	}
	if dec.More() {
		return nil, bad("(json)", "객체 뒤에 다른 값이 있다")
	}
	if err := in.Validate(); err != nil {
		return nil, err
	}
	return &in, nil
}

var fieldNames = []string{"request_id", "type", "ledger_id", "institution_id", "key_purpose", "contract", "function", "args", "drafter_id", "expires_at"}

// checkKeys 는 최상위 JSON 객체의 키가 fieldNames 와 정확히 같은지(대소문자 포함, 중복 없음) 확인한다.
func checkKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return bad("(json)", "%v", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return bad("(json)", "객체가 아니다")
	}
	want := map[string]bool{}
	for _, f := range fieldNames {
		want[f] = true
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return bad("(json)", "%v", err)
		}
		k, _ := tok.(string)
		if !want[k] {
			return bad(k, "알 수 없는 필드(대소문자 구분)")
		}
		if seen[k] {
			return bad(k, "중복된 필드")
		}
		seen[k] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return bad(k, "%v", err)
		}
	}
	for _, f := range fieldNames {
		if !seen[f] {
			return bad(f, "필드가 없다")
		}
	}
	return nil
}

// Validate 는 각 필드가 정규 형식인지 확인한다.
func (in *Intent) Validate() error {
	if u, err := ulid.ParseStrict(in.RequestID); err != nil || u.String() != in.RequestID {
		return bad("request_id", "대문자 ULID 26자여야 한다")
	}
	if in.Type != TypeTX {
		return bad("type", "지원하지 않는 유형 %q", in.Type)
	}
	for f, v := range map[string]string{"ledger_id": in.LedgerID, "institution_id": in.InstitutionID, "drafter_id": in.DrafterID} {
		if !idRe.MatchString(v) {
			return bad(f, "소문자·숫자·._- 로 된 1~64자여야 한다")
		}
	}
	if _, err := signer.ClassOf(in.KeyPurpose); err != nil {
		return bad("key_purpose", "알 수 없는 용도 %q", in.KeyPurpose)
	}
	if !isChecksumAddress(in.Contract) {
		return bad("contract", "EIP-55 체크섬 주소여야 한다")
	}
	types, err := functionTypes(in.Function)
	if err != nil {
		return bad("function", "%v", err)
	}
	if len(in.Args) != len(types) {
		return bad("args", "인자 수 %d, 함수 인자 수 %d", len(in.Args), len(types))
	}
	for i, t := range types {
		if err := checkArg(t, in.Args[i]); err != nil {
			return bad(fmt.Sprintf("args[%d]", i), "%v", err)
		}
	}
	ts, err := time.Parse(TimeLayout, in.ExpiresAt)
	if err != nil || ts.UTC().Format(TimeLayout) != in.ExpiresAt {
		return bad("expires_at", "%s 형식(UTC)이어야 한다", TimeLayout)
	}
	return nil
}

// Expires 는 만료 시각이다(Validate 를 통과한 intent 에서만 쓴다).
func (in *Intent) Expires() time.Time {
	t, _ := time.Parse(TimeLayout, in.ExpiresAt)
	return t
}

// ContractAddress 는 컨트랙트 주소다.
func (in *Intent) ContractAddress() common.Address { return common.HexToAddress(in.Contract) }

// Canonical 은 정규화 바이트다: 키 사전순, 공백 없음, UTF-8, HTML 이스케이프 없음(RFC 8785 방식, 값은 모두 문자열).
func (in *Intent) Canonical() ([]byte, error) {
	args := in.Args
	if args == nil {
		args = []string{}
	}
	m := map[string]any{
		"request_id": in.RequestID, "type": in.Type, "ledger_id": in.LedgerID, "institution_id": in.InstitutionID,
		"key_purpose": string(in.KeyPurpose), "contract": in.Contract, "function": in.Function, "args": args,
		"drafter_id": in.DrafterID, "expires_at": in.ExpiresAt,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil { // map 키는 사전순으로 직렬화된다
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Hash 는 SHA-256(정규화 바이트)다.
func (in *Intent) Hash() ([32]byte, error) {
	b, err := in.Canonical()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// Calldata 는 함수 선택자(keccak256(함수 서명)의 앞 4바이트)와 ABI 인코딩한 인자다.
// 서명 서버는 이 값과 미서명 tx 의 data 를 바이트 단위로 비교한다(느슨한 디코딩으로 인한 뒤 바이트·비정규 패딩 차단).
func (in *Intent) Calldata() ([]byte, error) {
	types, err := functionTypes(in.Function)
	if err != nil {
		return nil, err
	}
	var argsDef abi.Arguments
	vals := make([]any, len(types))
	for i, t := range types {
		at, err := abi.NewType(t, "", nil)
		if err != nil {
			return nil, err
		}
		argsDef = append(argsDef, abi.Argument{Type: at})
		if vals[i], err = goValue(t, in.Args[i]); err != nil {
			return nil, err
		}
	}
	packed, err := argsDef.Pack(vals...)
	if err != nil {
		return nil, fmt.Errorf("intent: ABI 인코딩: %w", err)
	}
	sel := crypto.Keccak256([]byte(in.Function))[:4]
	return append(sel, packed...), nil
}

func isChecksumAddress(s string) bool {
	return common.IsHexAddress(s) && strings.HasPrefix(s, "0x") && common.HexToAddress(s).Hex() == s
}

// functionTypes 는 정규 함수 서명 "name(type,type)"의 인자 타입 목록이다.
// 지원 타입: address, bool, string, bytes32, uint8..uint256(8의 배수). 별칭(uint)과 공백은 받지 않는다.
func functionTypes(fn string) ([]string, error) {
	m := fnRe.FindStringSubmatch(fn)
	if m == nil {
		return nil, fmt.Errorf("정규 함수 서명이 아니다: %q", fn)
	}
	if m[2] == "" {
		return nil, nil
	}
	types := strings.Split(m[2], ",")
	for _, t := range types {
		if t != "address" && t != "bool" && t != "string" && t != "bytes32" && !uintRe.MatchString(t) {
			return nil, fmt.Errorf("지원하지 않는 타입 %q", t)
		}
	}
	return types, nil
}

func checkArg(t, v string) error {
	_, err := goValue(t, v)
	return err
}

// goValue 는 정규 문자열 인자를 ABI 인코딩용 Go 값으로 바꾼다. 비정규 표기는 거부한다.
func goValue(t, v string) (any, error) {
	switch {
	case t == "address":
		if !isChecksumAddress(v) {
			return nil, errors.New("EIP-55 체크섬 주소여야 한다")
		}
		return common.HexToAddress(v), nil
	case t == "bool":
		if v != "true" && v != "false" {
			return nil, errors.New(`"true" 또는 "false" 여야 한다`)
		}
		return v == "true", nil
	case t == "string":
		for _, r := range v {
			if unicode.IsControl(r) || r == ' ' || r == ' ' {
				return nil, errors.New("제어 문자를 쓸 수 없다")
			}
		}
		return v, nil
	case t == "bytes32":
		if len(v) != 66 || !strings.HasPrefix(v, "0x") || strings.ToLower(v) != v {
			return nil, errors.New("0x 와 소문자 16진수 64자여야 한다")
		}
		var b [32]byte
		copy(b[:], common.FromHex(v))
		return b, nil
	case uintRe.MatchString(t):
		bits, _ := strconv.Atoi(strings.TrimPrefix(t, "uint"))
		n, ok := new(big.Int).SetString(v, 10)
		if !ok || n.Sign() < 0 || n.String() != v {
			return nil, errors.New("선행 0 없는 10진수 문자열이어야 한다")
		}
		if n.BitLen() > bits {
			return nil, fmt.Errorf("%s 범위를 넘는다", t)
		}
		switch bits {
		case 8:
			return uint8(n.Uint64()), nil
		case 16:
			return uint16(n.Uint64()), nil
		case 32:
			return uint32(n.Uint64()), nil
		case 64:
			return n.Uint64(), nil
		}
		return n, nil
	}
	return nil, fmt.Errorf("지원하지 않는 타입 %q", t)
}
