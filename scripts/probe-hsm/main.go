// Command probe-hsm 은 SoftHSM2(PKCS#11)의 동작을 실측한다(T0.3, T0.4).
//
//	probe-hsm sign -chain-id N -out DIR   secp256k1 키 생성(추출 불가) → CKM_ECDSA 서명 → low-s → v 계산 → 주소 확인,
//	                                      EIP-1559 트랜잭션을 서명해 DIR/raw-tx.hex 로 남긴다.
//	probe-hsm wrap -out DIR               AES-256 래핑 키 주입 → EC 개인키 C_WrapKey → 빈 토큰에 C_UnwrapKey → 주소 확인.
//
// 실측용 토큰은 실행할 때마다 새로 초기화하고, PIN 은 실행 중 무작위로 만들어 메모리에만 둔다.
// PIN, 래핑 키, 개인키 값은 어디에도 출력하지 않는다. 이 프로그램은 원장 노드에 접속하지 않는다.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/miekg/pkcs11"
)

// secp256k1 곡선 OID(1.3.132.0.10)의 DER 인코딩. CKA_EC_PARAMS 값으로 쓴다.
var oidSecp256k1 = []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A}

var (
	secpN     = crypto.S256().Params().N
	secpHalfN = new(big.Int).Rsh(crypto.S256().Params().N, 1)
)

// 이전 PKCS#11 헤더에서 쓰던 AES 키 랩 메커니즘 값(일부 구현이 아직 사용).
const (
	ckmAESKeyWrapLegacy    = 0x00001090
	ckmAESKeyWrapPadLegacy = 0x00001091
	ckmAESKeyWrapKWP       = 0x0000210B
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "사용법: probe-hsm sign|wrap [옵션]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "sign":
		err = cmdSign(os.Args[2:])
	case "wrap":
		err = cmdWrap(os.Args[2:])
	default:
		err = fmt.Errorf("알 수 없는 명령: %s", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "실패:", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------- 공통

type hsm struct {
	ctx *pkcs11.Ctx
	lib string
}

func openHSM(lib string) (*hsm, error) {
	ctx := pkcs11.New(lib)
	if ctx == nil {
		return nil, fmt.Errorf("PKCS#11 라이브러리를 열 수 없다: %s", lib)
	}
	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("C_Initialize: %w", err)
	}
	return &hsm{ctx: ctx, lib: lib}, nil
}

func (h *hsm) close() {
	_ = h.ctx.Finalize()
	h.ctx.Destroy()
}

type token struct {
	slot uint
	sess pkcs11.SessionHandle
}

func randomPIN() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// initToken 은 초기화되지 않은 슬롯에 새 토큰을 만들고 사용자로 로그인한 세션을 돌려준다.
func (h *hsm) initToken(label string) (*token, error) {
	slots, err := h.ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("C_GetSlotList: %w", err)
	}
	free := -1
	for _, s := range slots {
		ti, err := h.ctx.GetTokenInfo(s)
		if err != nil {
			return nil, fmt.Errorf("C_GetTokenInfo: %w", err)
		}
		if ti.Flags&pkcs11.CKF_TOKEN_INITIALIZED == 0 {
			free = int(s)
			break
		}
	}
	if free < 0 {
		return nil, errors.New("초기화되지 않은 슬롯이 없다")
	}
	soPIN, err := randomPIN()
	if err != nil {
		return nil, err
	}
	userPIN, err := randomPIN()
	if err != nil {
		return nil, err
	}
	if err := h.ctx.InitToken(uint(free), soPIN, label); err != nil {
		return nil, fmt.Errorf("C_InitToken: %w", err)
	}
	// SoftHSM2 는 토큰 초기화 뒤 슬롯 ID 를 다시 배정하므로 라벨로 다시 찾는다.
	slot, err := h.findSlot(label)
	if err != nil {
		return nil, err
	}
	sess, err := h.ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("C_OpenSession: %w", err)
	}
	if err := h.ctx.Login(sess, pkcs11.CKU_SO, soPIN); err != nil {
		return nil, fmt.Errorf("C_Login(SO): %w", err)
	}
	if err := h.ctx.InitPIN(sess, userPIN); err != nil {
		return nil, fmt.Errorf("C_InitPIN: %w", err)
	}
	if err := h.ctx.Logout(sess); err != nil {
		return nil, fmt.Errorf("C_Logout: %w", err)
	}
	if err := h.ctx.Login(sess, pkcs11.CKU_USER, userPIN); err != nil {
		return nil, fmt.Errorf("C_Login(USER): %w", err)
	}
	return &token{slot: slot, sess: sess}, nil
}

func (h *hsm) findSlot(label string) (uint, error) {
	slots, err := h.ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("C_GetSlotList: %w", err)
	}
	for _, s := range slots {
		ti, err := h.ctx.GetTokenInfo(s)
		if err != nil {
			return 0, fmt.Errorf("C_GetTokenInfo: %w", err)
		}
		if strings.TrimSpace(ti.Label) == label {
			return s, nil
		}
	}
	return 0, fmt.Errorf("라벨 %q 토큰을 찾지 못했다", label)
}

type ecKey struct {
	priv, pub  pkcs11.ObjectHandle
	pubRaw     []byte // 65바이트 비압축 공개키(0x04 || X || Y)
	ecPointRaw []byte // CKA_EC_POINT 원본
	ecPointFmt string
	address    common.Address
}

// genSecp256k1 은 토큰에 secp256k1 키 쌍을 만든다.
func (h *hsm) genSecp256k1(t *token, keyID string, extractable bool) (*ecKey, error) {
	pubTpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oidSecp256k1),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(keyID)),
	}
	privTpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(keyID)),
	}
	pub, priv, err := h.ctx.GenerateKeyPair(t.sess,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}, pubTpl, privTpl)
	if err != nil {
		return nil, fmt.Errorf("C_GenerateKeyPair(secp256k1): %w", err)
	}
	attrs, err := h.ctx.GetAttributeValue(t.sess, pub, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil)})
	if err != nil {
		return nil, fmt.Errorf("CKA_EC_POINT 조회: %w", err)
	}
	raw := attrs[0].Value
	pubRaw, format, err := parseECPoint(raw)
	if err != nil {
		return nil, err
	}
	pk, err := crypto.UnmarshalPubkey(pubRaw)
	if err != nil {
		return nil, fmt.Errorf("공개키 해석: %w", err)
	}
	return &ecKey{priv: priv, pub: pub, pubRaw: pubRaw, ecPointRaw: raw, ecPointFmt: format, address: crypto.PubkeyToAddress(*pk)}, nil
}

// parseECPoint 는 CKA_EC_POINT 값에서 65바이트 비압축 공개키를 꺼낸다.
// PKCS#11 표준은 DER OCTET STRING 으로 감싸도록 정하지만, 구현에 따라 감싸지 않은 값을 돌려주기도 한다.
func parseECPoint(v []byte) ([]byte, string, error) {
	if len(v) == 67 && v[0] == 0x04 && v[1] == 0x41 && v[2] == 0x04 {
		return v[2:], "DER OCTET STRING(04 41) 안의 비압축 점(0x04||X||Y, 65바이트)", nil
	}
	if len(v) == 65 && v[0] == 0x04 {
		return v, "감싸지 않은 비압축 점(0x04||X||Y, 65바이트)", nil
	}
	return nil, "", fmt.Errorf("알 수 없는 CKA_EC_POINT 형식(길이 %d, 앞 바이트 %x)", len(v), v[:min(len(v), 3)])
}

// signDigest 는 CKM_ECDSA 로 32바이트 다이제스트에 서명하고 r, s 를 돌려준다.
func (h *hsm) signDigest(t *token, priv pkcs11.ObjectHandle, digest []byte) (r, s *big.Int, rawLen int, err error) {
	if err := h.ctx.SignInit(t.sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, priv); err != nil {
		return nil, nil, 0, fmt.Errorf("C_SignInit(CKM_ECDSA): %w", err)
	}
	sig, err := h.ctx.Sign(t.sess, digest)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("C_Sign: %w", err)
	}
	if len(sig) != 64 {
		return nil, nil, len(sig), fmt.Errorf("서명 길이 %d (기대 64: r||s)", len(sig))
	}
	return new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]), len(sig), nil
}

// completeEVMSig 는 (r, s)를 low-s 로 정규화하고 복구 식별자를 찾아 65바이트 서명(r||s||v, v∈{0,1})을 만든다.
func completeEVMSig(digest []byte, r, s *big.Int, want common.Address) (sig []byte, wasHighS bool, err error) {
	if s.Cmp(secpHalfN) > 0 {
		s = new(big.Int).Sub(secpN, s)
		wasHighS = true
	}
	sig = make([]byte, 65)
	r.FillBytes(sig[0:32])
	s.FillBytes(sig[32:64])
	for v := byte(0); v <= 1; v++ {
		sig[64] = v
		pub, err := crypto.SigToPub(digest, sig)
		if err != nil {
			continue
		}
		if crypto.PubkeyToAddress(*pub) == want {
			return sig, wasHighS, nil
		}
	}
	return nil, wasHighS, errors.New("복구 식별자 0, 1 모두 주소가 일치하지 않는다")
}

func softhsmVersion() string {
	out, err := exec.Command("softhsm2-util", "--version").Output()
	if err != nil {
		return "확인 실패: " + err.Error()
	}
	return strings.TrimSpace(string(out))
}

func writeJSON(dir, name string, v any) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0o644)
}

func boolAttr(h *hsm, t *token, o pkcs11.ObjectHandle, types ...uint) (map[string]bool, error) {
	names := map[uint]string{
		pkcs11.CKA_SENSITIVE: "CKA_SENSITIVE", pkcs11.CKA_EXTRACTABLE: "CKA_EXTRACTABLE",
		pkcs11.CKA_ALWAYS_SENSITIVE: "CKA_ALWAYS_SENSITIVE", pkcs11.CKA_NEVER_EXTRACTABLE: "CKA_NEVER_EXTRACTABLE",
		pkcs11.CKA_TOKEN: "CKA_TOKEN", pkcs11.CKA_PRIVATE: "CKA_PRIVATE", pkcs11.CKA_SIGN: "CKA_SIGN",
	}
	tpl := make([]*pkcs11.Attribute, 0, len(types))
	for _, ty := range types {
		tpl = append(tpl, pkcs11.NewAttribute(ty, nil))
	}
	attrs, err := h.ctx.GetAttributeValue(t.sess, o, tpl)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, a := range attrs {
		out[names[a.Type]] = len(a.Value) == 1 && a.Value[0] == 1
	}
	return out, nil
}

// ---------------------------------------------------------------- sign (T0.3)

type signReport struct {
	Time               string          `json:"time"`
	SoftHSM            string          `json:"softhsm"`
	Library            string          `json:"library"`
	Mechanisms         map[string]any  `json:"mechanisms"`
	KeyAddress         string          `json:"key_address"`
	ECPointLen         int             `json:"ec_point_len"`
	ECPointFormat      string          `json:"ec_point_format"`
	PrivateAttrs       map[string]bool `json:"private_key_attrs"`
	ReadCKAValue       string          `json:"read_cka_value_result"`
	SignatureLen       int             `json:"signature_len"`
	SignatureFormat    string          `json:"signature_format"`
	Trials             int             `json:"trials"`
	HighSCount         int             `json:"high_s_count"`
	RecoveryIDCounts   map[string]int  `json:"recovery_id_counts"`
	AllRecovered       bool            `json:"all_recovered_address_match"`
	ChainID            string          `json:"chain_id"`
	TxType             int             `json:"tx_type"`
	TxHash             string          `json:"tx_hash"`
	TxSender           string          `json:"tx_sender_recovered"`
	TxSenderMatchesKey bool            `json:"tx_sender_matches_key"`
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	lib := fs.String("lib", "/usr/lib/softhsm/libsofthsm2.so", "PKCS#11 라이브러리 경로")
	chainID := fs.Int64("chain-id", 20261124, "트랜잭션 chainId")
	trials := fs.Int("trials", 200, "low-s 정규화 확인용 반복 서명 횟수")
	out := fs.String("out", "/out", "결과 디렉터리")
	_ = fs.Parse(args)

	h, err := openHSM(*lib)
	if err != nil {
		return err
	}
	defer h.close()
	t, err := h.initToken("probe-sign")
	if err != nil {
		return err
	}

	rep := signReport{Time: time.Now().UTC().Format(time.RFC3339), SoftHSM: softhsmVersion(), Library: *lib,
		Mechanisms: map[string]any{}, RecoveryIDCounts: map[string]int{}}
	for name, m := range map[string]uint{"CKM_EC_KEY_PAIR_GEN": pkcs11.CKM_EC_KEY_PAIR_GEN, "CKM_ECDSA": pkcs11.CKM_ECDSA} {
		info, err := h.ctx.GetMechanismInfo(t.slot, []*pkcs11.Mechanism{pkcs11.NewMechanism(m, nil)})
		if err != nil {
			rep.Mechanisms[name] = "미지원: " + err.Error()
			continue
		}
		rep.Mechanisms[name] = map[string]any{"min_key_bits": info.MinKeySize, "max_key_bits": info.MaxKeySize, "flags": fmt.Sprintf("0x%x", info.Flags)}
	}

	key, err := h.genSecp256k1(t, "probe-op-key", false)
	if err != nil {
		return err
	}
	rep.KeyAddress = key.address.Hex()
	rep.ECPointLen = len(key.ecPointRaw)
	rep.ECPointFormat = key.ecPointFmt
	if rep.PrivateAttrs, err = boolAttr(h, t, key.priv, pkcs11.CKA_TOKEN, pkcs11.CKA_PRIVATE, pkcs11.CKA_SENSITIVE,
		pkcs11.CKA_EXTRACTABLE, pkcs11.CKA_ALWAYS_SENSITIVE, pkcs11.CKA_NEVER_EXTRACTABLE, pkcs11.CKA_SIGN); err != nil {
		return fmt.Errorf("개인키 속성 조회: %w", err)
	}

	// 추출 불가 확인: 개인키 값(CKA_VALUE) 읽기는 실패해야 한다.
	if _, err := h.ctx.GetAttributeValue(t.sess, key.priv, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)}); err == nil {
		return errors.New("추출 불가 키의 CKA_VALUE 를 읽을 수 있었다")
	} else {
		rep.ReadCKAValue = "거부됨: " + err.Error()
		var pe pkcs11.Error
		if !errors.As(err, &pe) || pe != pkcs11.CKR_ATTRIBUTE_SENSITIVE {
			return fmt.Errorf("CKA_VALUE 읽기 거부 사유가 CKR_ATTRIBUTE_SENSITIVE 가 아니다: %w", err)
		}
	}

	// 반복 서명으로 high-s 발생과 정규화·복구를 확인한다.
	rep.Trials = *trials
	rep.AllRecovered = true
	for i := 0; i < *trials; i++ {
		digest := make([]byte, 32)
		if _, err := rand.Read(digest); err != nil {
			return err
		}
		r, s, n, err := h.signDigest(t, key.priv, digest)
		if err != nil {
			return err
		}
		rep.SignatureLen = n
		sig, high, err := completeEVMSig(digest, r, s, key.address)
		if err != nil {
			rep.AllRecovered = false
			return fmt.Errorf("반복 서명 %d: %w", i, err)
		}
		if high {
			rep.HighSCount++
		}
		rep.RecoveryIDCounts[fmt.Sprint(sig[64])]++
		// go-ethereum 의 검증은 high-s 를 거부하므로 정규화가 됐는지 함께 확인된다.
		if !crypto.VerifySignature(key.pubRaw, digest, sig[:64]) {
			return fmt.Errorf("반복 서명 %d: go-ethereum 서명 검증 실패", i)
		}
	}
	rep.SignatureFormat = "r(32바이트 빅엔디언) || s(32바이트 빅엔디언), DER 아님"

	// EIP-1559 트랜잭션(가스비 0)을 HSM 키로 서명한다(D-10).
	cid := big.NewInt(*chainID)
	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: cid, Nonce: 0, GasTipCap: big.NewInt(0), GasFeeCap: big.NewInt(0),
		Gas: 21000, To: &to, Value: big.NewInt(0)})
	signer := types.LatestSignerForChainID(cid)
	digest := signer.Hash(tx)
	r, s, _, err := h.signDigest(t, key.priv, digest[:])
	if err != nil {
		return err
	}
	sig, _, err := completeEVMSig(digest[:], r, s, key.address)
	if err != nil {
		return err
	}
	signed, err := tx.WithSignature(signer, sig)
	if err != nil {
		return fmt.Errorf("서명 결합: %w", err)
	}
	sender, err := types.Sender(signer, signed)
	if err != nil {
		return fmt.Errorf("송신자 복구: %w", err)
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		return err
	}
	rep.ChainID = cid.String()
	rep.TxType = int(signed.Type())
	rep.TxHash = signed.Hash().Hex()
	rep.TxSender = sender.Hex()
	rep.TxSenderMatchesKey = sender == key.address
	if !rep.TxSenderMatchesKey {
		return errors.New("트랜잭션 송신자가 HSM 키 주소와 다르다")
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "raw-tx.hex"), []byte("0x"+hex.EncodeToString(raw)+"\n"), 0o644); err != nil {
		return err
	}
	return writeJSON(*out, "probe-sign.json", rep)
}

// ---------------------------------------------------------------- wrap (T0.4)

type wrapAttempt struct {
	Mechanism string `json:"mechanism"`
	Value     string `json:"value"`
	Result    string `json:"result"`
	Wrapped   int    `json:"wrapped_len,omitempty"`
}

type wrapReport struct {
	Time                 string            `json:"time"`
	SoftHSM              string            `json:"softhsm"`
	WrapCapable          []string          `json:"wrap_capable_mechanisms"`
	Attempts             []wrapAttempt     `json:"wrap_attempts_on_ec_private_key"`
	NonExtractableWrap   string            `json:"wrap_non_extractable_key_result"`
	ChosenMechanism      string            `json:"chosen_mechanism"`
	SourceAddress        string            `json:"source_address"`
	RestoredAddress      string            `json:"restored_address"`
	AddressMatch         bool              `json:"address_match"`
	RestoredAttrs        map[string]bool   `json:"restored_private_key_attrs"`
	RestoredECParamsOK   bool              `json:"restored_ec_params_secp256k1"`
	RestoredGethVerifyOK bool              `json:"restored_signature_verified_by_geth"`
	Notes                map[string]string `json:"notes"`
}

func cmdWrap(args []string) error {
	fs := flag.NewFlagSet("wrap", flag.ExitOnError)
	lib := fs.String("lib", "/usr/lib/softhsm/libsofthsm2.so", "PKCS#11 라이브러리 경로")
	out := fs.String("out", "/out", "결과 디렉터리")
	_ = fs.Parse(args)

	h, err := openHSM(*lib)
	if err != nil {
		return err
	}
	defer h.close()

	rep := wrapReport{Time: time.Now().UTC().Format(time.RFC3339), SoftHSM: softhsmVersion(), Notes: map[string]string{}}

	src, err := h.initToken("probe-wrap-src")
	if err != nil {
		return err
	}
	// 래핑 키는 메모리에서 만들고, 두 토큰에 같은 값을 주입한 뒤 지운다(설계서 6.3 의식의 축소판).
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return err
	}
	defer clear(aesKey)
	srcWrap, err := h.injectAES(src, aesKey, "probe-wrap-key")
	if err != nil {
		return err
	}

	// 토큰이 알리는 메커니즘 중 CKF_WRAP 이 있는 것을 모두 적는다.
	mechs, err := h.ctx.GetMechanismList(src.slot)
	if err != nil {
		return fmt.Errorf("C_GetMechanismList: %w", err)
	}
	for _, m := range mechs {
		info, err := h.ctx.GetMechanismInfo(src.slot, []*pkcs11.Mechanism{m})
		if err != nil {
			continue
		}
		if info.Flags&pkcs11.CKF_WRAP != 0 {
			rep.WrapCapable = append(rep.WrapCapable, mechName(m.Mechanism))
		}
	}

	root, err := h.genSecp256k1(src, "probe-root-key", true)
	if err != nil {
		return err
	}
	rep.SourceAddress = root.address.Hex()

	candidates := []uint{pkcs11.CKM_AES_KEY_WRAP_PAD, ckmAESKeyWrapKWP, pkcs11.CKM_AES_KEY_WRAP, ckmAESKeyWrapPadLegacy, ckmAESKeyWrapLegacy}
	var chosen uint
	var wrapped []byte
	for _, c := range candidates {
		a := wrapAttempt{Mechanism: mechName(c), Value: fmt.Sprintf("0x%08X", c)}
		w, err := h.ctx.WrapKey(src.sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(c, nil)}, srcWrap, root.priv)
		if err != nil {
			a.Result = "실패: " + err.Error()
		} else {
			a.Result = "성공"
			a.Wrapped = len(w)
			if wrapped == nil {
				chosen, wrapped = c, w
			}
		}
		rep.Attempts = append(rep.Attempts, a)
	}

	// 운영 키(추출 불가)는 래핑도 거부돼야 한다(D-3).
	op, err := h.genSecp256k1(src, "probe-op-key", false)
	if err != nil {
		return err
	}
	if _, err := h.ctx.WrapKey(src.sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP_PAD, nil)}, srcWrap, op.priv); err == nil {
		return errors.New("추출 불가 키가 래핑됐다")
	} else {
		rep.NonExtractableWrap = "거부됨: " + err.Error()
	}

	if wrapped == nil {
		_ = writeJSON(*out, "probe-wrap.json", rep)
		return errors.New("EC 개인키를 래핑할 수 있는 메커니즘이 없다")
	}
	rep.ChosenMechanism = mechName(chosen)

	// 빈 토큰을 새로 만들어 같은 래핑 키를 주입하고 복원한다.
	dst, err := h.initToken("probe-wrap-dst")
	if err != nil {
		return err
	}
	dstWrap, err := h.injectAES(dst, aesKey, "probe-wrap-key")
	if err != nil {
		return err
	}
	unwrapTpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "probe-root-key"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("probe-root-key")),
	}
	restored, err := h.ctx.UnwrapKey(dst.sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(chosen, nil)}, dstWrap, wrapped, unwrapTpl)
	if err != nil {
		return fmt.Errorf("C_UnwrapKey(%s): %w", mechName(chosen), err)
	}
	if rep.RestoredAttrs, err = boolAttr(h, dst, restored, pkcs11.CKA_TOKEN, pkcs11.CKA_PRIVATE, pkcs11.CKA_SENSITIVE,
		pkcs11.CKA_EXTRACTABLE, pkcs11.CKA_SIGN); err != nil {
		return fmt.Errorf("복원 키 속성 조회: %w", err)
	}
	params, err := h.ctx.GetAttributeValue(dst.sess, restored, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil)})
	if err != nil {
		return fmt.Errorf("복원 키 CKA_EC_PARAMS 조회: %w", err)
	}
	rep.RestoredECParamsOK = bytes.Equal(params[0].Value, oidSecp256k1)

	// 복원된 키로 서명하고 공개키를 복구해 원래 주소와 비교한다.
	digest := crypto.Keccak256([]byte("sto-kms probe-wrap restore check"))
	r, s, _, err := h.signDigest(dst, restored, digest)
	if err != nil {
		return err
	}
	sig, _, err := completeEVMSig(digest, r, s, root.address)
	if err != nil {
		return fmt.Errorf("복원 키 서명이 원래 주소로 복구되지 않는다: %w", err)
	}
	pub, err := crypto.SigToPub(digest, sig)
	if err != nil {
		return err
	}
	rep.RestoredAddress = crypto.PubkeyToAddress(*pub).Hex()
	rep.AddressMatch = rep.RestoredAddress == rep.SourceAddress
	rep.RestoredGethVerifyOK = crypto.VerifySignature(crypto.FromECDSAPub(pub), digest, sig[:64])
	rep.Notes["wrapped_blob"] = "래핑된 키(암호문) 길이만 기록하고 값은 남기지 않는다"
	if !rep.AddressMatch || !rep.RestoredGethVerifyOK || !rep.RestoredECParamsOK {
		_ = writeJSON(*out, "probe-wrap.json", rep)
		return errors.New("복원 확인 실패")
	}
	return writeJSON(*out, "probe-wrap.json", rep)
}

// injectAES 는 AES-256 래핑 키를 토큰 객체(추출 불가)로 넣는다.
func (h *hsm) injectAES(t *token, key []byte, label string) (pkcs11.ObjectHandle, error) {
	o, err := h.ctx.CreateObject(t.sess, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, key),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, false),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	})
	if err != nil {
		return 0, fmt.Errorf("래핑 키 주입(C_CreateObject): %w", err)
	}
	return o, nil
}

func mechName(m uint) string {
	switch m {
	case pkcs11.CKM_AES_KEY_WRAP:
		return "CKM_AES_KEY_WRAP"
	case pkcs11.CKM_AES_KEY_WRAP_PAD:
		return "CKM_AES_KEY_WRAP_PAD"
	case ckmAESKeyWrapKWP:
		return "CKM_AES_KEY_WRAP_KWP"
	case ckmAESKeyWrapLegacy:
		return "CKM_AES_KEY_WRAP(구 값 0x1090)"
	case ckmAESKeyWrapPadLegacy:
		return "CKM_AES_KEY_WRAP_PAD(구 값 0x1091)"
	case pkcs11.CKM_AES_CBC:
		return "CKM_AES_CBC"
	case pkcs11.CKM_AES_CBC_PAD:
		return "CKM_AES_CBC_PAD"
	case pkcs11.CKM_AES_ECB:
		return "CKM_AES_ECB"
	case pkcs11.CKM_DES_ECB:
		return "CKM_DES_ECB"
	case pkcs11.CKM_DES_CBC:
		return "CKM_DES_CBC"
	case pkcs11.CKM_DES_CBC_PAD:
		return "CKM_DES_CBC_PAD"
	case pkcs11.CKM_DES3_CBC:
		return "CKM_DES3_CBC"
	case pkcs11.CKM_DES3_CBC_PAD:
		return "CKM_DES3_CBC_PAD"
	case pkcs11.CKM_DES3_ECB:
		return "CKM_DES3_ECB"
	case pkcs11.CKM_RSA_PKCS:
		return "CKM_RSA_PKCS"
	case pkcs11.CKM_RSA_PKCS_OAEP:
		return "CKM_RSA_PKCS_OAEP"
	case pkcs11.CKM_RSA_X_509:
		return "CKM_RSA_X_509"
	}
	return fmt.Sprintf("0x%08X", m)
}
