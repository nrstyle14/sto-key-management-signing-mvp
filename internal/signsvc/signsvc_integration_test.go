//go:build integration

// 통합 테스트: 서명 처리(설계서 5.3 의 1~4, 7~9단계)와 request_id 1회 서명(D-6). T1.5.
// 호스트에서 MySQL(make up && make migrate)에 signer_app 으로 접속한다.
// HSM 대신 go-ethereum 키를 쓰는 시험용 Signer 를 쓴다(HSM 서명 경로는 internal/signer/hsm 통합 테스트와
// test/ 의 서명 서버 종단 시험이 실제 SoftHSM2 로 확인한다). 만든 행은 시험이 끝나면 지운다.
package signsvc

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-sql-driver/mysql"
	"github.com/oklog/ulid/v2"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/evmtx"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

const chainID = 20261124

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	pw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "deploy", "secrets", "signer_app_password"))
	if err != nil {
		t.Fatalf("비밀 파일(make up 필요): %v", err)
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr, cfg.DBName = "signer_app", strings.TrimSpace(string(pw)), "tcp", "127.0.0.1:3306", "signer"
	cfg.ParseTime = true
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("DB 접속(make up && make migrate 필요): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// fakeSigner 는 go-ethereum 키로 서명한다. 절반은 high-s 로 돌려줘 정규화 경로를 탄다.
type fakeSigner struct {
	keys  map[string]*ecdsa.PrivateKey
	calls atomic.Int32
	fail  atomic.Bool
}

func (f *fakeSigner) Generate(context.Context, signer.KeySpec) (signer.PublicKey, error) {
	return nil, errors.New("시험용")
}
func (f *fakeSigner) Destroy(context.Context, string) error { return errors.New("시험용") }
func (f *fakeSigner) SignDigest(_ context.Context, keyID string, d [32]byte) (*big.Int, *big.Int, error) {
	f.calls.Add(1)
	if f.fail.Load() {
		return nil, nil, errors.New("HSM 응답 없음(시험)")
	}
	k, ok := f.keys[keyID]
	if !ok {
		return nil, nil, fmt.Errorf("키 없음 %s", keyID)
	}
	sig, err := crypto.Sign(d[:], k)
	if err != nil {
		return nil, nil, err
	}
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64])
	if d[0]&1 == 1 {
		s = new(big.Int).Sub(crypto.S256().Params().N, s)
	}
	return r, s, nil
}

type fixture struct {
	db                   *sql.DB
	svc                  *Service
	fs                   *fakeSigner
	ledger, instA, instB string
	keyA                 string
	addrA                common.Address
}

func rid() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func setup(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	db := openDB(t)
	s := rid()
	f := &fixture{db: db, ledger: "it-ledger-" + s, instA: "it-a-" + s, instB: "it-b-" + s, keyA: "it-key-a-" + s,
		fs: &fakeSigner{keys: map[string]*ecdsa.PrivateKey{}}}
	tokA, tokB := f.ledger+"."+f.instA, f.ledger+"."+f.instB
	keyB := "it-key-b-" + s
	t.Cleanup(func() {
		// 서명 기록, 동결, 키, 토큰 순으로 지운다(기동 점검에 걸리는 ACTIVE 키가 남지 않게).
		_, _ = db.Exec("DELETE FROM signatures WHERE key_id IN (?, ?)", f.keyA, keyB)
		_, _ = db.Exec("DELETE FROM freezes WHERE target IN (?, ?, ?)", f.keyA, f.instA, f.ledger)
		_, _ = db.Exec("DELETE FROM `keys` WHERE key_id IN (?, ?)", f.keyA, keyB)
		_, _ = db.Exec("DELETE FROM hsm_tokens WHERE token_id IN (?, ?)", tokA, tokB)
	})
	for tok, inst := range map[string]string{tokA: f.instA, tokB: f.instB} {
		if err := keyreg.RegisterToken(ctx, db, keyreg.Token{TokenID: tok, Label: "it-" + inst, LedgerID: f.ledger, InstitutionID: inst}); err != nil {
			t.Fatal(err)
		}
	}
	ka, _ := crypto.GenerateKey()
	kb, _ := crypto.GenerateKey()
	f.fs.keys[f.keyA], f.fs.keys[keyB] = ka, kb
	f.addrA = crypto.PubkeyToAddress(ka.PublicKey)
	if err := keyreg.RegisterKey(ctx, db, keyreg.Key{KeyID: f.keyA, TokenID: tokA, Purpose: signer.PurposeIssue, PublicKey: crypto.FromECDSAPub(&ka.PublicKey)}); err != nil {
		t.Fatal(err)
	}
	// 기관 B 에는 TRANSFER 키만 있다.
	if err := keyreg.RegisterKey(ctx, db, keyreg.Key{KeyID: keyB, TokenID: tokB, Purpose: signer.PurposeTransfer, PublicKey: crypto.FromECDSAPub(&kb.PublicKey)}); err != nil {
		t.Fatal(err)
	}
	f.svc = &Service{DB: db, Signer: f.fs, Chains: map[string]uint64{f.ledger: chainID}, MaxGas: 500000, Callers: []string{"apid"}}
	return f
}

var contract = common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")

func (f *fixture) intent(t *testing.T, inst string, purpose signer.Purpose) *intent.Intent {
	in := &intent.Intent{
		RequestID: ulid.Make().String(), Type: intent.TypeTX, LedgerID: f.ledger, InstitutionID: inst, KeyPurpose: purpose,
		Contract: contract.Hex(), Function: "issue(address,uint256)",
		Args:      []string{common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").Hex(), "1000"},
		DrafterID: "apr-a-01", ExpiresAt: time.Now().UTC().Add(time.Hour).Format(intent.TimeLayout),
	}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	return in
}

func request(t *testing.T, in *intent.Intent, tx *types.Transaction) Request {
	t.Helper()
	b, _ := in.Canonical()
	h, _ := in.Hash()
	raw, err := evmtx.EncodeUnsigned(tx)
	if err != nil {
		t.Fatal(err)
	}
	return Request{Intent: json.RawMessage(b), IntentHash: hex.EncodeToString(h[:]), UnsignedTx: "0x" + hex.EncodeToString(raw)}
}

func goodTx(t *testing.T, in *intent.Intent, nonce uint64) *types.Transaction {
	data, err := in.Calldata()
	if err != nil {
		t.Fatal(err)
	}
	return evmtx.NewUnsigned(big.NewInt(chainID), nonce, in.ContractAddress(), data, 100000)
}

func wantReject(t *testing.T, err error, step int, code string) {
	t.Helper()
	var rj *Rejection
	if !errors.As(err, &rj) || rj.Step != step || rj.Code != code {
		t.Fatalf("거부 기대(단계 %d %s), 실제: %v", step, code, err)
	}
}

func (f *fixture) rows(t *testing.T, requestID string) int {
	var n int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM signatures WHERE request_id = ?", requestID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSignAndReplay(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	in := f.intent(t, f.instA, signer.PurposeIssue)
	req := request(t, in, goodTx(t, in, 0))
	res, err := f.svc.SignTx(ctx, "apid", req)
	if err != nil {
		t.Fatal(err)
	}
	signed := new(types.Transaction)
	if err := signed.UnmarshalBinary(common.FromHex(res.SignedTx)); err != nil {
		t.Fatal(err)
	}
	from, err := types.Sender(types.LatestSignerForChainID(big.NewInt(chainID)), signed)
	if err != nil || from != f.addrA || res.Address != f.addrA.Hex() || res.KeyID != f.keyA || signed.Hash().Hex() != res.TxHash {
		t.Fatalf("서명 결과 불일치: from=%s res=%+v err=%v", from, res, err)
	}
	// 같은 요청 재호출: 다시 서명하지 않고 같은 결과(D-6)
	again, err := f.svc.SignTx(ctx, "apid", req)
	if err != nil || *again != *res {
		t.Fatalf("재호출 결과가 다르다: %+v %v", again, err)
	}
	if f.fs.calls.Load() != 1 || f.rows(t, in.RequestID) != 1 {
		t.Fatalf("서명 호출 %d, 행 %d (기대 1, 1)", f.fs.calls.Load(), f.rows(t, in.RequestID))
	}
}

// 같은 request_id 로 다른 tx 를 다시 서명받을 수 없다(설계서 16절).
func TestSameRequestDifferentTxRejected(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	in := f.intent(t, f.instA, signer.PurposeIssue)
	if _, err := f.svc.SignTx(ctx, "apid", request(t, in, goodTx(t, in, 0))); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.SignTx(ctx, "apid", request(t, in, goodTx(t, in, 1)))
	wantReject(t, err, 2, CodeRequestConflict)
}

// 같은 요청을 동시에 여러 번 보내도 서명은 한 번, 응답은 모두 같다.
func TestConcurrentSameRequestSignsOnce(t *testing.T) {
	f := setup(t)
	in := f.intent(t, f.instA, signer.PurposeIssue)
	req := request(t, in, goodTx(t, in, 0))
	const n = 8
	var wg sync.WaitGroup
	res := make([]*Response, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res[i], errs[i] = f.svc.SignTx(context.Background(), "apid", req)
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("동시 요청 %d: %v", i, errs[i])
		}
		if *res[i] != *res[0] {
			t.Fatalf("동시 요청 응답이 다르다: %+v / %+v", res[i], res[0])
		}
	}
	if c := f.fs.calls.Load(); c != 1 {
		t.Fatalf("HSM 서명 호출 %d 회 (기대 1)", c)
	}
	if f.rows(t, in.RequestID) != 1 {
		t.Fatal("서명 기록이 1행이 아니다")
	}
}

func TestHSMFailureLeavesNoRecord(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	in := f.intent(t, f.instA, signer.PurposeIssue)
	req := request(t, in, goodTx(t, in, 0))
	f.fs.fail.Store(true)
	_, err := f.svc.SignTx(ctx, "apid", req)
	wantReject(t, err, 8, CodeSignFailed)
	if f.rows(t, in.RequestID) != 0 {
		t.Fatal("HSM 실패 후 예약 행이 남았다")
	}
	f.fs.fail.Store(false)
	if _, err := f.svc.SignTx(ctx, "apid", req); err != nil {
		t.Fatalf("HSM 복구 후 재시도 실패: %v", err)
	}
}

func TestRejections(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	other := common.HexToAddress("0x00000000000000000000000000000000000000aa")

	t.Run("호출자", func(t *testing.T) {
		in := f.intent(t, f.instA, signer.PurposeIssue)
		_, err := f.svc.SignTx(ctx, "stoctl", request(t, in, goodTx(t, in, 0)))
		wantReject(t, err, 1, CodeCallerNotAllowed)
	})
	t.Run("만료", func(t *testing.T) {
		in := f.intent(t, f.instA, signer.PurposeIssue)
		svc := *f.svc
		svc.Now = func() time.Time { return in.Expires().Add(time.Second) }
		_, err := svc.SignTx(ctx, "apid", request(t, in, goodTx(t, in, 0)))
		wantReject(t, err, 3, CodeIntentExpired)
	})
	t.Run("승인 후 intent 변조(intent_hash 불일치)", func(t *testing.T) {
		in := f.intent(t, f.instA, signer.PurposeIssue)
		req := request(t, in, goodTx(t, in, 0))
		tampered := *in
		tampered.Args = []string{in.Args[0], "999999"}
		b, _ := tampered.Canonical()
		req.Intent = b // intent_hash 는 원래 값
		_, err := f.svc.SignTx(ctx, "apid", req)
		wantReject(t, err, 3, CodeIntentHash)
	})
	t.Run("알 수 없는 원장", func(t *testing.T) {
		in := f.intent(t, f.instA, signer.PurposeIssue)
		in.LedgerID = "it-unknown"
		_, err := f.svc.SignTx(ctx, "apid", request(t, in, goodTx(t, in, 0)))
		wantReject(t, err, 3, CodeLedgerUnknown)
	})
	t.Run("다른 기관(기관 B 로 ISSUE)", func(t *testing.T) {
		in := f.intent(t, f.instB, signer.PurposeIssue)
		_, err := f.svc.SignTx(ctx, "apid", request(t, in, goodTx(t, in, 0)))
		wantReject(t, err, 4, CodeKeyNotAvailable)
	})
	t.Run("다른 용도(기관 A 로 TRANSFER)", func(t *testing.T) {
		in := f.intent(t, f.instA, signer.PurposeTransfer)
		_, err := f.svc.SignTx(ctx, "apid", request(t, in, goodTx(t, in, 0)))
		wantReject(t, err, 4, CodeKeyNotAvailable)
	})
	t.Run("intent 와 다른 calldata", func(t *testing.T) {
		in := f.intent(t, f.instA, signer.PurposeIssue)
		alt := *in
		alt.Args = []string{other.Hex(), "1000"}
		data, _ := alt.Calldata()
		tx := evmtx.NewUnsigned(big.NewInt(chainID), 0, in.ContractAddress(), data, 100000)
		_, err := f.svc.SignTx(ctx, "apid", request(t, in, tx))
		wantReject(t, err, 7, evmtx.CodeTxCalldataMismatch)
	})
	t.Run("다른 to", func(t *testing.T) {
		in := f.intent(t, f.instA, signer.PurposeIssue)
		data, _ := in.Calldata()
		_, err := f.svc.SignTx(ctx, "apid", request(t, in, evmtx.NewUnsigned(big.NewInt(chainID), 0, other, data, 100000)))
		wantReject(t, err, 7, evmtx.CodeTxToMismatch)
	})
	t.Run("0 이 아닌 value", func(t *testing.T) {
		in := f.intent(t, f.instA, signer.PurposeIssue)
		data, _ := in.Calldata()
		to := in.ContractAddress()
		tx := types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(chainID), GasTipCap: big.NewInt(0), GasFeeCap: big.NewInt(0),
			Gas: 100000, To: &to, Value: big.NewInt(1), Data: data})
		_, err := f.svc.SignTx(ctx, "apid", request(t, in, tx))
		wantReject(t, err, 7, evmtx.CodeTxValueNonzero)
	})
	t.Run("다른 chainId", func(t *testing.T) {
		in := f.intent(t, f.instA, signer.PurposeIssue)
		data, _ := in.Calldata()
		_, err := f.svc.SignTx(ctx, "apid", request(t, in, evmtx.NewUnsigned(big.NewInt(1), 0, in.ContractAddress(), data, 100000)))
		wantReject(t, err, 7, evmtx.CodeTxChainIDMismatch)
	})
	t.Run("동결된 키", func(t *testing.T) {
		if _, err := f.db.Exec(`INSERT INTO freezes (freeze_id, scope, target, reason, frozen_by) VALUES (?, 'KEY', ?, 'it', 'it')`,
			"it-frz-"+rid(), f.keyA); err != nil {
			t.Fatal(err)
		}
		in := f.intent(t, f.instA, signer.PurposeIssue)
		_, err := f.svc.SignTx(ctx, "apid", request(t, in, goodTx(t, in, 0)))
		wantReject(t, err, 4, CodeKeyFrozen)
	})
	if c := f.fs.calls.Load(); c != 0 {
		t.Fatalf("거부 사례에서 HSM 서명이 %d 회 호출됐다", c)
	}
}

func TestRetiredKeyRejected(t *testing.T) {
	f := setup(t)
	if err := keyreg.SetStatus(context.Background(), f.db, f.keyA, keyreg.StatusActive, keyreg.StatusRetired); err != nil {
		t.Fatal(err)
	}
	in := f.intent(t, f.instA, signer.PurposeIssue)
	_, err := f.svc.SignTx(context.Background(), "apid", request(t, in, goodTx(t, in, 0)))
	wantReject(t, err, 4, CodeKeyNotAvailable)
}
