//go:build integration

package workflow

import (
	"context"
	"database/sql"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/oklog/ulid/v2"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger/besu"
)

// rawRow 는 상태 기계를 거치지 않고 요청 행을 직접 넣는다(nonce·제출 시험용).
type rawRow struct {
	status    Status
	nonce     uint64
	raw       []byte
	txHash    []byte
	submitted bool
}

func (f *fx) insertRow(t *testing.T, addr common.Address, r rawRow) string {
	t.Helper()
	id := ulid.Make().String()
	var sub any
	if r.submitted {
		sub = time.Now().UTC()
	}
	_, err := f.db.Exec(`INSERT INTO requests (request_id, type, ledger_id, institution_id, intent_json, intent_hash, status, drafter_id,
		signer_address, nonce, raw_tx, tx_hash, submitted_at, expires_at) VALUES (?, 'TX', ?, 'inst-a', '{}', ?, ?, 'apr-a-01', ?, ?, ?, ?, ?, ?)`,
		id, f.ledger, make([]byte, 32), string(r.status), addr.Hex(), r.nonce, r.raw, r.txHash, sub, time.Now().Add(time.Hour).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fx) setNext(t *testing.T, addr common.Address, next uint64) {
	t.Helper()
	if _, err := f.db.Exec(`INSERT INTO nonces (ledger_id, address, next_nonce) VALUES (?, ?, ?)`, f.ledger, addr.Hex(), next); err != nil {
		t.Fatal(err)
	}
}

func (f *fx) allocate(t *testing.T, addr common.Address, pending uint64) uint64 {
	t.Helper()
	ctx := context.Background()
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err := AllocateNonce(ctx, tx, fakeChain{pending: pending}, f.ledger, addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return n
}

// 서명되지 않고 끝난 요청이 남긴 빈자리 nonce 는 다음 할당이 다시 쓴다(설계서 5.5, T3.2).
// 노드가 한 번이라도 받은 tx 의 nonce 와 살아 있는 요청의 nonce 는 다시 쓰지 않는다.
func TestNonceGapReused(t *testing.T) {
	f := setup(t)
	addr := f.keyAddr
	f.setNext(t, addr, 11)
	f.insertRow(t, addr, rawRow{status: StatusFailed, nonce: 7})                     // 빈자리(서명 전 실패)
	f.insertRow(t, addr, rawRow{status: StatusSubmitted, nonce: 8, submitted: true}) // 빈자리 뒤에서 막힌 tx
	f.insertRow(t, addr, rawRow{status: StatusFailed, nonce: 9, submitted: true})    // 제출됐다가 실패: 재사용 불가
	f.insertRow(t, addr, rawRow{status: StatusExpired, nonce: 10})                   // 빈자리(서명 전 만료)
	f.insertRow(t, addr, rawRow{status: StatusFailed, nonce: 6})                     // pending 아래: 이미 체인이 지나갔다

	if n := f.allocate(t, addr, 7); n != 7 {
		t.Fatalf("첫 할당 %d (기대 빈자리 7)", n)
	}
	f.insertRow(t, addr, rawRow{status: StatusApproved, nonce: 7}) // 새 요청이 7 을 가져갔다
	if n := f.allocate(t, addr, 7); n != 10 {
		t.Fatalf("둘째 할당 %d (기대 빈자리 10, 9 는 제출된 적이 있어 건너뜀)", n)
	}
	f.insertRow(t, addr, rawRow{status: StatusApproved, nonce: 10})
	if n := f.allocate(t, addr, 7); n != 11 {
		t.Fatalf("셋째 할당 %d (기대 다음 값 11)", n)
	}
	// 빈자리가 있어도 체인 pending 이 그 위로 지나가면 쓰지 않는다.
	if n := f.allocate(t, addr, 20); n != 20 {
		t.Fatalf("넷째 할당 %d (기대 pending 20)", n)
	}
}

type fakeSubmitter struct {
	h   ledger.TxHash
	err error
}

func (s fakeSubmitter) Submit(context.Context, []byte) (ledger.TxHash, error) { return s.h, s.err }

func auditActions(t *testing.T, db *sql.DB, id string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT action FROM audit_log WHERE subject = ? ORDER BY seq`, id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		out = append(out, a)
	}
	return out
}

// 일시 오류는 SIGNED 로 남고, 영구 거부는 FAILED(사유 코드)로 끝난다.
func TestSubmitWorkerClassifiesErrors(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	h := common.HexToHash("0x01")
	cases := []struct {
		err  error
		want Status
		code string
	}{
		{errors.New("connection refused"), StatusSigned, ""},
		{ledger.ErrNonceConflict, StatusFailed, CodeLedgerNonceConflict},
		{ledger.ErrRejected, StatusFailed, CodeLedgerRejected},
	}
	for _, c := range cases {
		id := f.insertRow(t, f.keyAddr, rawRow{status: StatusSigned, nonce: 1, raw: []byte{1}, txHash: h[:]})
		w := &SubmitWorker{DB: f.db, LedgerID: f.ledger, Ledger: fakeSubmitter{h: h, err: c.err}}
		did, err := w.RunOnce(ctx)
		if !did {
			t.Fatal("요청을 잡지 못했다")
		}
		if c.want == StatusSigned && !errors.Is(err, ErrTransient) {
			t.Fatalf("일시 오류 분류: %v", err)
		}
		if got := f.status(t, id); got != c.want {
			t.Fatalf("%v: 상태 %s (기대 %s)", c.err, got, c.want)
		}
		if c.code != "" {
			var e string
			_ = f.db.QueryRow(`SELECT error FROM requests WHERE request_id = ?`, id).Scan(&e)
			if !strings.HasPrefix(e, c.code) {
				t.Fatalf("error %q (기대 %s)", e, c.code)
			}
			if acts := auditActions(t, f.db, id); len(acts) != 1 || acts[0] != "REQUEST_FAILED" {
				t.Fatalf("감사 기록 %v", acts)
			}
		}
		_, _ = f.db.Exec(`UPDATE requests SET status = 'FAILED' WHERE request_id = ?`, id) // 다음 사례에 섞이지 않게
	}
}

// 제출 직후 커밋 전에 업무 서버가 죽은 경우: 요청은 SIGNED 로 남고, 다음 주기의 재제출은 같은 tx 를
// 다시 보내 성공으로 처리된다. 체인에는 한 번만 반영된다(실제 Besu).
func TestSubmitWorkerResubmitAfterCrash(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a, eth, err := besu.Dial(ctx, "http://127.0.0.1:8545", besu.Config{ChainID: 20261124, GasLimit: 300000, DeployGasLimit: 3000000})
	if err != nil {
		t.Fatalf("RPC(make up 필요): %v", err)
	}
	defer eth.Close()
	key, _ := crypto.GenerateKey() // 시험용 임시 키(가스비 0 네트워크)
	from := crypto.PubkeyToAddress(key.PublicKey)
	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	chainID := big.NewInt(20261124)
	tx, err := types.SignNewTx(key, types.LatestSignerForChainID(chainID), &types.DynamicFeeTx{ChainID: chainID, Nonce: 0, GasTipCap: big.NewInt(0), GasFeeCap: big.NewInt(0), Gas: 21000, To: &to})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	h := tx.Hash()
	id := f.insertRow(t, from, rawRow{status: StatusSigned, nonce: 0, raw: raw, txHash: h[:]})

	if _, err := a.Submit(ctx, raw); err != nil { // 죽기 전에 나간 제출
		t.Fatal(err)
	}
	w := &SubmitWorker{DB: f.db, LedgerID: f.ledger, Ledger: a}
	if did, err := w.RunOnce(ctx); !did || err != nil {
		t.Fatalf("재제출: %v %v", did, err)
	}
	if got := f.status(t, id); got != StatusSubmitted {
		t.Fatalf("상태 %s (기대 SUBMITTED)", got)
	}
	if did, _ := w.RunOnce(ctx); did {
		t.Fatal("SUBMITTED 요청을 다시 잡았다")
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := a.Receipt(ctx, h); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("영수증 대기 시간 초과")
		}
		time.Sleep(200 * time.Millisecond)
	}
	// 확정 뒤 같은 요청을 다시 제출해도 성공이고 반영은 한 번이다.
	if _, err := a.Submit(ctx, raw); err != nil {
		t.Fatal(err)
	}
	n, err := eth.NonceAt(ctx, from, nil)
	if err != nil || n != 1 {
		t.Fatalf("송신 주소 nonce %d (기대 1, 한 번만 반영) %v", n, err)
	}
	var sub sql.NullTime
	_ = f.db.QueryRow(`SELECT submitted_at FROM requests WHERE request_id = ?`, id).Scan(&sub)
	if !sub.Valid {
		t.Fatal("submitted_at 이 없다")
	}
	if acts := auditActions(t, f.db, id); len(acts) != 1 || acts[0] != "REQUEST_LEDGER_SUBMITTED" {
		t.Fatalf("감사 기록 %v", acts)
	}
}
