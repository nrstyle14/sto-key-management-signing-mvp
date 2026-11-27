//go:build integration

package workflow

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/oklog/ulid/v2"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger"
)

// fakeReceipts 는 영수증 조회와 재제출 대역이다.
type fakeReceipts struct {
	rc      *ledger.Receipt
	submits atomic.Int32
}

func (f *fakeReceipts) Submit(context.Context, []byte) (ledger.TxHash, error) {
	f.submits.Add(1)
	return common.Hash{}, nil
}

func (f *fakeReceipts) Receipt(context.Context, ledger.TxHash) (*ledger.Receipt, error) {
	if f.rc == nil {
		return nil, ledger.ErrReceiptNotFound
	}
	return f.rc, nil
}

// submittedRow 는 제출 시각이 ago 전이고 마지막 확인이 checked 전인 SUBMITTED 요청을 넣는다(DB 시각 기준).
func (f *fx) submittedRow(t *testing.T, typ, intentJSON string, ago, checked time.Duration) string {
	t.Helper()
	id := ulid.Make().String()
	h := common.HexToHash("0xabcd")
	_, err := f.db.Exec(`INSERT INTO requests (request_id, type, ledger_id, institution_id, intent_json, intent_hash, status, drafter_id,
		signer_address, nonce, raw_tx, tx_hash, submitted_at, expires_at) VALUES (?, ?, ?, 'platform', ?, ?, 'SUBMITTED', 'sec-01', ?, 1, ?, ?,
		UTC_TIMESTAMP(6) - INTERVAL ? MICROSECOND, UTC_TIMESTAMP(6) + INTERVAL 1 HOUR)`,
		id, typ, f.ledger, intentJSON, make([]byte, 32), f.keyAddr.Hex(), []byte{1}, h[:], ago.Microseconds())
	if err != nil {
		t.Fatal(err)
	}
	f.backdate(t, id, checked)
	return id
}

func (f *fx) backdate(t *testing.T, id string, checked time.Duration) {
	t.Helper()
	if _, err := f.db.Exec(`UPDATE requests SET updated_at = UTC_TIMESTAMP(6) - INTERVAL ? MICROSECOND WHERE request_id = ?`, checked.Microseconds(), id); err != nil {
		t.Fatal(err)
	}
}

// 영수증이 없으면 제출 시각부터 30초마다 한 번만 같은 tx 를 다시 제출하고, 10분이 지나면 FAILED(LEDGER_TIMEOUT)다.
func TestReceiptWorkerResubmitAndTimeout(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	src := &fakeReceipts{}
	w := &ReceiptWorker{DB: f.db, LedgerID: f.ledger, Ledger: src}
	id := f.submittedRow(t, "TX", "{}", 35*time.Second, 30*time.Second)

	if did, err := w.RunOnce(ctx); !did || err != nil {
		t.Fatalf("첫 확인: %v %v", did, err)
	}
	if n := src.submits.Load(); n != 1 {
		t.Fatalf("30초가 지난 첫 확인의 재제출 %d 회(기대 1)", n)
	}
	// 방금 확인했으므로 1초 안에는 다시 잡지 않는다.
	if did, _ := w.RunOnce(ctx); did {
		t.Fatal("방금 확인한 요청을 다시 잡았다")
	}
	// 같은 30초 구간(제출 후 35초 → 마지막 확인 33초 전)이면 다시 보내지 않는다.
	f.backdate(t, id, 2*time.Second)
	if did, _ := w.RunOnce(ctx); !did || src.submits.Load() != 1 {
		t.Fatalf("같은 구간의 재확인에서 재제출 %d 회", src.submits.Load())
	}
	if f.status(t, id) != StatusSubmitted {
		t.Fatal("시간 초과 전에 상태가 바뀌었다")
	}
	// 10분이 지나면 FAILED(LEDGER_TIMEOUT)와 감사 기록
	f.backdate(t, id, 2*time.Second)
	w.Now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if did, err := w.RunOnce(ctx); !did || err != nil {
		t.Fatalf("시간 초과 확인: %v %v", did, err)
	}
	r, _ := f.svc.Get(ctx, id)
	if r.Status != StatusFailed || !strings.HasPrefix(r.Error, CodeLedgerTimeout) {
		t.Fatalf("시간 초과 뒤 %s %s", r.Status, r.Error)
	}
	if acts := auditActions(t, f.db, id); len(acts) != 1 || acts[0] != "REQUEST_FAILED" {
		t.Fatalf("감사 기록 %v", acts)
	}
}

// revert 는 FAILED(LEDGER_REVERTED), 배포 확정은 CONFIRMED 와 종목·이벤트 커서 등록(같은 트랜잭션).
func TestReceiptWorkerSettle(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = f.db.Exec(`DELETE FROM ledger_cursor WHERE ledger_id = ?`, f.ledger)
		_, _ = f.db.Exec(`DELETE FROM securities WHERE ledger_id = ?`, f.ledger)
	})
	src := &fakeReceipts{rc: &ledger.Receipt{Status: 0, BlockNumber: 41}}
	w := &ReceiptWorker{DB: f.db, LedgerID: f.ledger, Ledger: src}
	id := f.submittedRow(t, "TX", "{}", time.Second, 2*time.Second)
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	r, _ := f.svc.Get(ctx, id)
	if r.Status != StatusFailed || !strings.HasPrefix(r.Error, CodeLedgerReverted) || r.BlockNumber == nil || *r.BlockNumber != 41 {
		t.Fatalf("revert: %s %s %v", r.Status, r.Error, r.BlockNumber)
	}

	code := "KRCF" + strings.ToUpper(f.ledger[len(f.ledger)-6:])
	in := &intent.Intent{RequestID: ulid.Make().String(), Type: intent.TypeDeploy, LedgerID: f.ledger, InstitutionID: "platform",
		KeyPurpose: "CONTRACT_ADMIN", Contract: intent.ZeroAddress, Function: "constructor(string,string,address)",
		Args: []string{"확정 시험", code, f.keyAddr.Hex()}, DrafterID: "sec-01", ExpiresAt: time.Now().UTC().Add(time.Hour).Format(intent.TimeLayout),
		CodeHash: "0x" + strings.Repeat("ab", 32)}
	canon, err := in.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	contract := common.HexToAddress("0x00000000000000000000000000000000000c0ffe")
	src.rc = &ledger.Receipt{Status: 1, BlockNumber: 77, ContractAddress: &contract}
	id = f.submittedRow(t, "DEPLOY", string(canon), time.Second, 2*time.Second)
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	r, _ = f.svc.Get(ctx, id)
	if r.Status != StatusConfirmed || r.ContractAddress != contract.Hex() || *r.BlockNumber != 77 {
		t.Fatalf("배포 확정: %s %s %v", r.Status, r.ContractAddress, r.BlockNumber)
	}
	var name, addr string
	var last uint64
	if err := f.db.QueryRow(`SELECT s.name, s.contract_address, c.last_block FROM securities s JOIN ledger_cursor c
		ON c.ledger_id = s.ledger_id AND c.contract_address = s.contract_address WHERE s.issue_code = ?`, code).Scan(&name, &addr, &last); err != nil {
		t.Fatal(err)
	}
	if name != "확정 시험" || addr != contract.Hex() || last != 76 {
		t.Fatalf("종목 등록 %s %s 커서 %d", name, addr, last)
	}
	var p string
	_ = f.db.QueryRow(`SELECT payload_json FROM audit_log WHERE action = 'SECURITY_REGISTERED' AND subject = ?`, code).Scan(&p)
	var m map[string]any
	if json.Unmarshal([]byte(p), &m) != nil || m["request_id"] != id {
		t.Fatalf("종목 등록 감사 기록: %s", p)
	}
}
