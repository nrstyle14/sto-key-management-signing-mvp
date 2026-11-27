package workflow

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/go-sql-driver/mysql"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signsvc"
)

// Chain 은 nonce 할당에 쓰는 원장 조회다.
type Chain interface {
	PendingNonceAt(ctx context.Context, addr common.Address) (uint64, error)
}

// TxBuilder 는 intent 를 미서명 tx 로 만든다(ledger.Ledger.BuildTx).
type TxBuilder interface {
	BuildTx(ctx context.Context, in *intent.Intent, from common.Address, nonce uint64) ([]byte, error)
}

// AllocateNonce 는 (원장, 주소)의 다음 nonce 를 tx 안에서 잠그고 할당한다(설계서 5.5).
//   - 빈자리 재사용(T3.2): 서명·제출되지 않고 FAILED·EXPIRED 로 끝난 요청의 nonce 가 체인 pending 이상이고
//     살아 있는 다른 요청이 쓰지 않으면 그 값을 먼저 다시 쓴다. Besu 는 빈자리 뒤의 tx 를 풀에 붙잡아 두므로
//     (실측) 빈자리를 메우지 않으면 그 주소의 이후 tx 가 모두 멈춘다.
//   - 빈자리가 없으면 DB 의 다음 값과 체인의 pending nonce 중 큰 값을 쓴다(다른 경로로 앞서 나간 경우에도 겹치지 않음).
//
// 노드가 한 번이라도 받은 tx(submitted_at 있음)의 nonce 는 재사용하지 않는다. 할당은 nonces 행 잠금으로 직렬화된다.
func AllocateNonce(ctx context.Context, tx *sql.Tx, chain Chain, ledgerID string, addr common.Address) (uint64, error) {
	pending, err := chain.PendingNonceAt(ctx, addr)
	if err != nil {
		return 0, fmt.Errorf("workflow: pending nonce 조회: %w", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		var next uint64
		err := tx.QueryRowContext(ctx, `SELECT next_nonce FROM nonces WHERE ledger_id = ? AND address = ? FOR UPDATE`, ledgerID, addr.Hex()).Scan(&next)
		if errors.Is(err, sql.ErrNoRows) {
			_, ierr := tx.ExecContext(ctx, `INSERT INTO nonces (ledger_id, address, next_nonce) VALUES (?, ?, ?)`, ledgerID, addr.Hex(), pending+1)
			var me *mysql.MySQLError
			if errors.As(ierr, &me) && me.Number == 1062 {
				continue // 다른 작업자가 먼저 만들었다. 잠그고 다시 읽는다.
			}
			if ierr != nil {
				return 0, ierr
			}
			return pending, nil
		}
		if err != nil {
			return 0, err
		}
		gap, ok, err := freeGap(ctx, tx, ledgerID, addr, pending, next)
		if err != nil {
			return 0, err
		}
		if ok {
			return gap, nil
		}
		n := max(next, pending)
		if _, err := tx.ExecContext(ctx, `UPDATE nonces SET next_nonce = ? WHERE ledger_id = ? AND address = ?`, n+1, ledgerID, addr.Hex()); err != nil {
			return 0, err
		}
		return n, nil
	}
	return 0, errors.New("workflow: nonce 행 생성 경합")
}

// freeGap 은 [pending, next) 구간에서 끝난 요청이 남긴 빈자리 중 가장 작은 nonce 를 찾는다.
// 같은 nonce 를 쥔 살아 있는 요청(진행 중·확정, 또는 노드가 한 번이라도 받은 tx)이 있으면 빈자리가 아니다.
func freeGap(ctx context.Context, tx *sql.Tx, ledgerID string, addr common.Address, pending, next uint64) (uint64, bool, error) {
	if pending >= next {
		return 0, false, nil
	}
	var n uint64
	err := tx.QueryRowContext(ctx, `SELECT r.nonce FROM requests r
		WHERE r.ledger_id = ? AND r.signer_address = ? AND r.nonce >= ? AND r.nonce < ?
		  AND r.status IN ('FAILED', 'EXPIRED') AND r.submitted_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM requests l WHERE l.ledger_id = r.ledger_id AND l.signer_address = r.signer_address
		                  AND l.nonce = r.nonce AND (l.status IN ('APPROVED', 'SIGNED', 'SUBMITTED', 'CONFIRMED') OR l.submitted_at IS NOT NULL))
		ORDER BY r.nonce LIMIT 1`, ledgerID, addr.Hex(), pending, next).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return n, true, nil
}

// releaseNonce 는 서명되지 않고 끝난 요청(FAILED, EXPIRED)이 잡은 nonce 를 돌려준다(설계서 5.5).
// 그 nonce 가 마지막으로 할당된 값이면 다음 할당이 다시 쓴다. 뒤에 이미 다른 nonce 가 할당됐으면 빈자리로 남는다
// (빈자리 재사용은 원장 제출을 다루는 T3.2 에서 처리한다).
func releaseNonce(ctx context.Context, tx *sql.Tx, ledgerID, address string, nonce uint64) error {
	_, err := tx.ExecContext(ctx, `UPDATE nonces SET next_nonce = ? WHERE ledger_id = ? AND address = ? AND next_nonce = ?`,
		nonce, ledgerID, address, nonce+1)
	return err
}

// releaseRequestNonce 는 요청에 할당된 nonce 가 있으면 releaseNonce 한다.
func releaseRequestNonce(ctx context.Context, tx *sql.Tx, id string) error {
	var ledger, addr sql.NullString
	var nonce sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT ledger_id, signer_address, nonce FROM requests WHERE request_id = ?`, id).Scan(&ledger, &addr, &nonce); err != nil {
		return err
	}
	if !nonce.Valid || !addr.Valid || addr.String == "" {
		return nil
	}
	return releaseNonce(ctx, tx, ledger.String, addr.String, uint64(nonce.Int64))
}

// SignWorker 는 APPROVED 요청을 서명 서버로 보낸다(설계서 5.4).
//   - 요청 행은 `FOR UPDATE SKIP LOCKED` 로 잡는다. 같은 요청을 두 작업자가 동시에 처리하지 않는다.
//   - 처음에는 nonce 와 미서명 tx 를 만들어 요청에 저장(커밋)한다. 이후 서명 요청은 항상 저장된 같은 바이트를 보낸다.
//   - 서명 서버가 거부하면 FAILED, 응답이 없거나 일시 오류면 APPROVED 로 남겨 다음 주기에 다시 보낸다(NFR-4).
type SignWorker struct {
	DB       *sql.DB
	LedgerID string // 이 작업자가 처리하는 원장. 다른 원장의 요청은 건드리지 않는다
	Dir      Directory
	Signer   SignerClient
	Chain    Chain
	Builder  TxBuilder
	Now      func() time.Time
	// OnSigned, OnFailed 는 알람 규칙(설계서 7.4)에 쓰는 훅이다.
	OnSigned func(ctx context.Context, r *Request)
	OnFailed func(ctx context.Context, r *Request, code string)
}

func (w *SignWorker) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}

// ErrTransient 는 다음 주기에 다시 시도할 오류다.
var ErrTransient = errors.New("workflow: 일시 오류(다음 주기에 재시도)")

// RunOnce 는 APPROVED 요청 하나를 한 단계 진행한다. 처리한 요청이 있으면 true 다.
func (w *SignWorker) RunOnce(ctx context.Context) (bool, error) {
	tx, err := w.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var id, intentJSON string
	var signerAddr sql.NullString
	var hash, unsigned []byte
	var expires time.Time
	err = tx.QueryRowContext(ctx, `SELECT request_id, intent_json, intent_hash, unsigned_tx, signer_address, expires_at FROM requests
		WHERE status = 'APPROVED' AND ledger_id = ? ORDER BY updated_at LIMIT 1 FOR UPDATE SKIP LOCKED`, w.LedgerID).Scan(&id, &intentJSON, &hash, &unsigned, &signerAddr, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !w.now().Before(expires) {
		if err := w.finish(ctx, tx, id, StatusExpired, "REQUEST_EXPIRED", map[string]any{"reason": "서명 전에 만료"}, nil); err != nil {
			return true, err
		}
		return true, tx.Commit()
	}
	in, err := intent.Parse([]byte(intentJSON))
	if err != nil {
		return true, fmt.Errorf("workflow: 저장된 intent 해석(%s): %w", id, err)
	}

	if len(unsigned) == 0 {
		// 1단계: 서명 키 주소 확인 → nonce 할당 → 미서명 tx 저장(커밋).
		keys, err := w.Dir.Keys(ctx)
		if err != nil {
			_ = tx.Rollback()
			w.rotate(ctx, id)
			return true, fmt.Errorf("%w: 키 조회: %v", ErrTransient, err)
		}
		var addr string
		for _, k := range keys {
			if k.LedgerID == in.LedgerID && k.InstitutionID == in.InstitutionID && k.Purpose == string(in.KeyPurpose) && k.Status == "ACTIVE" {
				if addr != "" {
					addr = "ambiguous"
					break
				}
				addr = k.Address
			}
		}
		if addr == "" || addr == "ambiguous" || !common.IsHexAddress(addr) {
			if err := w.finish(ctx, tx, id, StatusFailed, "REQUEST_FAILED", map[string]any{"code": signsvc.CodeKeyNotAvailable},
				map[string]any{"error": signsvc.CodeKeyNotAvailable}); err != nil {
				return true, err
			}
			return true, tx.Commit()
		}
		from := common.HexToAddress(addr)
		nonce, err := AllocateNonce(ctx, tx, w.Chain, in.LedgerID, from)
		if err != nil {
			return true, fmt.Errorf("%w: %v", ErrTransient, err)
		}
		raw, err := w.Builder.BuildTx(ctx, in, from, nonce)
		if err != nil {
			return true, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE requests SET signer_address = ?, nonce = ?, unsigned_tx = ? WHERE request_id = ? AND status = 'APPROVED' AND unsigned_tx IS NULL`,
			from.Hex(), nonce, raw, id); err != nil {
			return true, err
		}
		return true, tx.Commit()
	}

	// 2단계: 저장된 미서명 tx 와 승인들로 서명 요청(행 잠금을 쥔 채 한 번만 보낸다).
	// nonce 를 할당한 서명 키 주소를 함께 보낸다. 그 사이 키가 교체됐으면 서명 서버가 4단계에서 거부한다(T3.5).
	req := signsvc.Request{Intent: []byte(intentJSON), IntentHash: hex.EncodeToString(hash), UnsignedTx: "0x" + hex.EncodeToString(unsigned),
		SignerAddress: signerAddr.String}
	rows, err := tx.QueryContext(ctx, `SELECT approver_id, decision, signature FROM approvals WHERE request_id = ? ORDER BY approver_id`, id)
	if err != nil {
		return true, err
	}
	for rows.Next() {
		var a approval.Approval
		var sig []byte
		if err := rows.Scan(&a.ApproverID, &a.Decision, &sig); err != nil {
			rows.Close()
			return true, err
		}
		a.Signature = hex.EncodeToString(sig)
		req.Approvals = append(req.Approvals, a)
	}
	rows.Close()

	res, err := w.Signer.SignTx(ctx, req)
	var rj *signsvc.Rejection
	switch {
	case err == nil:
		rawSigned, derr := hex.DecodeString(res.SignedTx[2:])
		if derr != nil || len(res.TxHash) != 66 {
			return true, fmt.Errorf("workflow: 서명 서버 응답 형식 오류")
		}
		txHash := common.HexToHash(res.TxHash)
		if err := w.finish(ctx, tx, id, StatusSigned, "REQUEST_SIGNED", map[string]any{"tx_hash": res.TxHash, "key_id": res.KeyID, "address": res.Address},
			map[string]any{"raw_tx": rawSigned, "tx_hash": txHash[:]}); err != nil {
			return true, err
		}
		if err := tx.Commit(); err != nil {
			return true, err
		}
		if w.OnSigned != nil {
			if r, gerr := (&Service{DB: w.DB}).Get(ctx, id); gerr == nil {
				w.OnSigned(ctx, r)
			}
		}
		return true, nil
	case errors.As(err, &rj):
		if err := w.finish(ctx, tx, id, StatusFailed, "REQUEST_FAILED", map[string]any{"code": rj.Code, "step": rj.Step, "reason": truncate(rj.Msg, 300)},
			map[string]any{"error": rj.Code + ": " + truncate(rj.Msg, 500)}); err != nil {
			return true, err
		}
		if err := tx.Commit(); err != nil {
			return true, err
		}
		if w.OnFailed != nil {
			if r, gerr := (&Service{DB: w.DB}).Get(ctx, id); gerr == nil {
				w.OnFailed(ctx, r, rj.Code)
			}
		}
		return true, nil
	default:
		_ = tx.Rollback()
		w.rotate(ctx, id)
		return true, fmt.Errorf("%w: 서명 서버 호출: %v", ErrTransient, err)
	}
}

// truncate 는 UTF-8 문자 경계를 지키며 n 바이트 이하로 자른다.
// rotate 는 일시 오류가 난 요청을 대기열 뒤로 보낸다(한 요청이 다른 요청을 계속 막지 않게).
func (w *SignWorker) rotate(ctx context.Context, id string) {
	_, _ = w.DB.ExecContext(ctx, `UPDATE requests SET updated_at = CURRENT_TIMESTAMP(6) WHERE request_id = ? AND status = 'APPROVED'`, id)
}

func truncate(v string, n int) string {
	if len(v) <= n {
		return v
	}
	for n > 0 && !utf8.RuneStart(v[n]) {
		n--
	}
	return v[:n]
}

// finish 는 APPROVED 에서 to 로 전이하고 감사 기록을 같은 트랜잭션에 넣는다.
func (w *SignWorker) finish(ctx context.Context, tx *sql.Tx, id string, to Status, action string, payload, set map[string]any) error {
	if to == StatusFailed || to == StatusExpired {
		if err := releaseRequestNonce(ctx, tx, id); err != nil {
			return err
		}
	}
	if err := Transition(ctx, tx, id, StatusApproved, to, set); err != nil {
		return err
	}
	payload["request_id"], payload["status"] = id, string(to)
	_, err := audit.Append(ctx, tx, audit.Entry{Actor: "apid", Action: action, Subject: id, Payload: payload})
	return err
}

// ExpireOnce 는 ledgerID 원장에서 만료 시각이 지난 PENDING_APPROVAL, APPROVED 요청을 EXPIRED 로 바꾼다. 바꾼 건수를 돌려준다.
func ExpireOnce(ctx context.Context, db *sql.DB, ledgerID string, now time.Time) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT request_id, status FROM requests WHERE status IN ('PENDING_APPROVAL', 'APPROVED') AND ledger_id = ? AND expires_at <= ?
		ORDER BY expires_at LIMIT 50 FOR UPDATE SKIP LOCKED`, ledgerID, now.UTC())
	if err != nil {
		return 0, err
	}
	type item struct{ id, status string }
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.status); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, it)
	}
	rows.Close()
	for _, it := range items {
		if err := releaseRequestNonce(ctx, tx, it.id); err != nil {
			return 0, err
		}
		if err := Transition(ctx, tx, it.id, Status(it.status), StatusExpired, nil); err != nil {
			return 0, err
		}
		if _, err := audit.Append(ctx, tx, audit.Entry{Actor: "apid", Action: "REQUEST_EXPIRED", Subject: it.id,
			Payload: map[string]any{"request_id": it.id, "from_status": it.status, "status": string(StatusExpired)}}); err != nil {
			return 0, err
		}
	}
	return len(items), tx.Commit()
}

// Run 은 주기마다 서명 작업자와 만료 작업자를 돌린다. ctx 가 끝나면 멈춘다.
func (w *SignWorker) Run(ctx context.Context, interval time.Duration, logf func(msg string, args ...any)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := ExpireOnce(ctx, w.DB, w.LedgerID, w.now()); err != nil {
			logf("만료 작업 오류", "err", err)
		} else if n > 0 {
			logf("요청 만료", "count", n)
		}
		transient := 0
		for i := 0; i < 50; i++ { // 한 주기에 여러 건을 진행한다
			did, err := w.RunOnce(ctx)
			if err != nil {
				logf("서명 작업 오류", "err", err)
				if errors.Is(err, ErrTransient) && transient < 3 {
					transient++
					continue // 대기열 뒤로 보냈으니 다음 요청을 진행한다(서명 서버 장애 시 한 주기에 최대 3번)
				}
				break
			}
			if !did {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
