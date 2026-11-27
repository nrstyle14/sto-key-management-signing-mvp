// Package alarm 은 이상 징후 규칙이다(설계서 7.4, FR-3.5, 요구사항 C-1-2).
// 알람은 api.alarms 에 남기고 로그로 출력한다. 자동 동결은 하지 않는다.
package alarm

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"time"
)

// 규칙
const (
	RuleHighAmount    = "HIGH_AMOUNT"    // 수량이 정책 한도의 80% 이상
	RuleRepeatKey     = "REPEAT_KEY"     // 같은 키로 10분 안에 5건 이상 서명
	RuleRejectRepeat  = "REJECT_REPEAT"  // 같은 기안자의 요청이 10분 안에 3건 이상 서명 거부
	RuleTotalMismatch = "TOTAL_MISMATCH" // 대사 불일치(M4)
)

// Rules 는 규칙 기준값이다.
type Rules struct {
	RepeatKeyCount    int
	RepeatKeyWindow   time.Duration
	RejectRepeatCount int
	RejectWindow      time.Duration
}

// Defaults 는 설계서 7.4 의 기본값이다.
var Defaults = Rules{RepeatKeyCount: 5, RepeatKeyWindow: 10 * time.Minute, RejectRepeatCount: 3, RejectWindow: 10 * time.Minute}

// Recorder 는 알람을 평가하고 기록한다.
type Recorder struct {
	DB    *sql.DB
	Log   *slog.Logger
	Rules Rules
	Now   func() time.Time
}

func (r *Recorder) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// Alarm 은 기록된 알람이다.
type Alarm struct {
	AlarmID   uint64          `json:"alarm_id"`
	Rule      string          `json:"rule"`
	Subject   string          `json:"subject"`
	Detail    json.RawMessage `json:"detail"`
	CreatedAt time.Time       `json:"created_at"`
}

// Raise 는 알람을 기록한다. 같은 규칙·대상의 알람이 within 안에 이미 있으면 다시 기록하지 않는다.
func (r *Recorder) Raise(ctx context.Context, rule, subject string, detail map[string]any, within time.Duration) (bool, error) {
	if within > 0 {
		var n int
		if err := r.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM alarms WHERE rule = ? AND subject = ? AND created_at >= ?`,
			rule, subject, r.now().Add(-within)).Scan(&n); err != nil {
			return false, err
		}
		if n > 0 {
			return false, nil
		}
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return false, err
	}
	if _, err := r.DB.ExecContext(ctx, `INSERT INTO alarms (rule, subject, detail_json, created_at) VALUES (?, ?, ?, ?)`, rule, subject, string(b), r.now()); err != nil {
		return false, fmt.Errorf("alarm: 기록: %w", err)
	}
	if r.Log != nil {
		r.Log.Warn("알람", "rule", rule, "subject", subject, "detail", string(b))
	}
	return true, nil
}

// HighAmount 는 수량이 한도의 80% 이상이면 알람을 낸다(big.Int 로 계산).
func (r *Recorder) HighAmount(ctx context.Context, requestID, policyID string, amount, max *big.Int) (bool, error) {
	if amount == nil || max == nil || max.Sign() <= 0 {
		return false, nil
	}
	if new(big.Int).Mul(amount, big.NewInt(100)).Cmp(new(big.Int).Mul(max, big.NewInt(80))) < 0 {
		return false, nil
	}
	return r.Raise(ctx, RuleHighAmount, requestID, map[string]any{"request_id": requestID, "policy_id": policyID,
		"amount": amount.String(), "max_amount": max.String()}, 0)
}

// RepeatKey 는 같은 서명 키 주소로 창 안에 서명된 요청 수가 기준 이상이면 알람을 낸다.
func (r *Recorder) RepeatKey(ctx context.Context, ledgerID, address string) (bool, error) {
	var n int
	if err := r.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM requests WHERE ledger_id = ? AND signer_address = ?
		AND status IN ('SIGNED', 'SUBMITTED', 'CONFIRMED') AND updated_at >= ?`, ledgerID, address, r.now().Add(-r.Rules.RepeatKeyWindow)).Scan(&n); err != nil {
		return false, err
	}
	if n < r.Rules.RepeatKeyCount {
		return false, nil
	}
	return r.Raise(ctx, RuleRepeatKey, address, map[string]any{"ledger_id": ledgerID, "address": address, "count": n,
		"window": r.Rules.RepeatKeyWindow.String()}, r.Rules.RepeatKeyWindow)
}

// RejectRepeat 는 같은 기안자의 요청이 창 안에 서명 거부(FAILED)된 수가 기준 이상이면 알람을 낸다.
func (r *Recorder) RejectRepeat(ctx context.Context, drafterID string) (bool, error) {
	var n int
	if err := r.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM requests WHERE drafter_id = ? AND status = 'FAILED' AND updated_at >= ?`,
		drafterID, r.now().Add(-r.Rules.RejectWindow)).Scan(&n); err != nil {
		return false, err
	}
	if n < r.Rules.RejectRepeatCount {
		return false, nil
	}
	return r.Raise(ctx, RuleRejectRepeat, drafterID, map[string]any{"drafter_id": drafterID, "count": n,
		"window": r.Rules.RejectWindow.String()}, r.Rules.RejectWindow)
}

// List 는 최근 알람 목록이다.
func List(ctx context.Context, db *sql.DB, limit int) ([]Alarm, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.QueryContext(ctx, `SELECT alarm_id, rule, subject, detail_json, created_at FROM alarms ORDER BY alarm_id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alarm{}
	for rows.Next() {
		var a Alarm
		var d string
		if err := rows.Scan(&a.AlarmID, &a.Rule, &a.Subject, &d, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.Detail, a.CreatedAt = json.RawMessage(d), a.CreatedAt.UTC()
		out = append(out, a)
	}
	return out, rows.Err()
}
