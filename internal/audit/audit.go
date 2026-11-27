// Package audit 는 추가 전용 해시 체인 감사로그다(설계서 8절, FR-4).
// api, signer 두 스키마의 audit_log 를 같은 코드로 다룬다.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// TimeLayout 은 해시에 넣는 시각 형식이다(UTC, 마이크로초). DB DATETIME(6) 값과 같다.
const TimeLayout = "2006-01-02T15:04:05.000000Z"

// Record 는 감사로그 한 행이다.
type Record struct {
	Seq         uint64    `json:"seq"`
	TS          time.Time `json:"ts"`
	Actor       string    `json:"actor"`
	Action      string    `json:"action"`
	Subject     string    `json:"subject"`
	PayloadJSON string    `json:"payload_json"`
	PrevHash    Hash      `json:"prev_hash"`
	Hash        Hash      `json:"hash"`
}

// Hash 는 32바이트 해시이며 JSON 에서는 16진수 문자열이다.
type Hash [32]byte

// MarshalText 는 16진수로 직렬화한다.
func (h Hash) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(h[:])), nil }

// UnmarshalText 는 16진수를 해석한다.
func (h *Hash) UnmarshalText(b []byte) error {
	d, err := hex.DecodeString(string(b))
	if err != nil || len(d) != 32 {
		return fmt.Errorf("audit: 해시 형식 오류(길이 %d)", len(b))
	}
	copy(h[:], d)
	return nil
}

// Entry 는 추가할 내용이다. Payload 는 허용된 키만 쓸 수 있다.
type Entry struct {
	Actor   string
	Action  string
	Subject string
	Payload map[string]any
}

// allowedKeys 는 payload 에 쓸 수 있는 키다. 개인키·PIN·래핑 키·승인자 개인키·비밀번호가 들어갈 자리가 없게 한다.
var allowedKeys = map[string]bool{
	"request_id": true, "key_id": true, "token": true, "purpose": true, "class": true, "address": true,
	"ledger_id": true, "institution_id": true, "intent_hash": true, "unsigned_tx_hash": true, "tx_hash": true,
	"step": true, "code": true, "reason": true, "status": true, "from_status": true, "to_status": true,
	"approver_id": true, "approvers": true, "decision": true, "policy_id": true, "version": true,
	"freeze_id": true, "scope": true, "target": true, "count": true, "keys": true, "tokens": true,
	"policies": true, "caller": true, "drafter_id": true, "function": true, "contract": true,
	"chain": true, "seq": true, "head_hash": true, "checkpoint_id": true, "nonce": true, "type": true,
	"rule": true, "error": true, "code_hash": true, "contract_address": true, "block_number": true,
	"issue_code": true, "args": true, "from_block": true, "to_block": true,
	"objects_before": true, "objects_after": true, "commitment": true, "ceremony_id": true, "custodians": true,
}

// ErrPayloadKey 는 허용되지 않은 payload 키다.
var ErrPayloadKey = errors.New("audit: 허용되지 않은 payload 키")

// CanonicalPayload 는 허용 키·허용 타입만 받아 정렬된 JSON 을 만든다.
func CanonicalPayload(p map[string]any) (string, error) {
	if p == nil {
		p = map[string]any{}
	}
	for k, v := range p {
		if !allowedKeys[k] {
			return "", fmt.Errorf("%w: %q", ErrPayloadKey, k)
		}
		switch v.(type) {
		case string, bool, int, int64, uint64, uint32, []string:
		default:
			return "", fmt.Errorf("audit: payload %q 의 타입 %T 는 허용되지 않는다", k, v)
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return "", err
	}
	return string(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

// ComputeHash 는 레코드 해시다: 각 필드 앞에 4바이트 빅엔디언 길이를 붙여 이어 붙인 값의 SHA-256.
func ComputeHash(r Record) Hash {
	h := sha256.New()
	field := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], r.Seq)
	field(seq[:])
	field([]byte(r.TS.UTC().Format(TimeLayout)))
	field([]byte(r.Actor))
	field([]byte(r.Action))
	field([]byte(r.Subject))
	field([]byte(r.PayloadJSON))
	field(r.PrevHash[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// Append 는 tx 안에서 체인 머리 행(audit_head)을 잠그고 레코드를 하나 추가한다.
// 업무 기록과 같은 트랜잭션으로 부르고, 잠금 경합을 줄이려 트랜잭션의 마지막에 부른다.
func Append(ctx context.Context, tx *sql.Tx, e Entry) (Record, error) {
	if e.Actor == "" || e.Action == "" {
		return Record{}, errors.New("audit: actor, action 이 필요하다")
	}
	payload, err := CanonicalPayload(e.Payload)
	if err != nil {
		return Record{}, err
	}
	var headSeq uint64
	var headHash []byte
	if err := tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_head WHERE id = 1 FOR UPDATE`).Scan(&headSeq, &headHash); err != nil {
		return Record{}, fmt.Errorf("audit: 체인 머리 잠금: %w", err)
	}
	r := Record{Seq: headSeq + 1, TS: time.Now().UTC().Truncate(time.Microsecond), Actor: e.Actor, Action: e.Action,
		Subject: e.Subject, PayloadJSON: payload}
	copy(r.PrevHash[:], headHash)
	r.Hash = ComputeHash(r)
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log (seq, ts, actor, action, subject, payload_json, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Seq, r.TS, r.Actor, r.Action, r.Subject, r.PayloadJSON, r.PrevHash[:], r.Hash[:]); err != nil {
		return Record{}, fmt.Errorf("audit: 기록: %w", err)
	}
	res, err := tx.ExecContext(ctx, `UPDATE audit_head SET seq = ?, hash = ? WHERE id = 1 AND seq = ?`, r.Seq, r.Hash[:], headSeq)
	if err != nil {
		return Record{}, fmt.Errorf("audit: 머리 갱신: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return Record{}, errors.New("audit: 머리 갱신 충돌")
	}
	return r, nil
}

// AppendTx 는 감사 기록 하나만을 위한 트랜잭션을 열어 추가한다(롤백된 업무에 대한 거부 기록 등).
func AppendTx(ctx context.Context, db *sql.DB, e Entry) (Record, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	r, err := Append(ctx, tx, e)
	if err != nil {
		_ = tx.Rollback()
		return Record{}, err
	}
	return r, tx.Commit()
}

// Load 는 seq >= from 인 레코드를 seq 순서로 최대 limit 개 읽는다.
func Load(ctx context.Context, db *sql.DB, from uint64, limit int) ([]Record, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := db.QueryContext(ctx, `SELECT seq, ts, actor, action, subject, payload_json, prev_hash, hash FROM audit_log WHERE seq >= ? ORDER BY seq LIMIT ?`, from, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: 조회: %w", err)
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		var prev, h []byte
		if err := rows.Scan(&r.Seq, &r.TS, &r.Actor, &r.Action, &r.Subject, &r.PayloadJSON, &prev, &h); err != nil {
			return nil, err
		}
		r.TS = r.TS.UTC()
		copy(r.PrevHash[:], prev)
		copy(r.Hash[:], h)
		out = append(out, r)
	}
	return out, rows.Err()
}

// HeadOf 는 audit_log 의 마지막 레코드(seq, hash)다. 비어 있으면 (0, 0 해시).
func HeadOf(ctx context.Context, db *sql.DB) (uint64, Hash, error) {
	var seq uint64
	var h []byte
	err := db.QueryRowContext(ctx, `SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&seq, &h)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, Hash{}, nil
	}
	if err != nil {
		return 0, Hash{}, err
	}
	var out Hash
	copy(out[:], h)
	return seq, out, nil
}

// Result 는 검증 결과다. OK 가 false 면 FirstBadSeq 가 어긋난 첫 seq 다.
type Result struct {
	OK          bool   `json:"ok"`
	Count       int    `json:"count"`
	HeadSeq     uint64 `json:"head_seq"`
	HeadHash    Hash   `json:"head_hash"`
	FirstBadSeq uint64 `json:"first_bad_seq,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// Verifier 는 레코드를 순서대로 받아 체인을 검증한다(페이지 단위로 받기 위함).
// 검증을 통과한 레코드의 seq → hash 를 Hashes 에 남긴다(체크포인트 대조용).
type Verifier struct {
	res     Result
	next    uint64
	prev    Hash
	stopped bool
	Hashes  map[uint64]Hash
}

// NewVerifier 는 seq 1 부터 검증한다.
func NewVerifier() *Verifier {
	return &Verifier{next: 1, res: Result{OK: true}, Hashes: map[uint64]Hash{}}
}

// Add 는 다음 레코드를 검증한다. 처음 어긋난 곳에서 멈춘다.
func (v *Verifier) Add(r Record) {
	if v.stopped {
		return
	}
	fail := func(reason string) {
		v.res.OK, v.res.FirstBadSeq, v.res.Reason, v.stopped = false, r.Seq, reason, true
	}
	switch {
	case r.Seq != v.next:
		v.res.OK, v.res.FirstBadSeq, v.res.Reason, v.stopped = false, v.next, fmt.Sprintf("seq %d 가 빠졌다(다음 레코드 seq %d)", v.next, r.Seq), true
		return
	case r.PrevHash != v.prev:
		fail("prev_hash 가 직전 레코드 해시와 다르다")
		return
	case ComputeHash(r) != r.Hash:
		fail("레코드 해시가 내용과 다르다(변조)")
		return
	}
	v.res.Count++
	v.res.HeadSeq, v.res.HeadHash = r.Seq, r.Hash
	v.Hashes[r.Seq] = r.Hash
	v.prev, v.next = r.Hash, r.Seq+1
}

// Result 는 지금까지의 결과다.
func (v *Verifier) Result() Result { return v.res }

// Verify 는 seq 1 부터의 전체 레코드를 검증한다.
func Verify(records []Record) Result {
	sorted := append([]Record(nil), records...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Seq < sorted[j].Seq })
	v := NewVerifier()
	for _, r := range sorted {
		v.Add(r)
	}
	return v.Result()
}
