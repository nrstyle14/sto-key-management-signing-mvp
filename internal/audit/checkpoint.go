package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// CheckpointDomain 은 체크포인트 서명의 도메인 구분 문자열이다.
const CheckpointDomain = "sto-audit-checkpoint-v1"

// Checkpoint 는 체인 머리(seq, hash)에 대한 AUDIT 키 서명이다(설계서 8절, FR-4.3).
type Checkpoint struct {
	ID        uint64    `json:"id"`
	Chain     string    `json:"chain"`
	Seq       uint64    `json:"seq"`
	HeadHash  Hash      `json:"head_hash"`
	KeyID     string    `json:"key_id"`
	Signature string    `json:"signature"` // 16진수 65바이트(r||s||v)
	TS        time.Time `json:"ts"`
}

// CheckpointDigest 는 서명할 32바이트다: SHA-256("sto-audit-checkpoint-v1" || len||chain || seq(8) || head_hash(32)).
func CheckpointDigest(chain string, seq uint64, head Hash) [32]byte {
	var b bytes.Buffer
	b.WriteString(CheckpointDomain)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(chain)))
	b.Write(n[:])
	b.WriteString(chain)
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	b.Write(s[:])
	b.Write(head[:])
	return sha256.Sum256(b.Bytes())
}

// VerifyCheckpointSignature 는 체크포인트 서명이 pub(65바이트 비압축 secp256k1 공개키)로 복구되는지 확인한다.
func VerifyCheckpointSignature(cp Checkpoint, pub []byte) error {
	sig, err := hex.DecodeString(cp.Signature)
	if err != nil || len(sig) != 65 {
		return errors.New("체크포인트 서명 형식 오류")
	}
	d := CheckpointDigest(cp.Chain, cp.Seq, cp.HeadHash)
	got, err := crypto.Ecrecover(d[:], sig)
	if err != nil || !bytes.Equal(got, pub) || !crypto.VerifySignature(pub, d[:], sig[:64]) {
		return errors.New("체크포인트 서명이 AUDIT 키와 맞지 않는다")
	}
	return nil
}

// CheckpointResult 는 체크포인트 하나의 검증 결과다.
type CheckpointResult struct {
	Checkpoint Checkpoint `json:"checkpoint"`
	OK         bool       `json:"ok"`
	Reason     string     `json:"reason,omitempty"`
}

// VerifyCheckpoints 는 각 체크포인트의 서명과, 다시 계산한 체인의 같은 seq 해시가 체크포인트의 머리 해시와 같은지 확인한다.
// hashes 는 체인 검증으로 얻은 seq → hash 다. pubkeys 는 key_id → AUDIT 공개키다.
// 마지막 체크포인트 이후 구간의 재작성은 체크포인트로는 알 수 없다(다음 체크포인트가 생길 때 잡힌다).
func VerifyCheckpoints(cps []Checkpoint, hashes map[uint64]Hash, pubkeys map[string][]byte) []CheckpointResult {
	out := make([]CheckpointResult, 0, len(cps))
	for _, cp := range cps {
		r := CheckpointResult{Checkpoint: cp, OK: true}
		pub, ok := pubkeys[cp.KeyID]
		switch {
		case !ok:
			r.OK, r.Reason = false, "체크포인트 키 "+cp.KeyID+" 의 공개키가 없다"
		case VerifyCheckpointSignature(cp, pub) != nil:
			r.OK, r.Reason = false, "체크포인트 서명이 AUDIT 키와 맞지 않는다"
		default:
			h, ok := hashes[cp.Seq]
			switch {
			case !ok:
				r.OK, r.Reason = false, fmt.Sprintf("체인에 seq %d 가 없다(체크포인트 이후 구간 삭제)", cp.Seq)
			case h != cp.HeadHash:
				r.OK, r.Reason = false, fmt.Sprintf("seq %d 의 해시가 체크포인트와 다르다(체크포인트 이전 구간 재작성)", cp.Seq)
			}
		}
		out = append(out, r)
	}
	return out
}

// LoadCheckpoints 는 저장된 체크포인트 목록이다(id 순서).
func LoadCheckpoints(ctx context.Context, db *sql.DB) ([]Checkpoint, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, chain, seq, head_hash, key_id, signature, ts FROM audit_checkpoints ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Checkpoint{}
	for rows.Next() {
		var cp Checkpoint
		var head, sig []byte
		if err := rows.Scan(&cp.ID, &cp.Chain, &cp.Seq, &head, &cp.KeyID, &sig, &cp.TS); err != nil {
			return nil, err
		}
		copy(cp.HeadHash[:], head)
		cp.Signature, cp.TS = hex.EncodeToString(sig), cp.TS.UTC()
		out = append(out, cp)
	}
	return out, rows.Err()
}

// LastCheckpointSeq 는 chain 의 마지막 체크포인트 seq 와 해시다(없으면 ok=false).
func LastCheckpointSeq(ctx context.Context, db *sql.DB, chain string) (uint64, Hash, bool, error) {
	var seq uint64
	var head []byte
	err := db.QueryRowContext(ctx, `SELECT seq, head_hash FROM audit_checkpoints WHERE chain = ? ORDER BY id DESC LIMIT 1`, chain).Scan(&seq, &head)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, Hash{}, false, nil
	}
	if err != nil {
		return 0, Hash{}, false, err
	}
	var h Hash
	copy(h[:], head)
	return seq, h, true, nil
}
