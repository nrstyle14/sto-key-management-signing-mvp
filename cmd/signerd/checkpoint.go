package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/hsm"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
	signerhsm "github.com/da-infra/sto-key-management-signing-mvp/internal/signer/hsm"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

// apiHead 는 업무 서버가 알려 온 api 감사 체인의 머리다. 서명 서버는 api 스키마를 읽지 못하므로,
// 체크포인트는 "업무 서버가 이 시점에 주장한 머리"를 AUDIT 키로 증명한다(설계서 8절).
type apiHead struct {
	mu   sync.Mutex
	seq  uint64
	hash audit.Hash
	set  bool
}

// checkpointer 는 체크포인트를 만든다. 실행 중인 signerd 안에서만 돈다(토큰 볼륨을 다른 프로세스와 함께 쓰지 않는다).
type checkpointer struct {
	a    *app
	mu   sync.Mutex
	file string
}

func (a *app) newCheckpointer() *checkpointer {
	return &checkpointer{a: a, file: a.cfg.Audit.CheckpointFile}
}

func (c *checkpointer) signer() *signerhsm.Signer {
	toks := make([]*hsm.Token, 0, len(c.a.tokens))
	for _, t := range c.a.tokens {
		toks = append(toks, t)
	}
	return signerhsm.New(toks, keyreg.TokenLabelOf(c.a.db))
}

// once 는 두 체인(signer, api)의 머리가 마지막 체크포인트 이후 바뀌었으면 AUDIT 키로 서명해 기록한다.
func (c *checkpointer) once(ctx context.Context) ([]audit.Checkpoint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key, err := keyreg.Lookup(ctx, c.a.db, c.a.cfg.Audit.KeyLedger, c.a.cfg.Audit.KeyInstitution, signer.PurposeAudit)
	if err != nil {
		return nil, fmt.Errorf("AUDIT 키 조회: %w", err)
	}
	heads := map[string][2]any{}
	seq, h, err := audit.HeadOf(ctx, c.a.db)
	if err != nil {
		return nil, err
	}
	heads["signer"] = [2]any{seq, h}
	c.a.apiHead.mu.Lock()
	if c.a.apiHead.set {
		heads["api"] = [2]any{c.a.apiHead.seq, c.a.apiHead.hash}
	}
	c.a.apiHead.mu.Unlock()

	var made []audit.Checkpoint
	for _, chain := range []string{"signer", "api"} {
		v, ok := heads[chain]
		if !ok {
			continue
		}
		seq, head := v[0].(uint64), v[1].(audit.Hash)
		if seq == 0 {
			continue
		}
		lastSeq, lastHash, has, err := audit.LastCheckpointSeq(ctx, c.a.db, chain)
		if err != nil {
			return made, err
		}
		if has && lastSeq == seq && lastHash == head {
			continue // 바뀐 것이 없다
		}
		d := audit.CheckpointDigest(chain, seq, head)
		r, s, err := c.signer().SignDigest(ctx, key.KeyID, d)
		if err != nil {
			return made, fmt.Errorf("체크포인트 서명: %w", err)
		}
		sig, err := signer.CompleteEVM(d, r, s, key.PublicKey)
		if err != nil {
			return made, err
		}
		cp := audit.Checkpoint{Chain: chain, Seq: seq, HeadHash: head, KeyID: key.KeyID, Signature: hex.EncodeToString(sig[:]), TS: time.Now().UTC()}
		res, err := c.a.db.ExecContext(ctx, `INSERT INTO audit_checkpoints (chain, seq, head_hash, key_id, signature, ts) VALUES (?, ?, ?, ?, ?, ?)`,
			cp.Chain, cp.Seq, cp.HeadHash[:], cp.KeyID, sig[:], cp.TS)
		if err != nil {
			return made, fmt.Errorf("체크포인트 저장: %w", err)
		}
		id, _ := res.LastInsertId()
		cp.ID = uint64(id)
		if err := c.appendFile(cp); err != nil {
			return made, err
		}
		made = append(made, cp)
		c.a.log.Info("감사 체크포인트", "chain", chain, "seq", seq, "key_id", key.KeyID)
	}
	return made, nil
}

// appendFile 은 체크포인트를 별도 볼륨의 파일에도 한 줄씩 남긴다(DB 와 다른 위치, FR-4.3).
func (c *checkpointer) appendFile(cp audit.Checkpoint) error {
	if c.file == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.file), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(c.file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("체크포인트 파일: %w", err)
	}
	b, _ := json.Marshal(cp)
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (c *checkpointer) run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := c.once(ctx); err != nil {
				c.a.log.Error("감사 체크포인트 실패", "err", err)
			}
		}
	}
}

// POST /v1/audit/api-head: 업무 서버가 자기 감사 체인 머리를 알린다. 뒤로 가는 값은 거부한다.
func (a *app) postAPIHead(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Seq  uint64     `json:"seq"`
		Hash audit.Hash `json:"hash"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		transport.WriteError(w, http.StatusBadRequest, transport.CodeBadRequest, err.Error())
		return
	}
	a.apiHead.mu.Lock()
	defer a.apiHead.mu.Unlock()
	if a.apiHead.set && (in.Seq < a.apiHead.seq || (in.Seq == a.apiHead.seq && in.Hash != a.apiHead.hash)) {
		a.log.Error("api 감사 체인 머리가 뒤로 갔다", "prev_seq", a.apiHead.seq, "seq", in.Seq)
		transport.WriteError(w, http.StatusConflict, "AUDIT_HEAD_REGRESSION", "api 감사 체인 머리가 이전 값보다 뒤로 갔다")
		return
	}
	a.apiHead.seq, a.apiHead.hash, a.apiHead.set = in.Seq, in.Hash, true
	w.WriteHeader(http.StatusNoContent)
}

// POST /v1/audit/checkpoints: 지금 체크포인트를 만든다(운영자·시험용, 실행 중인 signerd 안에서).
func (a *app) postCheckpoint(w http.ResponseWriter, r *http.Request) {
	made, err := a.cp.once(r.Context())
	if err != nil {
		a.log.Error("감사 체크포인트 실패", "err", err)
		transport.WriteError(w, http.StatusServiceUnavailable, transport.CodeUnavailable, "체크포인트 실패")
		return
	}
	if made == nil {
		made = []audit.Checkpoint{}
	}
	transport.WriteJSON(w, http.StatusOK, map[string]any{"created": made})
}

// GET /v1/audit/checkpoints
func (a *app) listCheckpoints(w http.ResponseWriter, r *http.Request) {
	list, err := audit.LoadCheckpoints(r.Context(), a.db)
	if err != nil {
		transport.WriteError(w, http.StatusInternalServerError, transport.CodeInternal, "체크포인트 조회 실패")
		return
	}
	transport.WriteJSON(w, http.StatusOK, map[string]any{"checkpoints": list})
}
