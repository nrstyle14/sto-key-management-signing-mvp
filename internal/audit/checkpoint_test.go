package audit

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// chain 은 메모리에서 n 개 레코드 체인을 만든다. tag 가 다르면 내용이 다른(그러나 유효한) 체인이 된다.
func chain(n int, tag string, from []Record) []Record {
	out := append([]Record(nil), from...)
	var prev Hash
	start := uint64(1)
	if len(out) > 0 {
		prev, start = out[len(out)-1].Hash, out[len(out)-1].Seq+1
	}
	ts, _ := time.Parse(TimeLayout, "2026-11-27T00:00:00.000000Z")
	for s := start; s < start+uint64(n); s++ {
		r := Record{Seq: s, TS: ts.Add(time.Duration(s) * time.Second), Actor: "it", Action: "TEST", Subject: fmt.Sprintf("%s-%d", tag, s), PayloadJSON: "{}", PrevHash: prev}
		r.Hash = ComputeHash(r)
		prev = r.Hash
		out = append(out, r)
	}
	return out
}

func checkpoint(t *testing.T, k *ecdsa.PrivateKey, chainName string, r Record) Checkpoint {
	t.Helper()
	d := CheckpointDigest(chainName, r.Seq, r.Hash)
	sig, err := crypto.Sign(d[:], k) // 시험용 키(실제는 HSM AUDIT 키)
	if err != nil {
		t.Fatal(err)
	}
	return Checkpoint{Chain: chainName, Seq: r.Seq, HeadHash: r.Hash, KeyID: "key-audit", Signature: hex.EncodeToString(sig)}
}

func verifyAll(rs []Record, cps []Checkpoint, pub []byte) (Result, []CheckpointResult) {
	v := NewVerifier()
	for _, r := range rs {
		v.Add(r)
	}
	return v.Result(), VerifyCheckpoints(cps, v.Hashes, map[string][]byte{"key-audit": pub})
}

func TestCheckpointDetectsRewriteBetweenCheckpoints(t *testing.T) {
	k, _ := crypto.GenerateKey()
	pub := crypto.FromECDSAPub(&k.PublicKey)
	orig := chain(20, "orig", nil)
	cps := []Checkpoint{checkpoint(t, k, "signer", orig[9]), checkpoint(t, k, "signer", orig[19])}
	if res, cr := verifyAll(orig, cps, pub); !res.OK || !cr[0].OK || !cr[1].OK {
		t.Fatalf("원본: %+v %+v", res, cr)
	}
	// 두 체크포인트 사이(11~20)를 통째로 지우고 유효한 체인으로 다시 쓴다.
	rewritten := chain(10, "forged", orig[:10])
	res, cr := verifyAll(rewritten, cps, pub)
	if !res.OK {
		t.Fatalf("시험 전제: 재작성한 체인은 해시 체인만으로는 정상이어야 한다: %+v", res)
	}
	if !cr[0].OK || cr[1].OK {
		t.Fatalf("체크포인트 검증이 재작성을 잡지 못했다: %+v", cr)
	}
	// 체크포인트 이후 구간 삭제(체인이 체크포인트보다 짧다)
	if _, cr := verifyAll(orig[:15], cps, pub); cr[1].OK {
		t.Fatal("체크포인트 seq 이후 삭제를 잡지 못했다")
	}
}

func TestCheckpointSignatureChecks(t *testing.T) {
	k, _ := crypto.GenerateKey()
	other, _ := crypto.GenerateKey()
	pub := crypto.FromECDSAPub(&k.PublicKey)
	rs := chain(5, "x", nil)
	cp := checkpoint(t, other, "signer", rs[4]) // 다른 키로 서명
	if _, cr := verifyAll(rs, []Checkpoint{cp}, pub); cr[0].OK {
		t.Fatal("다른 키의 체크포인트 서명이 통과했다")
	}
	good := checkpoint(t, k, "signer", rs[4])
	swapped := good
	swapped.Chain = "api" // 체인 이름을 바꾸면 서명이 맞지 않는다
	if _, cr := verifyAll(rs, []Checkpoint{swapped}, pub); cr[0].OK {
		t.Fatal("체인 이름을 바꾼 체크포인트가 통과했다")
	}
	unknown := good
	unknown.KeyID = "nope"
	if _, cr := verifyAll(rs, []Checkpoint{unknown}, pub); cr[0].OK {
		t.Fatal("알 수 없는 키의 체크포인트가 통과했다")
	}
}
