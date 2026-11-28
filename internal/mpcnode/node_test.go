package mpcnode

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/mpcwire"
)

var ids = []string{"mpcd-1", "mpcd-2", "mpcd-3"}

type cluster struct {
	nodes map[string]*Node
	privs map[string]ed25519.PrivateKey
	keys  map[string][]byte
	dir   string
}

func newCluster(t *testing.T) *cluster {
	t.Helper()
	c := &cluster{nodes: map[string]*Node{}, privs: map[string]ed25519.PrivateKey{}, keys: map[string][]byte{}, dir: t.TempDir()}
	pubs := map[string]ed25519.PublicKey{}
	for _, id := range ids {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		pubs[id], c.privs[id] = pub, priv
		k := make([]byte, 32)
		_, _ = rand.Read(k)
		c.keys[id] = k
	}
	for _, id := range ids {
		c.nodes[id] = c.open(t, id, pubs)
	}
	return c
}

func (c *cluster) open(t *testing.T, id string, pubs map[string]ed25519.PublicKey) *Node {
	t.Helper()
	peers := map[string]ed25519.PublicKey{}
	for k, v := range pubs {
		if k != id {
			peers[k] = v
		}
	}
	st, err := NewStore(filepath.Join(c.dir, id), id, c.keys[id])
	if err != nil {
		t.Fatal(err)
	}
	return New(id, c.privs[id], peers, st)
}

// relay 는 조정자처럼 참여 노드의 outbox 를 받는 노드의 inbox 로 옮긴다. 모든 노드가 want 상태가 되면 끝난다.
func (c *cluster) relay(t *testing.T, h mpcwire.Header, want string) map[string]mpcwire.Status {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		done := 0
		out := map[string]mpcwire.Status{}
		for _, id := range h.Participants {
			ob, err := c.nodes[id].Outbox(h.SessionID)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range ob.Envelopes {
				if err := c.nodes[e.To].Deliver(e); err != nil {
					t.Fatalf("%s → %s: %v", e.From, e.To, err)
				}
			}
			st, _ := c.nodes[id].Status(h.SessionID)
			if st.State == mpcwire.StateFailed {
				t.Fatalf("%s 실패: %s", id, st.Error)
			}
			if st.State == want {
				done++
			}
			out[id] = st
		}
		if done == len(h.Participants) {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("세션 %s 시간 초과: %+v", h.SessionID, out)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func digestOf(s string) [32]byte { return crypto.Keccak256Hash([]byte(s)) }

func addrOf(t *testing.T, pubHex string) string {
	t.Helper()
	b, _ := hex.DecodeString(pubHex)
	p, err := crypto.UnmarshalPubkey(b)
	if err != nil {
		t.Fatal(err)
	}
	return crypto.PubkeyToAddress(*p).Hex()
}

// recovered 는 (r, s)를 low-s 로 맞추고 복구 식별자 0/1 중 맞는 주소를 찾는다.
func recovered(t *testing.T, d [32]byte, st mpcwire.Status) []string {
	t.Helper()
	r, _ := new(big.Int).SetString(st.R, 10)
	s, _ := new(big.Int).SetString(st.S, 10)
	n := crypto.S256().Params().N
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		s.Sub(n, s)
	}
	var out []string
	for v := byte(0); v < 2; v++ {
		sig := make([]byte, 65)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:64])
		sig[64] = v
		if p, err := crypto.SigToPub(d[:], sig); err == nil {
			out = append(out, crypto.PubkeyToAddress(*p).Hex())
		}
	}
	return out
}

func contains(list []string, x string) bool {
	for _, v := range list {
		if v == x {
			return true
		}
	}
	return false
}

func TestGenerateReloadSign(t *testing.T) {
	c := newCluster(t)
	h := mpcwire.Header{SessionID: "gen-1", Kind: mpcwire.KindGenerate, KeyID: "key-t-1", Participants: ids}
	for _, id := range ids {
		if err := c.nodes[id].Start(h); err != nil {
			t.Fatal(err)
		}
	}
	st := c.relay(t, h, mpcwire.StateStaged)
	pub := st["mpcd-1"].PublicKey
	for _, id := range ids {
		if st[id].PublicKey != pub {
			t.Fatalf("노드마다 공개키가 다르다: %+v", st)
		}
		if info, _ := c.nodes[id].KeyInfo("key-t-1"); info.Present {
			t.Fatal("확정 전인데 조각이 보인다")
		}
		if _, err := c.nodes[id].Commit("gen-1"); err != nil {
			t.Fatal(err)
		}
	}
	addr := addrOf(t, pub)

	// 같은 세션 ID 는 다시 쓸 수 없다
	if err := c.nodes["mpcd-1"].Start(h); err == nil || !strings.Contains(err.Error(), "이미 쓰였다") {
		t.Fatalf("세션 재사용: %v", err)
	}
	// 같은 키로 다시 생성할 수 없다
	h2 := h
	h2.SessionID = "gen-2"
	if err := c.nodes["mpcd-2"].Start(h2); err == nil {
		t.Fatal("확정된 키를 다시 생성했다")
	}

	// 노드를 새로 열어(파일에서 다시 읽어) 서명한다. 두 조합 모두 같은 주소로 복구된다.
	pubs := map[string]ed25519.PublicKey{}
	for id, p := range c.privs {
		pubs[id] = p.Public().(ed25519.PublicKey)
	}
	for _, id := range ids {
		c.nodes[id] = c.open(t, id, pubs)
	}
	for i, pair := range [][]string{{"mpcd-1", "mpcd-3"}, {"mpcd-2", "mpcd-3"}, {"mpcd-1", "mpcd-2"}} {
		d := digestOf("tx-" + pair[0] + pair[1])
		sh := mpcwire.Header{SessionID: "sign-" + string(rune('a'+i)), Kind: mpcwire.KindSign, KeyID: "key-t-1", Participants: pair, Digest: hex.EncodeToString(d[:])}
		for _, id := range pair {
			if err := c.nodes[id].Start(sh); err != nil {
				t.Fatal(err)
			}
		}
		out := c.relay(t, sh, mpcwire.StateDone)
		if out[pair[0]].R != out[pair[1]].R || out[pair[0]].S != out[pair[1]].S {
			t.Fatalf("두 노드의 서명이 다르다: %+v", out)
		}
		if !contains(recovered(t, d, out[pair[0]]), addr) {
			t.Fatalf("%v 서명이 주소 %s 로 복구되지 않는다", pair, addr)
		}
	}

	// 폐기: 조각 파일이 남지 않는다
	for _, id := range ids {
		if n, err := c.nodes[id].Destroy("key-t-1"); err != nil || n != 0 {
			t.Fatalf("폐기 %s: %d %v", id, n, err)
		}
		if info, _ := c.nodes[id].KeyInfo("key-t-1"); info.Present {
			t.Fatal("폐기 뒤 조각이 남았다")
		}
	}
}

// 봉투 위조: 중계자가 본문을 바꾸거나, 다른 노드인 척하거나, 다른 세션 머리로 옮기면 받는 노드가 거부한다.
func TestEnvelopeForgeryRejected(t *testing.T) {
	c := newCluster(t)
	h := mpcwire.Header{SessionID: "gen-x", Kind: mpcwire.KindGenerate, KeyID: "key-x", Participants: ids}
	for _, id := range ids {
		if err := c.nodes[id].Start(h); err != nil {
			t.Fatal(err)
		}
	}
	var e mpcwire.Envelope
	for i := 0; i < 200 && e.From == ""; i++ {
		ob, _ := c.nodes["mpcd-1"].Outbox("gen-x")
		if len(ob.Envelopes) > 0 {
			e = ob.Envelopes[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	if e.From == "" {
		t.Fatal("봉투가 나오지 않았다")
	}
	to := c.nodes[e.To]
	tampered := e
	tampered.Payload = append([]byte{}, e.Payload...)
	tampered.Payload[len(tampered.Payload)-1] ^= 1
	spoofed := e
	spoofed.From = "mpcd-3"
	if e.To == "mpcd-3" {
		spoofed.From = "mpcd-2"
	}
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	resigned := mpcwire.Seal(h, e.From, e.To, e.Seq, e.Payload, attacker)
	other := mpcwire.Header{SessionID: "gen-x", Kind: mpcwire.KindGenerate, KeyID: "key-other", Participants: ids}
	moved := mpcwire.Seal(other, e.From, e.To, e.Seq, e.Payload, c.privs[e.From])
	for name, bad := range map[string]mpcwire.Envelope{"본문 변경": tampered, "보낸 노드 위장": spoofed, "다른 키로 서명": resigned, "다른 세션 머리": moved} {
		if err := to.Deliver(bad); err == nil {
			t.Errorf("%s 봉투를 받아들였다", name)
		}
	}
	// 원래 봉투는 받는다
	if err := to.Deliver(e); err != nil {
		t.Fatalf("정상 봉투: %v", err)
	}
	for _, id := range ids {
		_ = c.nodes[id].Abort("gen-x")
	}
}

// 조각 파일은 암호화돼 있고, 다른 노드의 저장 키로는 열리지 않는다.
func TestStoreEncryptedAndBound(t *testing.T) {
	c := newCluster(t)
	h := mpcwire.Header{SessionID: "gen-s", Kind: mpcwire.KindGenerate, KeyID: "key-s", Participants: ids}
	for _, id := range ids {
		if err := c.nodes[id].Start(h); err != nil {
			t.Fatal(err)
		}
	}
	c.relay(t, h, mpcwire.StateStaged)
	for _, id := range ids {
		if _, err := c.nodes[id].Commit("gen-s"); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(c.dir, "mpcd-1", "key-s.share")
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("조각 파일 권한: %v %v", fi, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "Share") || strings.Contains(string(raw), "key-s") {
		t.Fatal("조각 파일이 평문이다")
	}
	// mpcd-2 의 저장 키로 mpcd-1 파일을 열면 실패한다
	other, _ := NewStore(filepath.Join(c.dir, "mpcd-1"), "mpcd-1", c.keys["mpcd-2"])
	if _, err := other.Load("key-s"); err == nil {
		t.Fatal("다른 노드의 저장 키로 조각을 열었다")
	}
	// 확정 전 결과는 실패 시 지워진다
	h2 := mpcwire.Header{SessionID: "gen-s2", Kind: mpcwire.KindGenerate, KeyID: "key-s2", Participants: ids}
	for _, id := range ids {
		_ = c.nodes[id].Start(h2)
	}
	c.relay(t, h2, mpcwire.StateStaged)
	for _, id := range ids {
		_ = c.nodes[id].Abort("gen-s2")
		if _, err := os.Stat(filepath.Join(c.dir, id, "key-s2.staged")); err == nil {
			t.Fatalf("%s 중단 뒤 확정 전 파일이 남았다", id)
		}
	}
}
