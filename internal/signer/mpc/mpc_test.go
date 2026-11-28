package mpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/mpcnode"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

// 시험용 노드 3개(평문 HTTP, 프로세스 안). 실제 mTLS 와 컨테이너 경로는 test/mpc_e2e_test.go 가 확인한다.
type cluster struct {
	nodes   map[string]*mpcnode.Node
	servers map[string]*httptest.Server
	client  *Client
	pubs    map[string]signer.PublicKey
}

func newCluster(t *testing.T) *cluster {
	t.Helper()
	ids := []string{"mpcd-1", "mpcd-2", "mpcd-3"}
	privs, pubs := map[string]ed25519.PrivateKey{}, map[string]ed25519.PublicKey{}
	for _, id := range ids {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		privs[id], pubs[id] = priv, pub
	}
	c := &cluster{nodes: map[string]*mpcnode.Node{}, servers: map[string]*httptest.Server{}, pubs: map[string]signer.PublicKey{}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var nodes []Node
	dir := t.TempDir()
	for _, id := range ids {
		peers := map[string]ed25519.PublicKey{}
		for k, v := range pubs {
			if k != id {
				peers[k] = v
			}
		}
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		st, err := mpcnode.NewStore(filepath.Join(dir, id), id, key)
		if err != nil {
			t.Fatal(err)
		}
		n := mpcnode.New(id, privs[id], peers, st)
		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
		mux.Handle("/v1/", mpcnode.Handler(n, log))
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		c.nodes[id], c.servers[id] = n, srv
		nodes = append(nodes, Node{ID: id, URL: srv.URL})
	}
	c.client = &Client{Nodes: nodes, HTTP: &http.Client{Timeout: 30 * time.Second},
		PublicKey: func(_ context.Context, keyID string) (signer.PublicKey, error) { return c.pubs[keyID], nil }}
	return c
}

func signAndCheck(t *testing.T, c *cluster, keyID string) error {
	t.Helper()
	digest := crypto.Keccak256Hash([]byte("tx " + keyID + time.Now().String()))
	r, s, err := c.client.SignDigest(context.Background(), keyID, digest)
	if err != nil {
		return err
	}
	// low-s 로 맞춰 주소 복구(호출자 5.3 의 8단계와 같은 처리)
	n := crypto.S256().Params().N
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		s = new(big.Int).Sub(n, s)
	}
	want := c.pubs[keyID]
	for v := byte(0); v < 2; v++ {
		sig := make([]byte, 65)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:64])
		sig[64] = v
		if p, err := crypto.SigToPub(digest[:], sig); err == nil && string(crypto.FromECDSAPub(p)) == string(want) {
			return nil
		}
	}
	t.Fatal("서명이 공개키로 복구되지 않는다")
	return nil
}

func TestCoordinatorGenerateSignAndFailures(t *testing.T) {
	c := newCluster(t)
	ctx := context.Background()
	spec := signer.KeySpec{KeyID: "key-c-1", Purpose: signer.PurposeTransfer, Backend: signer.BackendMPC}
	pub, err := c.client.Generate(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	c.pubs["key-c-1"] = pub
	if n, err := c.client.ObjectCount(ctx, "", "key-c-1"); err != nil || n != 3 {
		t.Fatalf("조각 수 %d %v", n, err)
	}
	if err := signAndCheck(t, c, "key-c-1"); err != nil {
		t.Fatal(err)
	}
	// 살아 있지만 조각을 잃은 노드(mpcd-1)는 빼고 나머지 둘로 서명한다
	if _, err := c.nodes["mpcd-1"].Destroy("key-c-1"); err != nil {
		t.Fatal(err)
	}
	if err := signAndCheck(t, c, "key-c-1"); err != nil {
		t.Fatalf("조각을 잃은 노드가 있을 때: %v", err)
	}
	// 조각을 가진 노드 하나(mpcd-3)마저 내려가면 서명하지 못한다. 조각 수 세기도 0 이 아니라 오류다.
	c.servers["mpcd-3"].Close()
	if err := signAndCheck(t, c, "key-c-1"); err == nil {
		t.Fatal("조각을 가진 응답 노드가 1개인데 서명됐다")
	}
	if _, err := c.client.ObjectCount(ctx, "", "key-c-1"); err == nil {
		t.Fatal("응답하지 않는 노드가 있는데 조각 수를 셌다")
	}
	if _, err := c.client.DestroyIn(ctx, "", "key-c-1"); err == nil {
		t.Fatal("응답하지 않는 노드가 있는데 폐기가 성공했다")
	}
}

// 키 생성이 노드 확정 뒤 레지스트리 등록 전에 멈춘 경우(조각만 남음), 같은 키 ID 로 다시 생성할 수 있다.
func TestCoordinatorRegenerateAfterOrphanedShares(t *testing.T) {
	c := newCluster(t)
	ctx := context.Background()
	spec := signer.KeySpec{KeyID: "key-o-1", Purpose: signer.PurposeIssue, Backend: signer.BackendMPC}
	first, err := c.client.Generate(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.client.Generate(ctx, spec) // 등록 실패 뒤 재시도 흉내
	if err != nil {
		t.Fatalf("남은 조각이 있는 키 ID 재생성: %v", err)
	}
	if string(first) == string(second) {
		t.Fatal("재생성한 키가 이전 키와 같다")
	}
	c.pubs["key-o-1"] = second
	if err := signAndCheck(t, c, "key-o-1"); err != nil {
		t.Fatal(err)
	}
	// 루트 키 용도는 MPC 로 만들 수 없다
	if _, err := c.client.Generate(ctx, signer.KeySpec{KeyID: "key-o-2", Purpose: signer.PurposeContractAdmin, Backend: signer.BackendMPC}); err == nil {
		t.Fatal("루트 키를 MPC 로 만들었다")
	}
}
