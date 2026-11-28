// Package mpc 는 Signer 의 MPC 구현(조정자)이다(설계서 6.4 MPC 서명기, D-25).
//
// 키 조각은 mpcd 노드 3개에 있고, 이 패키지는 세션을 열고 노드 사이 봉투를 중계한다. 봉투 본문은 해석하지 않으며
// alice 를 import 하지 않는다(봉투는 노드끼리 Ed25519 로 서명·검증한다). 서명 결과 (r, s)는 레지스트리 공개키로
// 검증한 뒤 돌려준다. 응답하지 않는 노드는 조각 수를 셀 때 0 이 아니라 오류다.
package mpc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/oklog/ulid/v2"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/mpcwire"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

// Node 는 mpcd 노드 하나의 주소다.
type Node struct {
	ID  string `yaml:"id"`
	URL string `yaml:"url"`
}

// Client 는 MPC 조정자다.
type Client struct {
	Nodes []Node
	HTTP  *http.Client
	// PublicKey 는 레지스트리에 등록된 키의 공개키다(서명 결과 검증용).
	PublicKey func(ctx context.Context, keyID string) (signer.PublicKey, error)
	// GenerateTimeout, SignTimeout 은 세션 전체 시간 상한이다(기본 3분, 30초).
	GenerateTimeout, SignTimeout time.Duration
}

var _ signer.Signer = (*Client)(nil)

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (c *Client) do(ctx context.Context, n Node, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(n.URL, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("mpc: %s %s: %w", n.ID, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e apiError
		_ = json.Unmarshal(raw, &e)
		return fmt.Errorf("mpc: %s %s: HTTP %d %s %s", n.ID, path, resp.StatusCode, e.Code, e.Message)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (c *Client) node(id string) (Node, bool) {
	for _, n := range c.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

func newSessionID() string { return strings.ToLower(ulid.Make().String()) }

// run 은 세션을 참여 노드에서 시작하고, 모두 want 상태가 될 때까지 봉투를 중계한다. 실패하면 모든 참여 노드에서 중단한다.
func (c *Client) run(ctx context.Context, h mpcwire.Header, want string) (map[string]mpcwire.Status, error) {
	var nodes []Node
	for _, id := range h.Participants {
		n, ok := c.node(id)
		if !ok {
			return nil, fmt.Errorf("mpc: 노드 %s 설정이 없다", id)
		}
		nodes = append(nodes, n)
	}
	abort := func() {
		actx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, n := range nodes {
			_ = c.do(actx, n, http.MethodPost, "/v1/sessions/"+h.SessionID+"/abort", nil, nil)
		}
	}
	for _, n := range nodes {
		if err := c.do(ctx, n, http.MethodPost, "/v1/sessions", mpcwire.StartRequest{Header: h}, nil); err != nil {
			abort()
			return nil, err
		}
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu     sync.Mutex
		states = map[string]string{}
		first  error
		wg     sync.WaitGroup
	)
	setErr := func(err error) {
		mu.Lock()
		if first == nil {
			first = err
		}
		mu.Unlock()
		cancel()
	}
	for _, n := range nodes {
		wg.Add(1)
		go func(n Node) {
			defer wg.Done()
			for rctx.Err() == nil {
				var ob mpcwire.Outbox
				if err := c.do(rctx, n, http.MethodGet, "/v1/sessions/"+h.SessionID+"/outbox?wait=2000", nil, &ob); err != nil {
					if rctx.Err() == nil {
						setErr(err)
					}
					return
				}
				byTo := map[string][]mpcwire.Envelope{}
				for _, e := range ob.Envelopes {
					if e.From != n.ID || !h.Has(e.To) {
						setErr(fmt.Errorf("mpc: %s 가 보낸 봉투의 주소(%s → %s)가 맞지 않는다", n.ID, e.From, e.To))
						return
					}
					byTo[e.To] = append(byTo[e.To], e)
				}
				for to, es := range byTo {
					tn, _ := c.node(to)
					if err := c.do(rctx, tn, http.MethodPost, "/v1/sessions/"+h.SessionID+"/inbox", map[string]any{"envelopes": es}, nil); err != nil {
						if rctx.Err() == nil {
							setErr(err)
						}
						return
					}
				}
				if ob.State == mpcwire.StateFailed {
					var st mpcwire.Status
					_ = c.do(rctx, n, http.MethodGet, "/v1/sessions/"+h.SessionID, nil, &st)
					setErr(fmt.Errorf("mpc: %s 세션 실패: %s", n.ID, st.Error))
					return
				}
				mu.Lock()
				states[n.ID] = ob.State
				all := len(states) == len(nodes)
				for _, s := range states {
					if s != want {
						all = false
					}
				}
				mu.Unlock()
				if all {
					cancel()
					return
				}
				if ob.State == want && len(ob.Envelopes) == 0 {
					// 이 노드는 끝났다. 다른 노드가 끝날 때까지 가끔 확인만 한다.
					select {
					case <-rctx.Done():
						return
					case <-time.After(50 * time.Millisecond):
					}
				}
			}
		}(n)
	}
	wg.Wait()
	mu.Lock()
	err := first
	mu.Unlock()
	if err == nil && ctx.Err() != nil {
		err = fmt.Errorf("mpc: 세션 %s 시간 초과: %w", h.SessionID, ctx.Err())
	}
	if err != nil {
		abort()
		return nil, err
	}
	out := map[string]mpcwire.Status{}
	for _, n := range nodes {
		var st mpcwire.Status
		if err := c.do(ctx, n, http.MethodGet, "/v1/sessions/"+h.SessionID, nil, &st); err != nil {
			abort()
			return nil, err
		}
		if st.State != want {
			abort()
			return nil, fmt.Errorf("mpc: %s 상태 %s(기대 %s)", n.ID, st.State, want)
		}
		out[n.ID] = st
	}
	return out, nil
}

func (c *Client) allIDs() []string {
	var ids []string
	for _, n := range c.Nodes {
		ids = append(ids, n.ID)
	}
	sort.Strings(ids)
	return ids
}

// Generate 는 세 노드 모두로 키를 만든다: DKG → 부분 공개키 확인 → refresh → 임시 저장 → 공개키가 모두 같으면 확정.
// 확정 도중 실패하면 세 노드의 조각을 지워 같은 키 ID 로 다시 시도할 수 있게 한다.
func (c *Client) Generate(ctx context.Context, spec signer.KeySpec) (signer.PublicKey, error) {
	if err := signer.CheckBackend(signer.BackendMPC, spec.Purpose); err != nil {
		return nil, err
	}
	if len(c.Nodes) != 3 {
		return nil, fmt.Errorf("mpc: 노드 3개가 필요하다(설정 %d개)", len(c.Nodes))
	}
	timeout := c.GenerateTimeout
	if timeout == 0 {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// 호출자(keyops)는 레지스트리에 없는 키 ID 로만 부른다. 앞선 시도가 확정 뒤 등록 전에 멈춰 노드에 남긴 조각은
	// 이 키 ID 로 다시 생성할 수 없게 만들므로 먼저 지운다(등록된 키의 조각은 여기까지 오지 않는다).
	left, err := c.ObjectCount(ctx, "", spec.KeyID)
	if err != nil {
		return nil, err
	}
	if left > 0 {
		if _, err := c.DestroyIn(ctx, "", spec.KeyID); err != nil {
			return nil, fmt.Errorf("mpc: 등록되지 않은 키 %s 의 남은 조각 정리: %w", spec.KeyID, err)
		}
	}
	h := mpcwire.Header{SessionID: newSessionID(), Kind: mpcwire.KindGenerate, KeyID: spec.KeyID, Participants: c.allIDs()}
	st, err := c.run(ctx, h, mpcwire.StateStaged)
	if err != nil {
		return nil, err
	}
	pub := ""
	for id, s := range st {
		if pub == "" {
			pub = s.PublicKey
		}
		if s.PublicKey != pub || pub == "" {
			c.abortAll(h)
			return nil, fmt.Errorf("mpc: 노드 %s 의 공개키가 다르다", id)
		}
	}
	for _, id := range h.Participants {
		n, _ := c.node(id)
		if err := c.do(ctx, n, http.MethodPost, "/v1/sessions/"+h.SessionID+"/commit", nil, nil); err != nil {
			c.abortAll(h)
			if _, derr := c.DestroyIn(context.Background(), "", spec.KeyID); derr != nil {
				err = errors.Join(err, derr)
			}
			return nil, err
		}
	}
	b, err := hex.DecodeString(pub)
	if err != nil || len(b) != 65 || b[0] != 4 {
		return nil, errors.New("mpc: 공개키 형식")
	}
	return signer.PublicKey(b), nil
}

func (c *Client) abortAll(h mpcwire.Header) {
	actx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, id := range h.Participants {
		n, _ := c.node(id)
		_ = c.do(actx, n, http.MethodPost, "/v1/sessions/"+h.SessionID+"/abort", nil, nil)
	}
}

// holders 는 응답하고, 키 조각을 가졌고, 공개키가 레지스트리와 같은 노드 ID 를 정렬해 돌려준다.
// 살아 있어도 조각을 잃은 노드는 고르지 않는다(나머지 두 노드로 서명할 수 있게).
func (c *Client) holders(ctx context.Context, keyID, pubHex string) []string {
	hctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var mu sync.Mutex
	var ok []string
	var wg sync.WaitGroup
	for _, n := range c.Nodes {
		wg.Add(1)
		go func(n Node) {
			defer wg.Done()
			var info mpcwire.KeyInfo
			if c.do(hctx, n, http.MethodGet, "/v1/keys/"+keyID, nil, &info) == nil && info.Present && info.PublicKey == pubHex {
				mu.Lock()
				ok = append(ok, n.ID)
				mu.Unlock()
			}
		}(n)
	}
	wg.Wait()
	sort.Strings(ok)
	return ok
}

// SignDigest 는 응답하는 노드 2개로 서명하고, 두 노드의 결과가 같고 레지스트리 공개키로 검증될 때만 돌려준다.
// low-s 정규화와 v 계산은 호출자(5.3 의 8단계)가 한다.
func (c *Client) SignDigest(ctx context.Context, keyID string, digest [32]byte) (*big.Int, *big.Int, error) {
	if c.PublicKey == nil {
		return nil, nil, errors.New("mpc: 공개키 조회기가 없다")
	}
	pub, err := c.PublicKey(ctx, keyID)
	if err != nil {
		return nil, nil, err
	}
	pk, err := crypto.UnmarshalPubkey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("mpc: 레지스트리 공개키: %w", err)
	}
	timeout := c.SignTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	up := c.holders(ctx, keyID, hex.EncodeToString(pub))
	if len(up) < 2 {
		return nil, nil, fmt.Errorf("mpc: 키 %s 조각을 가진 응답 노드가 %d개다(서명에 2개 필요)", keyID, len(up))
	}
	h := mpcwire.Header{SessionID: newSessionID(), Kind: mpcwire.KindSign, KeyID: keyID, Participants: up[:2], Digest: hex.EncodeToString(digest[:])}
	st, err := c.run(ctx, h, mpcwire.StateDone)
	if err != nil {
		return nil, nil, err
	}
	a, b := st[h.Participants[0]], st[h.Participants[1]]
	if a.R == "" || a.R != b.R || a.S != b.S {
		return nil, nil, errors.New("mpc: 두 노드의 서명 결과가 다르다")
	}
	r, ok1 := new(big.Int).SetString(a.R, 10)
	s, ok2 := new(big.Int).SetString(a.S, 10)
	if !ok1 || !ok2 {
		return nil, nil, errors.New("mpc: 서명 값 형식")
	}
	if !ecdsa.Verify(pk, digest[:], r, s) {
		return nil, nil, errors.New("mpc: 서명이 레지스트리 공개키로 검증되지 않는다")
	}
	return r, s, nil
}

// keyInfos 는 모든 노드의 조각 정보다. 한 노드라도 응답하지 않으면 오류다.
func (c *Client) keyInfos(ctx context.Context, keyID string) ([]mpcwire.KeyInfo, error) {
	var out []mpcwire.KeyInfo
	for _, n := range c.Nodes {
		var info mpcwire.KeyInfo
		if err := c.do(ctx, n, http.MethodGet, "/v1/keys/"+keyID, nil, &info); err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, nil
}

// ObjectCount 는 노드에 남은 조각 수다(폐기 증적). 응답하지 않는 노드가 있으면 오류다(0 으로 세지 않는다).
func (c *Client) ObjectCount(ctx context.Context, _ string, keyID string) (int, error) {
	infos, err := c.keyInfos(ctx, keyID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, i := range infos {
		if i.Present {
			n++
		}
	}
	return n, nil
}

// PublicKeyOf 는 조각을 가진 노드들이 말하는 공개키다. 조각이 2개 미만이거나 노드마다 다르면 오류다.
func (c *Client) PublicKeyOf(ctx context.Context, _ string, keyID string) (signer.PublicKey, error) {
	infos, err := c.keyInfos(ctx, keyID)
	if err != nil {
		return nil, err
	}
	pub, n := "", 0
	for _, i := range infos {
		if !i.Present {
			continue
		}
		if pub != "" && i.PublicKey != pub {
			return nil, fmt.Errorf("mpc: 노드마다 키 %s 공개키가 다르다", keyID)
		}
		pub = i.PublicKey
		n++
	}
	if n < 2 {
		return nil, fmt.Errorf("mpc: 키 %s 조각이 %d개다(2개 이상 필요)", keyID, n)
	}
	b, err := hex.DecodeString(pub)
	if err != nil {
		return nil, err
	}
	return signer.PublicKey(b), nil
}

// DestroyIn 은 세 노드 모두에서 조각을 지운다. 응답하지 않는 노드가 있으면 오류다.
// 남은 조각 수를 돌려준다(keyops 가 ObjectCount 로 다시 확인한다).
func (c *Client) DestroyIn(ctx context.Context, _ string, keyID string) (int, error) {
	total := 0
	var errs []error
	for _, n := range c.Nodes {
		var res struct {
			Remaining int `json:"remaining"`
		}
		if err := c.do(ctx, n, http.MethodDelete, "/v1/keys/"+keyID, nil, &res); err != nil {
			errs = append(errs, err)
			continue
		}
		total += res.Remaining
	}
	return total, errors.Join(errs...)
}

// Destroy 는 Signer 인터페이스용이다.
func (c *Client) Destroy(ctx context.Context, keyID string) error {
	_, err := c.DestroyIn(ctx, "", keyID)
	return err
}
