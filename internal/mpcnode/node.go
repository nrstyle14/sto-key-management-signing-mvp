// Package mpcnode 는 MPC 키 조각 노드다(설계서 6.4 MPC 서명기, D-25). getamis/alice 의 CGGMP 를 쓰는 유일한 패키지다.
//
// 노드는 조정자(서명 서버)가 연 세션에서 alice 프로토콜을 돌리고, 나가는 메시지를 Ed25519 로 서명한 봉투로
// outbox 에 쌓는다. 조정자가 그 봉투를 다른 노드의 inbox 로 옮긴다. 받은 봉투는 보낸 노드의 고정 공개키로 검증한다.
//
//	GENERATE: DKG → 부분 공개키 교환·확인 → refresh → 확정 전 저장(STAGED) → 조정자의 확정 요청 → COMMITTED
//	SIGN:     확정 조각을 읽어 2-of-3 서명 → DONE(r, s)
//
// 실패한 세션은 이어 가지 않는다(FAILED, 키 생성이면 확정 전 결과를 지운다). 같은 세션 ID 는 다시 쓸 수 없다.
package mpcnode

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp/dkg"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp/refresh"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp/sign"
	"github.com/getamis/alice/types"
	"google.golang.org/protobuf/proto"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/mpcwire"
)

// 봉투 본문의 첫 바이트(단계)
const (
	tagDKG     byte = 1
	tagPartial byte = 2
	tagRefresh byte = 3
	tagSign    byte = 4
)

const (
	threshold       = 2    // 2-of-3: 서명에 노드 2개(alice 의 threshold 는 필요한 참여자 수)
	paillierBits    = 2048 // refresh 의 Paillier 키 크기
	generateTimeout = 3 * time.Minute
	signTimeout     = 60 * time.Second
	keepFinished    = 10 * time.Minute
)

// Node 는 MPC 노드다.
type Node struct {
	ID       string
	Identity ed25519.PrivateKey
	Peers    map[string]ed25519.PublicKey // 다른 노드의 신원 공개키(고정)
	Store    *Store

	mu       sync.Mutex
	sessions map[string]*session
	used     map[string]bool
}

// New 는 노드를 만든다.
func New(id string, identity ed25519.PrivateKey, peers map[string]ed25519.PublicKey, store *Store) *Node {
	return &Node{ID: id, Identity: identity, Peers: peers, Store: store, sessions: map[string]*session{}, used: map[string]bool{}}
}

type session struct {
	n      *Node
	h      mpcwire.Header
	cancel context.CancelFunc

	mu       sync.Mutex
	state    string
	err      string
	outbox   []mpcwire.Envelope
	seq      uint64
	seen     map[string]bool // from/seq
	pending  map[byte][]pendingMsg
	stage    byte // 지금 받을 수 있는 단계
	pubKey   *pt.ECPoint
	r, s     *big.Int
	finished time.Time

	// 키 생성 중간 결과
	dkgRes   *dkg.Result
	partials map[string]*pt.ECPoint
	inst     interface {
		AddMessage(string, types.Message) error
		Stop()
	}
	events chan types.MainState
}

type pendingMsg struct {
	from    string
	payload []byte
}

// errSession 은 세션을 실패로 끝낸다.
func (s *session) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == mpcwire.StateFailed || s.state == mpcwire.StateDone || s.state == mpcwire.StateCommitted {
		return
	}
	s.state, s.err, s.finished = mpcwire.StateFailed, err.Error(), time.Now()
	if s.inst != nil {
		s.inst.Stop()
	}
	if s.h.Kind == mpcwire.KindGenerate {
		_ = s.n.Store.DiscardStaged(s.h.KeyID)
	}
	if s.cancel != nil {
		s.cancel()
	}
}

// pm 은 alice 의 PeerManager 다. 보내는 메시지를 단계 태그를 붙여 봉투로 만든다.
type pm struct {
	s     *session
	tag   byte
	peers []string
}

func (p *pm) NumPeers() uint32  { return uint32(len(p.peers)) }
func (p *pm) PeerIDs() []string { return p.peers }
func (p *pm) SelfID() string    { return p.s.n.ID }
func (p *pm) MustSend(id string, msg interface{}) {
	m, ok := msg.(proto.Message)
	if !ok {
		p.s.fail(fmt.Errorf("mpcnode: 보낼 메시지 형식 %T", msg))
		return
	}
	raw, err := proto.Marshal(m)
	if err != nil {
		p.s.fail(err)
		return
	}
	p.s.send(id, append([]byte{p.tag}, raw...))
}

func (s *session) send(to string, payload []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	s.outbox = append(s.outbox, mpcwire.Seal(s.h, s.n.ID, to, s.seq, payload, s.n.Identity))
}

type listener struct{ ch chan types.MainState }

func (l listener) OnStateChanged(_, n types.MainState) {
	if n == types.StateDone || n == types.StateFailed {
		select {
		case l.ch <- n:
		default:
		}
	}
}

func (s *session) others() []string {
	var out []string
	for _, p := range s.h.Participants {
		if p != s.n.ID {
			out = append(out, p)
		}
	}
	return out
}

// Start 는 세션을 연다. 같은 세션 ID 는 다시 쓸 수 없다.
func (n *Node) Start(h mpcwire.Header) error {
	if err := h.Validate(); err != nil {
		return err
	}
	if !h.Has(n.ID) {
		return fmt.Errorf("mpcnode: %s 는 세션 참여 노드가 아니다", n.ID)
	}
	for _, p := range h.Participants {
		if p != n.ID {
			if _, ok := n.Peers[p]; !ok {
				return fmt.Errorf("mpcnode: 노드 %s 의 신원 공개키가 없다", p)
			}
		}
	}
	n.mu.Lock()
	n.gc()
	if n.used[h.SessionID] {
		n.mu.Unlock()
		return fmt.Errorf("mpcnode: 세션 %s 는 이미 쓰였다", h.SessionID)
	}
	n.used[h.SessionID] = true
	timeout := signTimeout
	if h.Kind == mpcwire.KindGenerate {
		timeout = generateTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	s := &session{n: n, h: h, cancel: cancel, state: mpcwire.StateRunning, seen: map[string]bool{}, pending: map[byte][]pendingMsg{},
		partials: map[string]*pt.ECPoint{}, events: make(chan types.MainState, 1)}
	n.sessions[h.SessionID] = s
	n.mu.Unlock()

	var err error
	if h.Kind == mpcwire.KindGenerate {
		err = s.startGenerate()
	} else {
		err = s.startSign()
	}
	if err != nil {
		s.fail(err)
		return err
	}
	go s.run(ctx)
	return nil
}

// gc 는 끝난 지 오래된 세션을 지운다(n.mu 를 잡고 부른다).
func (n *Node) gc() {
	for id, s := range n.sessions {
		s.mu.Lock()
		old := !s.finished.IsZero() && time.Since(s.finished) > keepFinished
		s.mu.Unlock()
		if old {
			delete(n.sessions, id)
		}
	}
}

func (n *Node) session(id string) (*session, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	s, ok := n.sessions[id]
	if !ok {
		return nil, fmt.Errorf("mpcnode: 세션 %s 가 없다", id)
	}
	return s, nil
}

// Deliver 는 조정자가 옮겨 온 봉투를 받는다.
func (n *Node) Deliver(e mpcwire.Envelope) error {
	s, err := n.session(e.SessionID)
	if err != nil {
		return err
	}
	if err := mpcwire.Open(s.h, n.ID, e, n.Peers); err != nil {
		return err
	}
	if len(e.Payload) < 1 {
		return errors.New("mpcnode: 빈 본문")
	}
	key := fmt.Sprintf("%s/%d", e.From, e.Seq)
	s.mu.Lock()
	if s.seen[key] {
		s.mu.Unlock()
		return nil // 같은 봉투 재전송은 무시
	}
	s.seen[key] = true
	if s.state != mpcwire.StateRunning {
		s.mu.Unlock()
		return nil
	}
	tag := e.Payload[0]
	if tag != s.stage {
		// 다음 단계 메시지가 먼저 왔다: 단계가 바뀔 때 처리한다
		s.pending[tag] = append(s.pending[tag], pendingMsg{from: e.From, payload: e.Payload[1:]})
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	return s.handle(tag, e.From, e.Payload[1:])
}

func (s *session) handle(tag byte, from string, payload []byte) error {
	if tag == tagPartial {
		return s.addPartial(from, payload)
	}
	var m proto.Message
	switch tag {
	case tagDKG:
		m = &dkg.Message{}
	case tagRefresh:
		m = &refresh.Message{}
	case tagSign:
		m = &sign.Message{}
	default:
		return fmt.Errorf("mpcnode: 알 수 없는 단계 %d", tag)
	}
	if err := proto.Unmarshal(payload, m); err != nil {
		return fmt.Errorf("mpcnode: 메시지 해석: %w", err)
	}
	msg, ok := m.(types.Message)
	if !ok {
		return errors.New("mpcnode: 메시지 형식")
	}
	// alice 메시지 안의 ID 는 원래 작성 노드다. alice 의 echo 브로드캐스트는 다른 노드의 메시지를 되돌려 보내므로
	// 봉투의 보낸 노드(서명으로 확인한 중계 노드)와 다를 수 있다. echo 일관성 검사는 alice 가 한다.
	// 다만 작성 노드는 세션 참여 노드여야 한다.
	if !s.h.Has(msg.GetId()) {
		return fmt.Errorf("mpcnode: 참여 노드가 아닌 %q 의 메시지", msg.GetId())
	}
	s.mu.Lock()
	inst := s.inst
	s.mu.Unlock()
	if inst == nil {
		return errors.New("mpcnode: 진행 중인 프로토콜이 없다")
	}
	return inst.AddMessage(from, msg)
}

// setStage 는 단계를 바꾸고 미리 온 메시지를 처리한다.
func (s *session) setStage(tag byte) {
	s.mu.Lock()
	s.stage = tag
	queued := s.pending[tag]
	delete(s.pending, tag)
	s.mu.Unlock()
	for _, q := range queued {
		if err := s.handle(tag, q.from, q.payload); err != nil {
			s.fail(err)
			return
		}
	}
}

func (s *session) startGenerate() error {
	// 앞선 시도가 남긴 확정 전 결과는 지우고 처음부터 한다. 확정 조각이 있으면 거부한다.
	if _, err := s.n.Store.Load(s.h.KeyID); err == nil {
		return fmt.Errorf("mpcnode: 키 %s 조각이 이미 있다", s.h.KeyID)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	if err := s.n.Store.DiscardStaged(s.h.KeyID); err != nil {
		return err
	}
	d, err := dkg.NewDKG(elliptic.Secp256k1(), &pm{s: s, tag: tagDKG, peers: s.others()}, []byte(s.h.SessionID+"/"+s.h.KeyID), threshold, 0, listener{s.events})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.inst = d
	s.mu.Unlock()
	s.setStage(tagDKG)
	d.Start()
	return nil
}

func (s *session) startSign() error {
	sh, err := s.n.Store.Load(s.h.KeyID)
	if err != nil {
		return err
	}
	digest, _ := hex.DecodeString(s.h.Digest)
	bks := map[string]*birkhoffinterpolation.BkParameter{}
	for _, p := range s.h.Participants {
		bk, ok := sh.Bks[p]
		if !ok {
			return fmt.Errorf("mpcnode: 노드 %s 의 Birkhoff 매개변수가 없다", p)
		}
		bks[p] = bk
	}
	ssid := sessionSSID(s.h, sh.Rid)
	sg, err := sign.NewSign(threshold, ssid, sh.Share, sh.PublicKey, sh.Partial, sh.Paillier, sh.Ped, bks, digest,
		&pm{s: s, tag: tagSign, peers: s.others()}, listener{s.events})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.inst, s.pubKey = sg, sh.PublicKey
	s.mu.Unlock()
	s.setStage(tagSign)
	sg.Start()
	return nil
}

// run 은 단계 전이를 처리한다(alice 콜백 밖에서).
func (s *session) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			s.fail(errors.New("mpcnode: 세션 시간 초과"))
			return
		case st := <-s.events:
			if st != types.StateDone {
				s.fail(errors.New("mpcnode: 프로토콜 실패"))
				return
			}
			done, err := s.next()
			if err != nil {
				s.fail(err)
				return
			}
			if done {
				return
			}
		}
	}
}

// next 는 한 프로토콜이 끝났을 때 다음 단계로 간다. 세션이 끝났으면 true.
func (s *session) next() (bool, error) {
	s.mu.Lock()
	inst, stage := s.inst, s.stage
	s.mu.Unlock()
	switch v := inst.(type) {
	case *dkg.DKG:
		res, err := v.GetResult()
		if err != nil {
			return false, err
		}
		v.Stop()
		own := pt.ScalarBaseMult(elliptic.Secp256k1(), res.Share)
		s.mu.Lock()
		s.dkgRes, s.pubKey, s.inst = res, res.PublicKey, nil
		s.partials[s.n.ID] = own
		s.mu.Unlock()
		s.setStage(tagPartial)
		raw := own.ToPubKey()
		pub := append([]byte{4}, append(pad32(raw.X), pad32(raw.Y)...)...)
		for _, p := range s.others() {
			s.send(p, append([]byte{tagPartial}, pub...))
		}
		return false, s.maybeRefresh()
	case *refresh.Refresh:
		res, err := v.GetResult()
		if err != nil {
			return false, err
		}
		v.Stop()
		s.mu.Lock()
		d := s.dkgRes
		s.mu.Unlock()
		sh := &Share{KeyID: s.h.KeyID, PublicKey: d.PublicKey, Share: res.Share, Paillier: res.PaillierKey, Partial: res.PartialPubKey,
			Ped: res.PedParameter, Bks: d.Bks, Rid: d.Rid}
		if err := s.n.Store.Stage(sh); err != nil {
			return false, err
		}
		s.mu.Lock()
		s.state, s.inst = mpcwire.StateStaged, nil
		s.mu.Unlock()
		// 확정 요청(Commit)이 세션 문맥을 끝낸다. 그 전에 시간이 다 되면 fail 이 확정 전 결과를 지운다.
		return false, nil
	case *sign.Sign:
		res, err := v.GetResult()
		if err != nil {
			return false, err
		}
		v.Stop()
		s.mu.Lock()
		s.r, s.s, s.state, s.finished, s.inst = res.R, res.S, mpcwire.StateDone, time.Now(), nil
		s.mu.Unlock()
		s.cancel()
		return true, nil
	}
	return false, fmt.Errorf("mpcnode: 단계 %d 에서 알 수 없는 결과", stage)
}

// sessionSSID 는 세션의 SSID 다. 참여 노드가 모두 같은 값을 써야 한다(실측: alice 예제처럼 노드마다 자기 Bk 를
// 넣으면 refresh 2라운드 증명 검증이 실패한다). 세션 ID·키 ID·DKG Rid 에 묶는다.
func sessionSSID(h mpcwire.Header, rid []byte) []byte {
	return cggmp.ComputeSSID([]byte(h.SessionID), []byte(h.KeyID), rid)
}

func pad32(v *big.Int) []byte {
	b := make([]byte, 32)
	v.FillBytes(b)
	return b
}

// addPartial 은 다른 노드의 부분 공개키(share·G)를 받는다.
func (s *session) addPartial(from string, payload []byte) error {
	if len(payload) != 65 || payload[0] != 4 {
		return errors.New("mpcnode: 부분 공개키 형식")
	}
	p, err := pt.NewECPoint(elliptic.Secp256k1(), new(big.Int).SetBytes(payload[1:33]), new(big.Int).SetBytes(payload[33:]))
	if err != nil {
		return fmt.Errorf("mpcnode: 부분 공개키: %w", err)
	}
	s.mu.Lock()
	if _, dup := s.partials[from]; dup {
		s.mu.Unlock()
		return nil
	}
	s.partials[from] = p
	s.mu.Unlock()
	if err := s.maybeRefresh(); err != nil {
		s.fail(err)
		return err
	}
	return nil
}

// maybeRefresh 는 세 노드의 부분 공개키가 모이면 모든 2노드 조합의 결합이 DKG 공개키와 같은지 확인하고 refresh 를 시작한다.
func (s *session) maybeRefresh() error {
	s.mu.Lock()
	if s.dkgRes == nil || len(s.partials) < len(s.h.Participants) || s.inst != nil || s.state != mpcwire.StateRunning {
		s.mu.Unlock()
		return nil
	}
	d := s.dkgRes
	partials := map[string]*pt.ECPoint{}
	for k, v := range s.partials {
		partials[k] = v
	}
	s.mu.Unlock()
	ids := s.h.Participants
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			bks := birkhoffinterpolation.BkParameters{d.Bks[ids[i]], d.Bks[ids[j]]}
			if err := bks.ValidatePublicKey([]*pt.ECPoint{partials[ids[i]], partials[ids[j]]}, threshold, d.PublicKey); err != nil {
				return fmt.Errorf("mpcnode: 부분 공개키 %s·%s 결합이 공개키와 다르다: %w", ids[i], ids[j], err)
			}
		}
	}
	ssid := sessionSSID(s.h, d.Rid)
	r, err := refresh.NewRefresh(d.Share, d.PublicKey, &pm{s: s, tag: tagRefresh, peers: s.others()}, threshold, partials, d.Bks, paillierBits, ssid, listener{s.events})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.inst = r
	s.mu.Unlock()
	s.setStage(tagRefresh)
	r.Start()
	return nil
}

// Outbox 는 보낼 봉투를 꺼낸다(가져가면 비워진다).
func (n *Node) Outbox(id string) (mpcwire.Outbox, error) {
	s, err := n.session(id)
	if err != nil {
		return mpcwire.Outbox{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := mpcwire.Outbox{Envelopes: s.outbox, State: s.state}
	s.outbox = nil
	if out.Envelopes == nil {
		out.Envelopes = []mpcwire.Envelope{}
	}
	return out, nil
}

// Status 는 세션 상태다.
func (n *Node) Status(id string) (mpcwire.Status, error) {
	s, err := n.session(id)
	if err != nil {
		return mpcwire.Status{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := mpcwire.Status{SessionID: id, State: s.state, Error: s.err}
	if s.pubKey != nil && (s.state == mpcwire.StateStaged || s.state == mpcwire.StateCommitted) {
		st.PublicKey = encodePub(s.pubKey)
	}
	if s.state == mpcwire.StateDone && s.r != nil {
		st.R, st.S = s.r.String(), s.s.String()
	}
	return st, nil
}

func encodePub(p *pt.ECPoint) string {
	k := p.ToPubKey()
	return hex.EncodeToString(append([]byte{4}, append(pad32(k.X), pad32(k.Y)...)...))
}

// Commit 은 키 생성 세션의 결과를 확정한다(조정자가 세 노드의 공개키가 같은지 확인한 뒤).
func (n *Node) Commit(id string) (mpcwire.Status, error) {
	s, err := n.session(id)
	if err != nil {
		return mpcwire.Status{}, err
	}
	s.mu.Lock()
	if s.h.Kind != mpcwire.KindGenerate || s.state != mpcwire.StateStaged {
		st := s.state
		s.mu.Unlock()
		return mpcwire.Status{}, fmt.Errorf("mpcnode: 세션 %s 는 확정할 수 없는 상태 %s", id, st)
	}
	if err := n.Store.Commit(s.h.KeyID); err != nil {
		s.mu.Unlock()
		return mpcwire.Status{}, err
	}
	s.state, s.finished = mpcwire.StateCommitted, time.Now()
	s.mu.Unlock()
	s.cancel()
	return n.Status(id)
}

// Abort 는 세션을 실패로 끝낸다(조정자가 다른 노드의 실패를 알았을 때).
func (n *Node) Abort(id string) error {
	s, err := n.session(id)
	if err != nil {
		return err
	}
	s.fail(errors.New("mpcnode: 조정자가 세션을 중단했다"))
	return nil
}

// KeyInfo 는 조각 보유 여부와 공개키다.
func (n *Node) KeyInfo(keyID string) (mpcwire.KeyInfo, error) {
	sh, err := n.Store.Load(keyID)
	if errors.Is(err, ErrNotFound) {
		return mpcwire.KeyInfo{KeyID: keyID, Node: n.ID}, nil
	}
	if err != nil {
		return mpcwire.KeyInfo{}, err
	}
	return mpcwire.KeyInfo{KeyID: keyID, Node: n.ID, Present: true, PublicKey: encodePub(sh.PublicKey)}, nil
}

// Destroy 는 조각을 지우고 남은 파일 수를 돌려준다.
func (n *Node) Destroy(keyID string) (int, error) { return n.Store.Destroy(keyID) }
