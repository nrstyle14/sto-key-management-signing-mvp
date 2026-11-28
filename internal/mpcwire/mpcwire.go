// Package mpcwire 는 MPC 노드(mpcd)와 조정자(서명 서버) 사이의 API 형식과 봉투 서명이다(설계서 6.4, D-25).
//
// 노드끼리는 직접 통신하지 않고 조정자가 봉투를 중계한다. 봉투는 보낸 노드의 Ed25519 신원 키로 서명되고,
// 서명 대상은 도메인 "sto-mpc-v1" ‖ 세션 머리 해시 ‖ 보낸 노드 ‖ 받는 노드 ‖ 순번 ‖ SHA-256(본문)이다.
// 세션 머리(세션 ID, 종류, 키 ID, 참여 노드, 서명 다이제스트)를 묶으므로 다른 세션·다른 다이제스트로 옮겨 쓸 수 없고,
// 조정자는 본문을 고치거나 다른 노드인 척할 수 없다. 이 패키지는 alice 를 import 하지 않는다(서명 서버도 쓰므로).
package mpcwire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

// 도메인과 세션 종류
const (
	Domain = "sto-mpc-v1"

	KindGenerate = "GENERATE" // DKG → 부분 공개키 확인 → refresh, 세 노드 모두
	KindSign     = "SIGN"     // 2-of-3 서명
)

// 세션 상태
const (
	StateRunning   = "RUNNING"
	StateStaged    = "STAGED" // 키 생성: 결과를 임시 파일에 썼다(확정 대기)
	StateDone      = "DONE"
	StateFailed    = "FAILED"
	StateCommitted = "COMMITTED" // 키 생성: 확정됨
)

var (
	idRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	nodeRe = regexp.MustCompile(`^mpcd-[1-9]$`)
)

// Header 는 세션 머리다. 모든 봉투가 이 머리의 해시에 묶인다.
type Header struct {
	SessionID    string   `json:"session_id"` // 소문자 ULID 등 세션마다 새 값
	Kind         string   `json:"kind"`
	KeyID        string   `json:"key_id"`
	Participants []string `json:"participants"`     // 정렬된 노드 ID
	Digest       string   `json:"digest,omitempty"` // SIGN: 16진수 32바이트
}

// Validate 는 머리 형식을 확인한다.
func (h Header) Validate() error {
	if !idRe.MatchString(h.SessionID) || !idRe.MatchString(h.KeyID) {
		return errors.New("mpcwire: session_id, key_id 형식")
	}
	if !sort.StringsAreSorted(h.Participants) {
		return errors.New("mpcwire: participants 는 정렬돼야 한다")
	}
	seen := map[string]bool{}
	for _, p := range h.Participants {
		if !nodeRe.MatchString(p) || seen[p] {
			return fmt.Errorf("mpcwire: 참여 노드 %q 형식 또는 중복", p)
		}
		seen[p] = true
	}
	switch h.Kind {
	case KindGenerate:
		if len(h.Participants) != 3 || h.Digest != "" {
			return errors.New("mpcwire: 키 생성은 노드 3개, 다이제스트 없음")
		}
	case KindSign:
		if len(h.Participants) != 2 {
			return errors.New("mpcwire: 서명은 노드 2개")
		}
		if d, err := hex.DecodeString(h.Digest); err != nil || len(d) != 32 {
			return errors.New("mpcwire: 서명 다이제스트는 16진수 32바이트")
		}
	default:
		return fmt.Errorf("mpcwire: 알 수 없는 세션 종류 %q", h.Kind)
	}
	return nil
}

// Has 는 노드가 참여자인지다.
func (h Header) Has(node string) bool {
	for _, p := range h.Participants {
		if p == node {
			return true
		}
	}
	return false
}

func field(buf []byte, b []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	return append(append(buf, n[:]...), b...)
}

// Hash 는 세션 머리 해시다(필드마다 4바이트 길이 접두).
func (h Header) Hash() [32]byte {
	var buf []byte
	buf = field(buf, []byte(Domain+"/header"))
	buf = field(buf, []byte(h.SessionID))
	buf = field(buf, []byte(h.Kind))
	buf = field(buf, []byte(h.KeyID))
	for _, p := range h.Participants {
		buf = field(buf, []byte(p))
	}
	buf = field(buf, []byte(h.Digest))
	return sha256.Sum256(buf)
}

// Envelope 는 노드 사이 메시지 하나다. Payload 는 alice 프로토콜 메시지(protobuf) 또는 부분 공개키다.
type Envelope struct {
	SessionID string `json:"session_id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Seq       uint64 `json:"seq"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// SigningBytes 는 봉투의 서명 대상이다.
func SigningBytes(h Header, from, to string, seq uint64, payload []byte) []byte {
	hh := h.Hash()
	ph := sha256.Sum256(payload)
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	var buf []byte
	buf = field(buf, []byte(Domain))
	buf = field(buf, hh[:])
	buf = field(buf, []byte(from))
	buf = field(buf, []byte(to))
	buf = field(buf, s[:])
	buf = field(buf, ph[:])
	return buf
}

// Seal 은 봉투를 만들어 서명한다.
func Seal(h Header, from, to string, seq uint64, payload []byte, priv ed25519.PrivateKey) Envelope {
	return Envelope{SessionID: h.SessionID, From: from, To: to, Seq: seq, Payload: payload,
		Signature: ed25519.Sign(priv, SigningBytes(h, from, to, seq, payload))}
}

// Open 은 받은 봉투를 검증한다: 자기 세션·자기에게 온 것, 참여 노드가 보낸 것, 서명이 보낸 노드의 고정 공개키와 맞는 것.
func Open(h Header, self string, e Envelope, peers map[string]ed25519.PublicKey) error {
	if e.SessionID != h.SessionID || e.To != self {
		return errors.New("mpcwire: 다른 세션 또는 다른 노드의 봉투")
	}
	if e.From == self || !h.Has(e.From) {
		return fmt.Errorf("mpcwire: 참여 노드가 아닌 %q 의 봉투", e.From)
	}
	pub, ok := peers[e.From]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("mpcwire: %q 의 신원 공개키가 없다", e.From)
	}
	if !ed25519.Verify(pub, SigningBytes(h, e.From, e.To, e.Seq, e.Payload), e.Signature) {
		return fmt.Errorf("mpcwire: %q 의 봉투 서명이 맞지 않는다", e.From)
	}
	return nil
}

// StartRequest 는 세션 시작 요청이다(POST /v1/sessions, 조정자 → 노드).
type StartRequest struct {
	Header Header `json:"header"`
}

// Status 는 세션 상태다(GET /v1/sessions/{id}).
type Status struct {
	SessionID string `json:"session_id"`
	State     string `json:"state"`
	Error     string `json:"error,omitempty"`
	PublicKey string `json:"public_key,omitempty"` // 키 생성: 0x04‖X‖Y 16진수
	R         string `json:"r,omitempty"`          // 서명: 10진수
	S         string `json:"s,omitempty"`
}

// Outbox 는 노드가 보낼 봉투들이다(GET /v1/sessions/{id}/outbox, 가져가면 비워진다).
type Outbox struct {
	Envelopes []Envelope `json:"envelopes"`
	State     string     `json:"state"`
}

// KeyInfo 는 노드의 조각 보유 정보다(GET /v1/keys/{id}). Present 가 false 면 PublicKey 는 비어 있다.
type KeyInfo struct {
	KeyID     string `json:"key_id"`
	Node      string `json:"node"`
	Present   bool   `json:"present"`
	PublicKey string `json:"public_key,omitempty"`
}
