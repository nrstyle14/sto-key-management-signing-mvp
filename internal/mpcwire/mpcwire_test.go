package mpcwire

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func header() Header {
	return Header{SessionID: "s-1", Kind: KindSign, KeyID: "key-1", Participants: []string{"mpcd-1", "mpcd-3"}, Digest: strings.Repeat("ab", 32)}
}

func TestHeaderValidate(t *testing.T) {
	if err := header().Validate(); err != nil {
		t.Fatal(err)
	}
	gen := Header{SessionID: "s-2", Kind: KindGenerate, KeyID: "key-1", Participants: []string{"mpcd-1", "mpcd-2", "mpcd-3"}}
	if err := gen.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Header){
		"정렬 안 됨":    func(h *Header) { h.Participants = []string{"mpcd-3", "mpcd-1"} },
		"중복 노드":     func(h *Header) { h.Participants = []string{"mpcd-1", "mpcd-1"} },
		"노드 이름":     func(h *Header) { h.Participants = []string{"mpcd-1", "node-x"} },
		"서명 노드 3개":  func(h *Header) { h.Participants = []string{"mpcd-1", "mpcd-2", "mpcd-3"} },
		"다이제스트 길이":  func(h *Header) { h.Digest = "abcd" },
		"알 수 없는 종류": func(h *Header) { h.Kind = "REFRESH" },
		"세션 ID 형식":  func(h *Header) { h.SessionID = "S 1" },
		"생성에 다이제스트": func(h *Header) { h.Kind, h.Participants = KindGenerate, []string{"mpcd-1", "mpcd-2", "mpcd-3"} },
	} {
		h := header()
		mut(&h)
		if err := h.Validate(); err == nil {
			t.Errorf("%s: 받아들였다", name)
		}
	}
}

// 봉투 서명은 세션 머리의 모든 필드와 보낸·받는 노드, 순번, 본문에 묶인다.
func TestSealOpenBinding(t *testing.T) {
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub3, _, _ := ed25519.GenerateKey(rand.Reader)
	peers := map[string]ed25519.PublicKey{"mpcd-1": pub1, "mpcd-3": pub3}
	h := header()
	e := Seal(h, "mpcd-1", "mpcd-3", 7, []byte("payload"), priv1)
	if err := Open(h, "mpcd-3", e, peers); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() (Header, string, Envelope){
		"다른 다이제스트": func() (Header, string, Envelope) { x := h; x.Digest = strings.Repeat("cd", 32); return x, "mpcd-3", e },
		"다른 키":     func() (Header, string, Envelope) { x := h; x.KeyID = "key-2"; return x, "mpcd-3", e },
		"다른 참여자": func() (Header, string, Envelope) {
			x := h
			x.Participants = []string{"mpcd-1", "mpcd-2"}
			return x, "mpcd-3", e
		},
		"다른 받는 노드": func() (Header, string, Envelope) { return h, "mpcd-1", e },
		"순번 변경":    func() (Header, string, Envelope) { x := e; x.Seq = 8; return h, "mpcd-3", x },
		"본문 변경":    func() (Header, string, Envelope) { x := e; x.Payload = []byte("payloaX"); return h, "mpcd-3", x },
		"보낸 노드 위장": func() (Header, string, Envelope) { x := e; x.From = "mpcd-3"; x.To = "mpcd-1"; return h, "mpcd-1", x },
		"참여자 아님":   func() (Header, string, Envelope) { x := e; x.From = "mpcd-2"; return h, "mpcd-3", x },
	}
	for name, c := range cases {
		hh, self, env := c()
		if err := Open(hh, self, env, peers); err == nil {
			t.Errorf("%s: 받아들였다", name)
		}
	}
}
