package freeze

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestMessageBindsFieldsAndDomain(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := NewRequest(ScopeKey, "key-a", "도난 의심", "sec-01", priv, time.Now())
	base := r.Message()
	if !bytes.HasPrefix(base, []byte(DomainFreeze)) {
		t.Fatal("동결 메시지에 도메인이 없다")
	}
	for name, mut := range map[string]func(*Request){
		"scope": func(x *Request) { x.Scope = ScopeLedger }, "target": func(x *Request) { x.Target = "key-b" },
		"reason": func(x *Request) { x.Reason = "x" }, "admin": func(x *Request) { x.AdminID = "sec-02" },
		"time": func(x *Request) { x.RequestedAt = "2000-01-01T00:00:00Z" }, "id": func(x *Request) { x.FreezeID = "01ARZ3NDEKTSV4RRFFQ69G5FAV" },
	} {
		c := r
		mut(&c)
		if bytes.Equal(c.Message(), base) {
			t.Errorf("%s 를 바꿔도 서명 대상이 같다", name)
		}
	}
	rel := NewRelease(r.FreezeID, time.Now())
	if !bytes.HasPrefix(rel.ReleaseMessage(), []byte(DomainRelease)) || bytes.Equal(rel.ReleaseMessage(), base) {
		t.Fatal("해제 메시지가 동결 메시지와 구분되지 않는다")
	}
}

func TestFresh(t *testing.T) {
	now := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	cfg := Config{MaxSkew: 5 * time.Minute}
	if err := fresh(cfg, now.Add(-4*time.Minute).Format(TimeLayout), now); err != nil {
		t.Fatal(err)
	}
	for _, ts := range []string{now.Add(-6 * time.Minute).Format(TimeLayout), now.Add(6 * time.Minute).Format(TimeLayout), "2026-11-27T00:00:00.5Z", "bad"} {
		if err := fresh(cfg, ts, now); err == nil {
			t.Errorf("%s 가 허용됐다", ts)
		}
	}
}
