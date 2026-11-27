package audit

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// 테스트 벡터: 기대 해시는 Go 구현과 별개로 python3(struct.pack(">I"/">Q") + hashlib.sha256)로 계산했다.
func vector(t *testing.T) []Record {
	t.Helper()
	ts1, _ := time.Parse(TimeLayout, "2026-11-27T01:02:03.456789Z")
	ts2, _ := time.Parse(TimeLayout, "2026-11-27T01:02:04.000000Z")
	p, err := CanonicalPayload(map[string]any{"request_id": "r1", "key_id": "k1"})
	if err != nil {
		t.Fatal(err)
	}
	r1 := Record{Seq: 1, TS: ts1, Actor: "signerd", Action: "SIGN", Subject: "01JDQ8Z3V4N6P7R8S9T0W1X2Y3", PayloadJSON: p}
	r1.Hash = ComputeHash(r1)
	r2 := Record{Seq: 2, TS: ts2, Actor: "stoctl", Action: "FREEZE", Subject: "키:k1", PayloadJSON: "{}", PrevHash: r1.Hash}
	r2.Hash = ComputeHash(r2)
	return []Record{r1, r2}
}

func TestHashVector(t *testing.T) {
	rs := vector(t)
	if rs[0].PayloadJSON != `{"key_id":"k1","request_id":"r1"}` {
		t.Fatalf("payload 정규화: %s", rs[0].PayloadJSON)
	}
	want := []string{
		"be257cab47dcecae64d46f267696638590297b323c079e8c71a7e83abe71d4d2",
		"e91a1930181be2891c22b2c11249bd6dcb9eaebf25097bf3e934eaf56468cd48",
	}
	for i, r := range rs {
		if got := hex.EncodeToString(r.Hash[:]); got != want[i] {
			t.Fatalf("레코드 %d 해시 %s, 기대 %s", i+1, got, want[i])
		}
	}
	if res := Verify(rs); !res.OK || res.Count != 2 || res.HeadSeq != 2 {
		t.Fatalf("%+v", res)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	cases := map[string]func([]Record){
		"내용 변조":   func(rs []Record) { rs[0].Actor = "attacker" },
		"시각 변조":   func(rs []Record) { rs[0].TS = rs[0].TS.Add(time.Microsecond) },
		"payload": func(rs []Record) { rs[0].PayloadJSON = `{"key_id":"k2","request_id":"r1"}` },
		"해시 재계산":  func(rs []Record) { rs[0].Actor = "x"; rs[0].Hash = ComputeHash(rs[0]) }, // 다음 레코드의 prev_hash 가 어긋난다
	}
	for name, mut := range cases {
		rs := vector(t)
		mut(rs)
		res := Verify(rs)
		want := uint64(1)
		if name == "해시 재계산" {
			want = 2
		}
		if res.OK || res.FirstBadSeq != want {
			t.Errorf("%s: %+v (기대 첫 오류 seq %d)", name, res, want)
		}
	}
	rs := vector(t)
	if res := Verify(rs[1:]); res.OK || res.FirstBadSeq != 1 {
		t.Errorf("앞 레코드 삭제: %+v", res)
	}
}

func TestCanonicalPayloadAllowList(t *testing.T) {
	for _, k := range []string{"pin", "password", "private_key", "wrap_key", "PIN"} {
		if _, err := CanonicalPayload(map[string]any{k: "x"}); !errors.Is(err, ErrPayloadKey) {
			t.Errorf("키 %q 가 허용됐다", k)
		}
	}
	if _, err := CanonicalPayload(map[string]any{"reason": 1.5}); err == nil {
		t.Error("float 값이 허용됐다")
	}
	if _, err := CanonicalPayload(map[string]any{"reason": map[string]any{"pin": "1"}}); err == nil {
		t.Error("중첩 객체가 허용됐다")
	}
	p, err := CanonicalPayload(map[string]any{"reason": "<a&b>", "count": 3, "keys": []string{"a"}})
	if err != nil || p != `{"count":3,"keys":["a"],"reason":"<a&b>"}` {
		t.Fatalf("%s %v", p, err)
	}
}

func TestHashJSONRoundTrip(t *testing.T) {
	rs := vector(t)
	b, _ := rs[0].Hash.MarshalText()
	var h Hash
	if err := h.UnmarshalText(b); err != nil || h != rs[0].Hash {
		t.Fatal("해시 텍스트 왕복 실패")
	}
}
