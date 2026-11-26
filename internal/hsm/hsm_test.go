package hsm

import (
	"bytes"
	"testing"
)

func TestParseECPoint(t *testing.T) {
	raw := append([]byte{0x04}, bytes.Repeat([]byte{0xAB}, 64)...)
	der := append([]byte{0x04, 0x41}, raw...)
	for name, in := range map[string][]byte{"DER": der, "raw": raw} {
		got, err := ParseECPoint(in)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("%s: got=%x err=%v", name, got, err)
		}
	}
	if _, err := ParseECPoint(raw[:33]); err == nil {
		t.Fatal("압축 점(33바이트)이 허용됐다")
	}
}
