package recon

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// 이벤트 재생: 발행·말소·대체를 주소별 수량으로 계산한다(주소 대소문자 무관). 수량 형식 오류는 오류다.
func TestApplyReplay(t *testing.T) {
	a := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	b := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	s := &snapshot{replay: map[string]*big.Int{}}
	steps := []struct{ name, payload string }{
		{"Issued", `{"account":"` + a.Hex() + `","amount":"1000"}`},
		{"Transferred", `{"agent":"0x01","amount":"300","from":"` + a.Hex() + `","to":"0x00000000000000000000000000000000000000BB"}`},
		{"Redeemed", `{"account":"` + b.Hex() + `","amount":"100"}`},
		{"Issued", `{"account":"` + b.Hex() + `","amount":"1000000000000000000000000000000"}`},
	}
	for _, st := range steps {
		if err := s.applyReplay(st.name, st.payload); err != nil {
			t.Fatalf("%s: %v", st.name, err)
		}
	}
	if s.replay[a.Hex()].String() != "700" || s.replay[b.Hex()].String() != "1000000000000000000000000000200" || len(s.replay) != 2 {
		t.Fatalf("재생 결과 %v", s.replay)
	}
	for _, bad := range []string{`{"account":"0x01","amount":"1.5"}`, `{"account":"0x01","amount":"-1"}`, `{"account":"0x01"}`, `not json`} {
		if err := s.applyReplay("Issued", bad); err == nil {
			t.Errorf("%s 를 받아들였다", bad)
		}
	}
}
