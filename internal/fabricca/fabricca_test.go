package fabricca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"net/http"
	"strings"
	"testing"
)

// 토큰 서명은 항상 low-S 다(Fabric CA 는 high-S 를 거부한다).
func TestSoftwareTokenLowS(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	half := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	for i := 0; i < 200; i++ {
		req, _ := http.NewRequest("POST", "http://ca/api/v1/gencrl", nil)
		if err := SoftwareToken(k, []byte("cert"))(req, []byte("{}")); err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(req.Header.Get("Authorization"), ".")
		der, _ := base64.StdEncoding.DecodeString(parts[1])
		var sig struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(der, &sig); err != nil {
			t.Fatal(err)
		}
		if sig.S.Cmp(half) > 0 {
			t.Fatalf("%d번째 토큰 서명이 high-S 다", i)
		}
	}
}
