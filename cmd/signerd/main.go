// Command signerd 는 서명 서버다. 현재는 버전만 출력한다(T0.1 골격).
package main

import (
	"fmt"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/version"
)

func main() {
	fmt.Println(version.String("signerd"))
}
