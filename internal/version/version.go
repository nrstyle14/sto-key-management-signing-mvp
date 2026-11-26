// Package version 은 실행 파일의 버전 정보를 제공한다.
// 값은 빌드 시 -ldflags "-X" 로 주입한다.
package version

import "fmt"

var (
	// Version 은 빌드 버전이다(기본값 dev).
	Version = "dev"
	// Commit 은 빌드한 소스의 커밋 해시다.
	Commit = "unknown"
)

// String 은 "<이름> <버전> (<커밋>)" 형식의 버전 문자열을 돌려준다.
func String(name string) string {
	return fmt.Sprintf("%s %s (%s)", name, Version, Commit)
}
