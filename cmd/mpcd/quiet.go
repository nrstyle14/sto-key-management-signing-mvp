package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// quietLibraryLog 는 표준 출력을 /dev/null 로 돌린다. alice 는 초기화 때 표준 출력에 붙는 자체 로거로
// 프로토콜 진행 메시지를 쓰고 그 로거를 바꿀 공개 API 가 없다(조각 값은 쓰지 않음을 확인했다).
// mpcd 자신의 로그는 표준 오류(slog JSON)로 쓴다.
func quietLibraryLog() {
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return
	}
	_ = unix.Dup2(int(f.Fd()), int(os.Stdout.Fd()))
}
