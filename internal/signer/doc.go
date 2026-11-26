// Package signer 는 Signer 인터페이스(설계서 6.4), 키 용도·부류(D-3), EVM 서명 완성(설계서 6.2)을 다룬다.
// 이 패키지는 cgo 와 internal/hsm 에 의존하지 않는다. HSM 구현은 internal/signer/hsm 에 있다.
package signer
