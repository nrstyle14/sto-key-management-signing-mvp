# 실측: SoftHSM2 secp256k1 서명 (T0.3)

> 실측일: 2026-11-27 (KST) · 재현: `make up && scripts/probe-hsm.sh sign`
> 원시 결과: `scripts/probe-hsm/out/probe-sign.json`, `receipt.json` (생성물, 커밋하지 않음)

## 결론

SoftHSM2 2.6.1은 secp256k1 키 생성과 `CKM_ECDSA` 서명을 지원한다. HSM이 돌려준 `(r, s)`를 low-s로 정규화하고 복구 식별자를 계산해 만든 EIP-1559 트랜잭션이 Besu QBFT 네트워크에서 확정됐다. 요구사항 7절의 "SoftHSM2의 secp256k1 지원 여부" 리스크는 해소됐다. M1 구조를 바꿀 필요가 없다.

## 환경

| 항목 | 값 |
|---|---|
| 서명 서버 이미지 | `deploy/signerd/Dockerfile` (빌드 `golang:1.27.4-trixie`, 실행 `debian:trixie-slim`) |
| SoftHSM2 | 2.6.1 (Debian trixie `softhsm2` 패키지), 라이브러리 `/usr/lib/softhsm/libsofthsm2.so` |
| PKCS#11 바인딩 | `github.com/miekg/pkcs11` v1.1.2 (cgo) |
| EVM 라이브러리 | `github.com/ethereum/go-ethereum` v1.17.10 |
| 실행 사용자 | `signer`(uid 10001), `softhsm` 그룹. Debian 패키지가 `/etc/softhsm`, `/var/lib/softhsm`을 `softhsm` 그룹 전용으로 두기 때문에 그룹 추가가 필요했다 |
| 네트워크 | 실측 컨테이너는 `--network none`. 원장 제출은 호스트 스크립트가 node1 RPC로 한다 |
| 원장 | Besu 26.11.2 QBFT 4노드, chainId 20261124, 가스비 0 (D-10) |

## 절차

1. 초기화되지 않은 슬롯에 토큰을 만든다. SO PIN과 사용자 PIN은 실행마다 무작위로 만들어 메모리에만 둔다(출력·저장하지 않음).
2. `CKM_EC_KEY_PAIR_GEN`으로 키 쌍을 만든다.
3. 개인키의 `CKA_VALUE` 읽기를 시도한다(실패해야 함).
4. 무작위 다이제스트 200개에 `CKM_ECDSA` 서명 → low-s 정규화 → 복구 식별자 계산 → go-ethereum `VerifySignature`로 검증한다.
5. EIP-1559 트랜잭션(가스비 0)의 서명 해시에 서명해 직렬화하고, 호스트에서 `eth_sendRawTransaction`으로 제출해 영수증을 확인한다.

## 결과

### 메커니즘

| 메커니즘 | 값 | 키 크기(비트) | 지원 |
|---|---|---|---|
| `CKM_EC_KEY_PAIR_GEN` | `0x1040` | 112~521 | 예 |
| `CKM_ECDSA` | `0x1041` | 112~521 | 예 |

### 키 속성

| 구분 | 속성 | 값 |
|---|---|---|
| 곡선 지정 | `CKA_EC_PARAMS` | `06 05 2B 81 04 00 0A` (secp256k1 OID 1.3.132.0.10의 DER) |
| 공개키 템플릿 | `CKA_TOKEN`, `CKA_VERIFY` | true |
| 개인키 템플릿 | `CKA_TOKEN`, `CKA_PRIVATE`, `CKA_SENSITIVE`, `CKA_SIGN` | true |
| 개인키 템플릿 | `CKA_EXTRACTABLE` | false |
| 생성 후 확인 | `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE` | true, true |
| 식별 | `CKA_LABEL`, `CKA_ID` | key_id 문자열, key_id 바이트 |

### 출력 형식

| 항목 | 형식 |
|---|---|
| `CKA_EC_POINT` | 67바이트. DER OCTET STRING(`04 41`)으로 감싼 비압축 점(`0x04 ‖ X ‖ Y`, 65바이트). 앞 2바이트를 벗겨 쓴다 |
| `C_Sign(CKM_ECDSA)` | 64바이트 `r ‖ s`(각 32바이트 빅엔디언). DER 아님 |
| 다이제스트 | 호출자가 계산한 32바이트를 그대로 서명한다(해시를 다시 하지 않음) |

### 추출 불가 확인

개인키 `CKA_VALUE` 읽기 → `CKR_ATTRIBUTE_SENSITIVE (0x11)`로 거부됨.

### low-s 정규화와 복구 식별자

| 항목 | 1차 실측 | 2차 실측(non-root 재실행) |
|---|---|---|
| 반복 서명 수 | 200 | 200 |
| high-s 발생(`s > n/2`) | 101 | 103 |
| 정규화 후 주소 복구 일치 | 200/200 | 200/200 |
| 복구 식별자 분포(0/1) | 99/101 | — |

SoftHSM2는 s를 정규화하지 않는다. 약 절반이 high-s이므로 설계서 6.2의 3단계(low-s 정규화)는 필수다. go-ethereum의 `VerifySignature`는 high-s를 거부하므로 정규화 결과가 함께 검증됐다.

### 트랜잭션 확정

| 항목 | 1차 | 2차 |
|---|---|---|
| 유형 | type 2 (EIP-1559), `maxFeePerGas = maxPriorityFeePerGas = 0` | 같음 |
| tx 해시 | `0xc08acc8e6364098165e125114db7f21b43841b5bdc8b71792a5e6c9a88c38552` | `0x3c3e40ebfb1b631d013499dc75b874ed5a65d60f72a0fb84d5237a7ca7947389` |
| 블록 | 242 | 263 |
| 영수증 `status` | `0x1` | `0x1` |
| 영수증 `from` = HSM 키 주소 | 일치 | 일치 |
| `effectiveGasPrice` | 0 | 0 |

실측 키와 토큰은 실행마다 새 볼륨에 만들고 실행 후 볼륨째 지웠다. 위 주소는 폐기된 실측용 키의 주소다.

## M1 구현에 넘길 사항

- 공개키는 `CKA_EC_POINT`의 DER 감싸기를 벗겨 65바이트로 쓴다. 다른 PKCS#11 구현은 감싸지 않은 값을 줄 수 있으므로 두 형식을 모두 받는다.
- 서명은 64바이트 `r ‖ s`로 받고, low-s 정규화 → 복구 식별자 0·1로 공개키를 복구해 레지스트리 주소와 일치하는 값을 고른다(설계서 6.2 그대로).
- 토큰 초기화 뒤 SoftHSM2는 슬롯 ID를 다시 배정한다. 슬롯은 ID가 아니라 토큰 라벨로 찾는다.
- 서명 서버 이미지는 non-root `signer` 사용자를 `softhsm` 그룹에 넣어 실행한다.
