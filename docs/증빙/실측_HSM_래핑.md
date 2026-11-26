# 실측: SoftHSM2 EC 개인키 래핑 (T0.4)

> 실측일: 2026-11-27 (KST) · 재현: `scripts/probe-hsm.sh wrap`
> 원시 결과: `scripts/probe-hsm/out/probe-wrap.json` (생성물, 커밋하지 않음)

## 결론

SoftHSM2 2.6.1은 AES-256 래핑 키로 secp256k1 개인키를 `C_WrapKey`로 내보내고, 다른(빈) 토큰에서 `C_UnwrapKey`로 복원할 수 있다. 복원한 키의 서명은 원래 주소로 복구된다. 설계서 6.3의 래핑 백업 방식을 그대로 쓰고, 대체 방식(토큰 저장소 암호화 사본)은 쓰지 않는다. 래핑 메커니즘은 SoftHSM2 2.6.1이 구현한 `CKM_AES_KEY_WRAP_PAD`로 확정한다. 래핑 결과(암호문) 형식은 PKCS#11 구현마다 다를 수 있어, 다른 HSM 제품 간 이식성은 확인하지 않았다.

## 환경

`실측_HSM_서명.md`와 같다(SoftHSM2 2.6.1, `miekg/pkcs11` v1.1.2, `signer` 사용자, `--network none`).

## 절차

1. 원본 토큰(`probe-wrap-src`)을 초기화한다. PIN은 실행마다 무작위, 메모리에만 둔다.
2. AES-256 래핑 키 32바이트를 메모리에서 만들어 `C_CreateObject`로 주입한다. 속성: `CKK_AES`, `CKA_TOKEN`, `CKA_PRIVATE`, `CKA_SENSITIVE` true, `CKA_EXTRACTABLE` false, `CKA_WRAP`, `CKA_UNWRAP` true, `CKA_ENCRYPT`, `CKA_DECRYPT` false.
3. 토큰이 알리는 메커니즘 중 `CKF_WRAP` 플래그가 있는 것을 나열한다.
4. 루트 키(secp256k1, `CKA_EXTRACTABLE=true`, `CKA_SENSITIVE=true`)를 만들고 후보 메커니즘마다 `C_WrapKey`를 시도한다.
5. 운영 키(`CKA_EXTRACTABLE=false`)의 래핑을 시도한다(실패해야 함, D-3).
6. 빈 토큰(`probe-wrap-dst`)을 새로 초기화하고 같은 래핑 키를 주입한 뒤 `C_UnwrapKey`로 복원한다.
7. 복원한 키의 속성과 `CKA_EC_PARAMS`를 확인하고, 서명 → 공개키 복구 → 주소 비교, go-ethereum 서명 검증을 한다.
8. 메모리의 래핑 키를 지운다. 래핑된 암호문은 길이만 기록한다.

## 결과

### `CKF_WRAP` 지원 메커니즘(토큰 보고)

`CKM_AES_CBC`, `CKM_AES_KEY_WRAP`, `CKM_AES_KEY_WRAP_PAD`, `CKM_DES3_CBC`, `CKM_DES_CBC`, `CKM_DES_CBC_PAD`, `CKM_DES_ECB`, `CKM_RSA_PKCS`, `CKM_RSA_PKCS_OAEP`

### EC 개인키 래핑 시도

| 메커니즘 | 값 | 결과 | 암호문 길이 |
|---|---|---|---|
| `CKM_AES_KEY_WRAP_PAD` | `0x210A` | 성공 | 72바이트 |
| `CKM_AES_KEY_WRAP_KWP` | `0x210B` | `CKR_MECHANISM_INVALID` | — |
| `CKM_AES_KEY_WRAP` | `0x2109` | 성공 | 72바이트 |
| `CKM_AES_KEY_WRAP_PAD`(구 값) | `0x1091` | `CKR_MECHANISM_INVALID` | — |
| `CKM_AES_KEY_WRAP`(구 값) | `0x1090` | `CKR_MECHANISM_INVALID` | — |

`CKM_AES_KEY_WRAP`도 성공했지만, 패딩을 메커니즘이 처리하는 `CKM_AES_KEY_WRAP_PAD`를 쓴다(설계서 6.3의 "AES 키 랩 패딩 메커니즘").

### 추출 불가 키

운영 키(`CKA_EXTRACTABLE=false`)의 `C_WrapKey(CKM_AES_KEY_WRAP_PAD)` → `CKR_KEY_UNEXTRACTABLE (0x6A)`로 거부됨. D-3의 "추출 불가 속성과 래핑 내보내기는 양립하지 않는다"를 확인했다.

### 복원

| 항목 | 결과 |
|---|---|
| 복원 템플릿 | `CKO_PRIVATE_KEY`, `CKK_EC`, `CKA_TOKEN`, `CKA_PRIVATE`, `CKA_SENSITIVE`, `CKA_EXTRACTABLE`, `CKA_SIGN` true, `CKA_LABEL`/`CKA_ID` = key_id |
| 복원된 속성 | 템플릿과 같음 |
| `CKA_EC_PARAMS` | secp256k1 OID와 일치 |
| 원본 주소 | `0x95fDd084Ee346AFf3230211e5FE1479624FcBc3a` |
| 복원 키 서명으로 복구한 주소 | `0x95fDd084Ee346AFf3230211e5FE1479624FcBc3a` (일치) |
| go-ethereum 서명 검증 | 통과 |

## M3(T3.6) 구현에 넘길 사항

- `C_UnwrapKey`는 개인키 객체만 만든다. 공개키 객체가 없으므로 주소 확인은 레지스트리의 공개키와 "서명 → 복구"로 하고, 필요하면 백업 파일의 공개키로 공개키 객체를 따로 만든다.
- 복원 템플릿의 `CKA_EXTRACTABLE`을 true로 둬야 복원된 루트 키를 다시 백업할 수 있다.
- 래핑 키는 두 토큰에 같은 값으로 주입해야 하므로, 설계서 6.3의 의식에서 Shamir 조각으로 복원한 값을 주입한 뒤 메모리에서 지운다.
- 이번 실측은 한 컨테이너 안에서 두 토큰을 썼다. "빈 HSM 복구 리허설"(T3.6)은 새 토큰 볼륨에서 실행한다.
