# 토큰증권 키 관리·서명 시스템 MVP

업무 서버는 키를 갖지 않고, 분리된 서명 서버가 HSM(PKCS#11) 안의 키로 승인된 요청만 서명하는 구조를 허가형 분산원장(Hyperledger Besu) 위에서 구현하는 프로젝트다.

## 먼저 읽을 문서

- `docs/01_개발요구사항_및_결정사항.md`: 요구사항(FR, NFR)과 결정사항(D-n). 기준 문서다.
- `docs/02_개발설계서.md`: 구성, 흐름, 데이터 모델, API, 보안 설계.
- `docs/03_작업지시서.md`: 작업 목록(T-n), 공통 규칙, 진행 현황.

작업을 시작하기 전에 `docs/03_작업지시서.md`의 공통 규칙과 해당 작업 항목을 읽어.

## 반드시 지킬 것

- 작업지시서의 순서를 지키고, 완료 기준의 검증 명령을 통과한 뒤에만 완료로 표시해.
- 개인키, HSM PIN, 래핑 키, 승인자 개인키, 비밀번호를 코드·로그·커밋에 넣지 마.
- `cmd/apid`와 그것이 쓰는 패키지에서 `internal/hsm`을 import하지 마.
- 서명 서버의 검사 단계(설계서 5.3)를 우회하는 옵션을 만들지 마.
- 설계서와 다르게 구현해야 하면 멈추고 보고해. 문서를 먼저 고치고 구현해.
- 버전과 도구 동작은 추측하지 말고 공식 문서나 실측으로 확인해.
- 메인넷이나 외부 공개망에 접속하지 마.

## 명령

| 명령 | 내용 |
|---|---|
| `make build` | 세 실행 파일 빌드(`bin/`) |
| `make test` | 단위 테스트 |
| `make test-contracts` | 컨트랙트 테스트(T3.1에서 구현) |
| `make lint` | gofmt, `go vet`, import 경계 검사(`scripts/check-imports.sh`) |
| `make up` / `make down` | 로컬 환경(Besu 4노드, MySQL) 기동·종료. `up`은 노드 키·genesis·비밀 파일이 없으면 먼저 만든다 |
| `make migrate` | DB 마이그레이션과 서버용 계정 테이블 단위 권한 부여 |
| `make it` | 통합 테스트(`-tags integration`, `make up && make migrate` 이후) |
| `make demo` | 전체 시연(T4.4에서 구현) |
| `scripts/check-besu.sh [--fault-test]` | Besu 블록 생성·검증 노드·가스비 0 tx·노드 장애 점검 |
| `scripts/probe-hsm.sh sign\|wrap` | SoftHSM2 서명·래핑 실측(서명 서버 이미지 안에서 실행) |

생성물과 비밀(커밋 금지): `deploy/besu/generated/`(노드 키), `deploy/secrets/`(DB 비밀번호), `scripts/probe-hsm/out/`.

명령이 아직 없으면 T0.1에서 만든다. 명령을 추가하거나 바꾸면 이 표를 고쳐.
