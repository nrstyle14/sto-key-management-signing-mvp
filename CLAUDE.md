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
| `make gen` | 컨트랙트 컴파일(Foundry)과 Go 바인딩 생성(`internal/ledger/besu/sectoken`, 커밋 대상) |
| `make test-contracts` | 컨트랙트 테스트(Foundry)와 커밋된 바인딩이 소스와 같은지 확인. 처음 받은 저장소는 `git submodule update --init` 먼저 |
| `make lint` | gofmt, `go vet`(통합 태그 포함), import 경계 검사(`scripts/check-imports.sh`) |
| `make up` / `make down` | 로컬 환경 기동·종료. `up`: 생성물(노드 키·비밀·인증서·승인자 키와 부트스트랩 파일) → Besu·MySQL → 마이그레이션 → HSM 토큰 초기화·부트스트랩(`scripts/init-signer.sh`) → signerd·apid |
| `make migrate` | DB 마이그레이션과 서버용 계정 테이블 단위 권한 부여 |
| `make it` | 통합 테스트(`make up` 이후): 호스트 DB·서버·종단 시험 → SoftHSM2 컨테이너 시험(`scripts/it-hsm.sh`) |
| `make demo` | 전체 시연(T4.4에서 구현) |
| `scripts/check-besu.sh [--fault-test]` | Besu 블록 생성·검증 노드·가스비 0 tx·노드 장애 점검 |
| `scripts/probe-hsm.sh sign\|wrap` | SoftHSM2 서명·래핑 실측(서명 서버 이미지 안에서 실행) |
| `bin/stoctl request draft\|approve\|reject\|show\|list` | 업무 요청 기안·승인(승인자 키 파일로 서명)·조회 |
| `bin/stoctl freeze key\|institution\|ledger\|release\|list` | 동결(보안관리자 1인)·해제(2인), 서명 서버 직접 호출 |
| `bin/stoctl request wait <id> [--status]` | 요청이 기대 상태(기본 CONFIRMED)가 될 때까지 대기 |
| `bin/stoctl security deploy\|grant-role\|set-agent\|list\|roles` | 종목 배포(DEPLOY)·역할 부여/회수·기관 대응 요청 기안, 종목 조회, 원장의 역할 확인 |
| `bin/stoctl registry events --contract` | 보존된 원장 이벤트 조회 |
| `bin/stoctl key list\|generate\|retire\|destroy\|rotate` | 키 레지스트리 조회, 키 작업(보안관리자 2명 서명), 키 교체(`--until`, `--resume`) |
| `bin/stoctl key ceremony\|backup\|restore` | 래핑 키 의식(Shamir 조각 `deploy/ceremony/`), 루트 키 백업(`deploy/backups/`)·복원 |
| `bin/stoctl audit verify\|checkpoint\|trail\|head` | 두 감사 체인과 체크포인트 검증, 체크포인트 생성, 요청별 기록(`--require`), 머리 seq |
| `scripts/bootstrap-security.sh [종목코드] [종목명]` | 종목 배포와 기관 키 역할 부여(모두 승인 요청), 원장·감사 확인 |
| `scripts/flow-issue-transfer.sh <컨트랙트>` | stoctl 로 계좌 등록 → 발행 → 계좌대체, 보존 이벤트 확인 |
| `scripts/rehearsal-restore.sh` | 래핑 키 의식 → 루트 키 백업 → 일회용 빈 토큰 복구 리허설 → `docs/증빙/복구리허설_YYYYMMDD.md` |
| `scripts/incident-key-compromise.sh [기관/용도]` | 키 도난 대응(동결 → 역할 회수 → 유통 정지 → 새 키 → 재개 → 폐기), 단계별 시간·감사 seq |
| `go run ./scripts/probe-besu-resubmit` | Besu 재제출 응답·가스 사용량 실측 |

생성물과 비밀(커밋 금지): `deploy/besu/generated/`(노드 키), `deploy/secrets/`(DB 비밀번호, HSM PIN, 승인자 키 암호), `deploy/approvers/`(암호화된 승인자 키), `deploy/signerd/generated/`(부트스트랩 파일), `deploy/certs/`(CA·서버 인증서와 키), `deploy/ceremony/`(래핑 키 조각), `deploy/backups/`(루트 키 백업), `scripts/probe-hsm/out/`, `contracts/out/`·`contracts/cache/`.

빌드 태그: `integration`(통합 테스트).

명령이 아직 없으면 T0.1에서 만든다. 명령을 추가하거나 바꾸면 이 표를 고쳐.
