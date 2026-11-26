#!/usr/bin/env bash
# M1 종단 시험: signerd 를 시험용 빌드(signtx_m1, 서명 API 열림)로 바꿔 띄우고 test/ 의 종단 시험을 실행한 뒤
# 기본 빌드(서명 API 없음)로 되돌린다. 같은 토큰 볼륨을 쓰는 signerd 는 항상 하나만 돈다(컨테이너 교체).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/deploy/docker-compose.yml")

restore() {
  echo "signerd 를 기본 빌드로 되돌린다"
  "${COMPOSE[@]}" up -d --wait --build signerd >/dev/null
}
trap restore EXIT

SIGNERD_IMAGE_TAG=it-signtx-m1 SIGNERD_GO_BUILD_TAGS=signtx_m1 "${COMPOSE[@]}" up -d --wait --build signerd >/dev/null
cd "$ROOT"
go test -count=1 -tags "integration signtx_m1" -run 'TestSignTx' -v ./test/... 2>&1 | grep -E '^(=== RUN|--- |ok|FAIL|PASS)|signtx_e2e_test'
