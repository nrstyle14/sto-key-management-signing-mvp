#!/usr/bin/env bash
# 서명 서버의 HSM 토큰 초기화(scripts/init-tokens.sh)와 부트스트랩을 실행한다(T1.2, T1.4).
# - 토큰 초기화는 멱등이다. 부트스트랩은 한 번만 적용되고, 이미 적용된 경우(종료 코드 3)는 정상으로 본다.
#   signerd init 자체는 두 번째 실행을 거부한다.
# - signerd 는 init-tokens.sh 가 멈춰 둔 상태에서 실행한다(토큰 볼륨 동시 사용 방지).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/deploy/docker-compose.yml")

"$ROOT/scripts/init-tokens.sh"
set +e
"${COMPOSE[@]}" run --rm -T signerd-setup init --config /etc/sto/signerd.yaml --bootstrap /etc/sto/bootstrap.yaml
rc=$?
set -e
case $rc in
  0) echo "부트스트랩 적용" ;;
  3) echo "부트스트랩: 이미 적용됨(건너뜀)" ;;
  *) echo "부트스트랩 실패(rc=$rc)" >&2; exit "$rc" ;;
esac
