#!/usr/bin/env bash
# 설계서 2절의 HSM 토큰 네 개(besu-local.platform, besu-local.inst-a, besu-local.inst-b, audit)를 초기화한다(T1.2).
# - signerd init-tokens 가 PKCS#11(C_InitToken, C_InitPIN)로 초기화한다. PIN 은 Docker secret 파일에서 읽고
#   명령행 인자·환경 변수로 넘기지 않는다. 이미 있는 토큰은 건너뛴다(다시 초기화하지 않는다).
# - 같은 토큰 볼륨을 두 프로세스가 동시에 쓰지 않도록 signerd 를 먼저 멈춘다.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/deploy/docker-compose.yml")

"${COMPOSE[@]}" build -q signerd
"${COMPOSE[@]}" stop signerd >/dev/null 2>&1 || true
"${COMPOSE[@]}" run --rm -T signerd-setup init-tokens --config /etc/sto/signerd.yaml
