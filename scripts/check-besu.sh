#!/usr/bin/env bash
# Besu 로컬 네트워크 점검(T0.2)
#  1) 블록이 생성되는지
#  2) 검증 노드가 4개인지, 피어가 3개인지
#  3) eth_gasPrice 가 0인지
#  4) 잔액 0인 계정의 가스비 0 트랜잭션(레거시, EIP-1559)이 확정되는지
#  --fault-test: 검증 노드 하나(node4)를 내린 상태에서도 블록이 계속 생성되는지 확인하고 다시 올린다.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RPC="${RPC:-http://127.0.0.1:8545}"
COMPOSE=(docker compose -f "$ROOT/deploy/docker-compose.yml")
FAULT_TEST=0
[ "${1:-}" = "--fault-test" ] && FAULT_TEST=1

rpc() {
  curl -sf -X POST -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":${2:-[]},\"id\":1}" "$RPC"
}
hex2dec() { printf '%d' "$1"; }
block_number() { hex2dec "$(rpc eth_blockNumber | jq -r .result)"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "OK  : $*"; }

# 블록이 timeout 초 안에 늘어나는지 본다.
wait_block_advance() {
  local timeout=$1 start now
  start=$(block_number)
  for _ in $(seq 1 "$timeout"); do
    sleep 1
    now=$(block_number)
    if [ "$now" -gt "$start" ]; then
      echo "$start $now"
      return 0
    fi
  done
  return 1
}

# 1) 블록 생성
read -r b0 b1 < <(wait_block_advance 15) || fail "15초 동안 블록이 늘지 않았다"
ok "블록 생성: $b0 -> $b1"

# 2) 검증 노드 수와 피어 수
validators=$(rpc qbft_getValidatorsByBlockNumber '["latest"]' | jq '.result | length')
[ "$validators" -eq 4 ] || fail "검증 노드 수 $validators (기대 4)"
ok "검증 노드 수: $validators"
peers=$(hex2dec "$(rpc net_peerCount | jq -r .result)")
[ "$peers" -eq 3 ] || fail "피어 수 $peers (기대 3)"
ok "피어 수: $peers"

# 3) 가스 가격
gas_price=$(hex2dec "$(rpc eth_gasPrice | jq -r .result)")
[ "$gas_price" -eq 0 ] || fail "eth_gasPrice=$gas_price (기대 0)"
ok "eth_gasPrice: 0"

# 4) 잔액 0 계정의 가스비 0 트랜잭션
(cd "$ROOT" && go run ./scripts/zerogas-tx -rpc "$RPC") || fail "가스비 0 트랜잭션 실측 실패"
ok "잔액 0 계정의 가스비 0 트랜잭션 확정"

if [ "$FAULT_TEST" -eq 1 ]; then
  echo "--- 장애 시험: besu-node4 중지"
  "${COMPOSE[@]}" stop besu-node4 >/dev/null
  trap '"${COMPOSE[@]}" start besu-node4 >/dev/null 2>&1 || true' EXIT
  # 중지된 노드가 제안자 차례이면 라운드 변경(requesttimeoutseconds=4, 이후 배증)이 일어나므로 여유를 둔다.
  sleep 5
  read -r f0 f1 < <(wait_block_advance 60) || fail "노드 하나 중지 후 60초 동안 블록이 늘지 않았다"
  read -r g0 g1 < <(wait_block_advance 60) || fail "노드 하나 중지 후 블록 생성이 이어지지 않았다"
  ok "노드 하나 중지 상태에서 블록 생성: $f0 -> $g1"
  (cd "$ROOT" && go run ./scripts/zerogas-tx -rpc "$RPC" -types dynamic) || fail "노드 하나 중지 상태에서 트랜잭션 확정 실패"
  ok "노드 하나 중지 상태에서 트랜잭션 확정"
  "${COMPOSE[@]}" start besu-node4 >/dev/null
  trap - EXIT
  for _ in $(seq 1 60); do
    sleep 2
    peers=$(hex2dec "$(rpc net_peerCount | jq -r .result)")
    [ "$peers" -eq 3 ] && break
  done
  [ "$peers" -eq 3 ] || fail "node4 재기동 후 피어 수 $peers (기대 3)"
  ok "node4 재기동 후 피어 수 복구: $peers"
fi

echo "check-besu: 모든 점검 통과"
