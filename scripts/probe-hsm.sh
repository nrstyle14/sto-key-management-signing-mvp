#!/usr/bin/env bash
# SoftHSM2 실측 실행기(T0.3, T0.4)
#   scripts/probe-hsm.sh sign  : 서명 서버 이미지 안에서 secp256k1 서명을 실측하고,
#                                만든 트랜잭션을 호스트에서 Besu(node1)에 제출해 확정을 확인한다.
#   scripts/probe-hsm.sh wrap  : EC 개인키 래핑·복원을 실측한다.
# 실측 컨테이너는 네트워크 없이(--network none) 실행한다. 서명 서버 쪽은 원장 노드에 접속하지 않는다.
# 토큰은 실행마다 새 볼륨에 만들고 끝나면 지운다.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${SIGNERD_IMAGE:-sto-kms/signerd:dev}"
RPC="${RPC:-http://127.0.0.1:8545}"
OUT="$ROOT/scripts/probe-hsm/out"
MODE="${1:-sign}"

docker build -q -f "$ROOT/deploy/signerd/Dockerfile" -t "$IMAGE" "$ROOT" >/dev/null
mkdir -p "$OUT"

VOL="sto-kms-probe-tokens-$$"
docker volume create "$VOL" >/dev/null
trap 'docker volume rm -f "$VOL" >/dev/null 2>&1 || true' EXIT

rpc() {
  curl -sf -X POST -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":$2,\"id\":1}" "$RPC"
}

case "$MODE" in
  sign)
    chain_id=$(printf '%d' "$(rpc eth_chainId '[]' | jq -r .result)")
    docker run --rm --network none -v "$VOL:/var/lib/softhsm/tokens" -v "$OUT:/out" \
      --entrypoint /usr/local/bin/probe-hsm "$IMAGE" sign -chain-id "$chain_id" -out /out
    raw=$(tr -d '\n' < "$OUT/raw-tx.hex")
    want_hash=$(jq -r .tx_hash "$OUT/probe-sign.json")
    want_from=$(jq -r .key_address "$OUT/probe-sign.json" | tr '[:upper:]' '[:lower:]')
    resp=$(rpc eth_sendRawTransaction "[\"$raw\"]")
    got_hash=$(echo "$resp" | jq -r '.result // empty')
    [ -n "$got_hash" ] || { echo "제출 실패: $resp" >&2; exit 1; }
    [ "$got_hash" = "$want_hash" ] || { echo "tx 해시 불일치: $got_hash != $want_hash" >&2; exit 1; }
    for _ in $(seq 1 30); do
      rcpt=$(rpc eth_getTransactionReceipt "[\"$got_hash\"]" | jq -c '.result')
      [ "$rcpt" != "null" ] && break
      sleep 1
    done
    [ "$rcpt" != "null" ] || { echo "영수증 시간 초과" >&2; exit 1; }
    status=$(echo "$rcpt" | jq -r .status)
    from=$(echo "$rcpt" | jq -r .from)
    block=$(printf '%d' "$(echo "$rcpt" | jq -r .blockNumber)")
    echo "$rcpt" | jq '{transactionHash, blockNumber, from, status, type, effectiveGasPrice}' > "$OUT/receipt.json"
    [ "$status" = "0x1" ] || { echo "트랜잭션 실패 status=$status" >&2; exit 1; }
    [ "$from" = "$want_from" ] || { echo "송신자 불일치: $from != $want_from" >&2; exit 1; }
    echo "OK: HSM 키로 서명한 트랜잭션 확정 tx=$got_hash block=$block from=$from"
    ;;
  wrap)
    docker run --rm --network none -v "$VOL:/var/lib/softhsm/tokens" -v "$OUT:/out" \
      --entrypoint /usr/local/bin/probe-hsm "$IMAGE" wrap -out /out
    echo "OK: EC 개인키 래핑·복원 실측 성공"
    ;;
  *)
    echo "사용법: $0 sign|wrap" >&2
    exit 2
    ;;
esac
