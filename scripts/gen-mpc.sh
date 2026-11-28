#!/usr/bin/env bash
# MPC 노드(mpcd-1~3)의 비밀과 설정을 만든다(T5.1, D-25). 멱등: 있는 비밀은 두고, 설정은 비밀의 공개키로 다시 만든다.
#   deploy/secrets/mpc_node_<n>_identity   Ed25519 신원 키 시드(16진수 32바이트, 커밋 금지)
#   deploy/secrets/mpc_node_<n>_store_key  조각 파일 암호화 키(16진수 32바이트, 커밋 금지)
#   deploy/mpcd/generated/mpcd-<n>.yaml    노드 설정(다른 노드 신원 공개키 포함, 비밀 아님, 생성물)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SEC=deploy/secrets
OUT=deploy/mpcd/generated
mkdir -p "$SEC" "$OUT"
chmod 700 "$SEC"
umask 077
for n in 1 2 3; do
  for kind in identity store_key; do
    f="$SEC/mpc_node_${n}_${kind}"
    if [ ! -s "$f" ]; then
      openssl rand -hex 32 | tr -d '\n' >"$f"
      echo "생성: $f"
    fi
    chmod 600 "$f"
  done
done
declare -a PUB
for n in 1 2 3; do
  PUB[$n]="$(go run ./cmd/mpcd pubkey --identity-file "$SEC/mpc_node_${n}_identity")"
done
umask 022
for n in 1 2 3; do
  cat >"$OUT/mpcd-$n.yaml" <<YAML
# 생성물(scripts/gen-mpc.sh). 노드 mpcd-$n 설정. 비밀은 Docker secret 파일 경로로만 가리킨다.
listen: ":9543"
node_id: mpcd-$n
data_dir: /var/lib/sto/mpc
identity_file: /run/secrets/mpc_node_${n}_identity
store_key_file: /run/secrets/mpc_node_${n}_store_key
coordinator: signerd
tls:
  ca: /etc/sto/certs/ca.crt
  cert: /etc/sto/certs/mpcd-$n.crt
  key: /etc/sto/certs/mpcd-$n.key
peers:
  mpcd-1: ${PUB[1]}
  mpcd-2: ${PUB[2]}
  mpcd-3: ${PUB[3]}
YAML
done
echo "MPC 노드 설정: $OUT/mpcd-{1,2,3}.yaml"
