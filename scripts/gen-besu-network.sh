#!/usr/bin/env bash
# Besu QBFT 로컬 네트워크의 노드 키, genesis, 노드별 설정을 생성한다.
# - 노드 키는 개인키이므로 deploy/besu/generated/ 에만 두고 커밋하지 않는다(.gitignore).
# - 이미 생성돼 있으면 아무것도 하지 않는다(멱등). 다시 만들려면 generated 디렉터리를 직접 지운다.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BESU_IMAGE="${BESU_IMAGE:-hyperledger/besu:26.11.2}"
SRC="$ROOT/deploy/besu"
OUT="$SRC/generated"
# docker-compose.yml 의 besu 네트워크 고정 IP와 맞춘다.
NODE_IPS=(172.28.0.11 172.28.0.12 172.28.0.13 172.28.0.14)
P2P_PORT=30303

if [ -f "$OUT/genesis.json" ]; then
  echo "이미 생성됨: $OUT (재생성하려면 디렉터리를 지운다)"
  exit 0
fi

tmp="$OUT.tmp"
rm -rf -- "$tmp"
mkdir -p "$tmp"
cp "$SRC/qbftConfigFile.json" "$tmp/qbftConfigFile.json"

docker run --rm --user "$(id -u):$(id -g)" -v "$tmp:/work" "$BESU_IMAGE" \
  operator generate-blockchain-config \
  --config-file=/work/qbftConfigFile.json --to=/work/networkFiles --private-key-file-name=key >/dev/null

# 노드 디렉터리는 주소 오름차순으로 node1..node4 에 배정한다.
KEYDIRS=()
while IFS= read -r line; do KEYDIRS+=("$line"); done < <(find "$tmp/networkFiles/keys" -mindepth 1 -maxdepth 1 -type d | sort)
if [ "${#KEYDIRS[@]}" -ne 4 ]; then
  echo "노드 키가 4개가 아니다: ${#KEYDIRS[@]}" >&2
  exit 1
fi

ENODES=()
for i in 0 1 2 3; do
  pub="$(tr -d '\n' < "${KEYDIRS[$i]}/key.pub")"
  ENODES+=("enode://${pub#0x}@${NODE_IPS[$i]}:${P2P_PORT}")
done

for i in 0 1 2 3; do
  n=$((i + 1))
  d="$tmp/node$n"
  mkdir -p "$d"
  cp "${KEYDIRS[$i]}/key" "$d/key"
  cp "${KEYDIRS[$i]}/key.pub" "$d/key.pub"
  chmod 600 "$d/key"
  basename "${KEYDIRS[$i]}" > "$d/address"
  # 자기 자신을 뺀 나머지 노드를 정적 피어로 둔다. 디스커버리는 끈다(외부 망 접속 차단).
  {
    echo "["
    first=1
    for j in 0 1 2 3; do
      [ "$j" -eq "$i" ] && continue
      [ "$first" -eq 1 ] || echo ","
      printf '  "%s"' "${ENODES[$j]}"
      first=0
    done
    echo
    echo "]"
  } > "$d/static-nodes.json"
done

cp "$tmp/networkFiles/genesis.json" "$tmp/genesis.json"
rm -rf -- "$tmp/networkFiles" "$tmp/qbftConfigFile.json"
mv "$tmp" "$OUT"
echo "생성 완료: $OUT"
for n in 1 2 3 4; do echo "  node$n $(cat "$OUT/node$n/address")"; done
