#!/usr/bin/env bash
# 로컬 Fabric 네트워크 기동(T5.2, D-26). make up 뒤에 실행한다(make up-fabric). 멱등.
#   1. 노드·기관 관리자 신원(cryptogen)과 채널 블록(configtxgen) → deploy/fabric/generated/(커밋 금지)
#   2. MSP 루트 CA·peer TLS CA 를 서명 서버·업무 서버가 읽는 위치에 둔다
#   3. orderer·peer·CA·도구 기동 → 채널 참가(osnadmin, peer)
#   4. 체인코드(CCaaS) 패키지 설치·승인·커밋 → 체인코드 컨테이너 기동
#   5. 서명 서버·업무 서버를 다시 띄워 Fabric 원장을 켠다
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f deploy/docker-compose.yml)
FAB=(docker compose -f deploy/docker-compose.yml --profile fabric)
GEN=deploy/fabric/generated
ORG=/w/generated/crypto-config/peerOrganizations/insta.example.com
ORDERER_TLS=/w/generated/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/tls
TOOLS_IMAGE=hyperledger/fabric-tools:2.5.16
CHANNEL=sto-channel
CC=sectoken
CC_LABEL=sectoken_1

mkdir -p "$GEN/roots" "$GEN/public"

echo "1. 신원·채널 블록"
if [ ! -d "$GEN/crypto-config" ]; then
  docker run --rm -v "$PWD/deploy/fabric:/w" -w /w "$TOOLS_IMAGE" \
    cryptogen generate --config=/w/crypto-config.yaml --output=/w/generated/crypto-config >/dev/null
  echo "   cryptogen 생성"
fi
if [ ! -f "$GEN/$CHANNEL.block" ]; then
  docker run --rm -v "$PWD/deploy/fabric:/w" -w /w -e FABRIC_CFG_PATH=/w "$TOOLS_IMAGE" \
    configtxgen -profile StoChannel -outputBlock "/w/generated/$CHANNEL.block" -channelID "$CHANNEL" >/dev/null 2>&1
  echo "   채널 블록 생성"
fi
cp "$GEN/crypto-config/peerOrganizations/insta.example.com/ca/ca.insta.example.com-cert.pem" "$GEN/roots/insta-ca.pem"
# 업무 서버·체인코드 컨테이너에는 공개 파일(public/)만 마운트한다(개인키가 있는 generated/ 전체는 아님).
cp "$GEN/crypto-config/peerOrganizations/insta.example.com/peers/peer0.insta.example.com/tls/ca.crt" "$GEN/public/peer-tls-ca.pem"

echo "2. 노드 기동"
"${FAB[@]}" up -d fabric-orderer fabric-peer fabric-ca fabric-tools >/dev/null 2>&1

admin() { # 도구 컨테이너에서 InstAMSP 관리자 신원으로 실행
  "${FAB[@]}" exec -T -e CORE_PEER_LOCALMSPID=InstAMSP -e "CORE_PEER_MSPCONFIGPATH=$ORG/users/Admin@insta.example.com/msp" \
    -e CORE_PEER_ADDRESS=peer0.insta.example.com:7051 -e CORE_PEER_TLS_ENABLED=true \
    -e "CORE_PEER_TLS_ROOTCERT_FILE=$ORG/peers/peer0.insta.example.com/tls/ca.crt" fabric-tools "$@"
}
osn() {
  "${FAB[@]}" exec -T fabric-tools osnadmin "$@" -o orderer.example.com:7053 --ca-file "$ORDERER_TLS/ca.crt" \
    --client-cert "$ORDERER_TLS/server.crt" --client-key "$ORDERER_TLS/server.key"
}
for _ in $(seq 1 30); do
  osn channel list >/dev/null 2>&1 && break
  sleep 1
done

echo "3. 채널 참가"
if ! osn channel list 2>/dev/null | grep -q "\"$CHANNEL\""; then
  osn channel join --channelID "$CHANNEL" --config-block "/w/generated/$CHANNEL.block" >/dev/null
  echo "   orderer 참가"
fi
for _ in $(seq 1 30); do
  admin peer channel list >/dev/null 2>&1 && break
  sleep 1
done
if ! admin peer channel list 2>/dev/null | grep -qx "$CHANNEL"; then
  admin peer channel join -b "/w/generated/$CHANNEL.block" >/dev/null 2>&1
  echo "   peer 참가"
fi

echo "4. 체인코드"
mkdir -p "$GEN/cc"
if [ ! -f "$GEN/cc/$CC.tgz" ]; then
  tmp="$(mktemp -d)"
  echo '{"address":"sectoken-cc:9999","dial_timeout":"10s","tls_required":false}' >"$tmp/connection.json"
  echo "{\"type\":\"ccaas\",\"label\":\"$CC_LABEL\"}" >"$tmp/metadata.json"
  tar -C "$tmp" -czf "$tmp/code.tar.gz" connection.json
  tar -C "$tmp" -czf "$GEN/cc/$CC.tgz" metadata.json code.tar.gz
  rm -r "$tmp"
fi
pkg="$(admin peer lifecycle chaincode queryinstalled 2>/dev/null | sed -n "s/^Package ID: \(${CC_LABEL}:[0-9a-f]*\), Label: ${CC_LABEL}.*/\1/p" | head -1)"
if [ -z "$pkg" ]; then
  admin peer lifecycle chaincode install "/w/generated/cc/$CC.tgz" >/dev/null 2>&1
  pkg="$(admin peer lifecycle chaincode queryinstalled 2>/dev/null | sed -n "s/^Package ID: \(${CC_LABEL}:[0-9a-f]*\), Label: ${CC_LABEL}.*/\1/p" | head -1)"
  echo "   설치: $pkg"
fi
[ -n "$pkg" ] || { echo "체인코드 패키지 ID 를 찾지 못했다" >&2; exit 1; }
printf '%s' "$pkg" >"$GEN/public/cc-package-id"
"${FAB[@]}" up -d --build fabric-cc >/dev/null 2>&1
if ! admin peer lifecycle chaincode querycommitted -C "$CHANNEL" -n "$CC" >/dev/null 2>&1; then
  admin peer lifecycle chaincode approveformyorg -o orderer.example.com:7050 --tls --cafile "$ORDERER_TLS/ca.crt" \
    -C "$CHANNEL" -n "$CC" -v 1 --package-id "$pkg" --sequence 1 >/dev/null 2>&1
  admin peer lifecycle chaincode commit -o orderer.example.com:7050 --tls --cafile "$ORDERER_TLS/ca.crt" -C "$CHANNEL" -n "$CC" -v 1 \
    --sequence 1 --peerAddresses peer0.insta.example.com:7051 --tlsRootCertFiles "$ORG/peers/peer0.insta.example.com/tls/ca.crt" >/dev/null 2>&1
  echo "   승인·커밋"
fi

echo "5. 서명 서버·업무 서버 재기동(Fabric 원장 켜기)"
"${COMPOSE[@]}" up -d --wait --force-recreate signerd apid >/dev/null 2>&1
echo "Fabric 네트워크 준비: 채널 $CHANNEL, 체인코드 $CC ($pkg)"
