#!/usr/bin/env bash
# Fabric 폐기 반영(T5.2, D-26): CA 가 낸 CRL 을 채널 설정의 InstAMSP revocation_list 에 넣는다(기관 관리자 서명).
# CA 에서 폐기만 해서는 원장에서 효력이 없고, 이 갱신 직후부터 그 인증서의 요청이 거부된다(실측 0.2초).
#   사용: scripts/fabric-crl-update.sh deploy/fabric/generated/crl/<일련번호>.pem
# 기관 관리자 키는 파일(cryptogen, D-26 ⑥ 한계)이고 도구 컨테이너 안에서만 쓴다.
set -euo pipefail
cd "$(dirname "$0")/.."

CRL="${1:?CRL 파일이 필요하다}"
case "$CRL" in
  deploy/fabric/generated/*) ;;
  *) echo "CRL 은 deploy/fabric/generated/ 아래에 있어야 한다(도구 컨테이너가 /w/generated 로 본다)" >&2; exit 2 ;;
esac
IN_CONTAINER="/w/${CRL#deploy/fabric/}"
CHANNEL=sto-channel
GEN=deploy/fabric/generated
WORK="$GEN/config-update"
mkdir -p "$WORK"
ORG=/w/generated/crypto-config/peerOrganizations/insta.example.com
ORDERER_CA=/w/generated/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/tls/ca.crt
FAB=(docker compose -f deploy/docker-compose.yml --profile fabric)

admin() {
  "${FAB[@]}" exec -T -e CORE_PEER_LOCALMSPID=InstAMSP -e "CORE_PEER_MSPCONFIGPATH=$ORG/users/Admin@insta.example.com/msp" \
    -e CORE_PEER_ADDRESS=peer0.insta.example.com:7051 -e CORE_PEER_TLS_ENABLED=true \
    -e "CORE_PEER_TLS_ROOTCERT_FILE=$ORG/peers/peer0.insta.example.com/tls/ca.crt" fabric-tools "$@"
}

W=/w/generated/config-update
admin peer channel fetch config "$W/config_block.pb" -o orderer.example.com:7050 --tls --cafile "$ORDERER_CA" -c "$CHANNEL" >/dev/null 2>&1
admin configtxlator proto_decode --input "$W/config_block.pb" --type common.Block --output "$W/config_block.json"
python3 - "$WORK" "$CRL" <<'PY'
import base64, json, sys
work, crl_file = sys.argv[1], sys.argv[2]
block = json.load(open(f"{work}/config_block.json"))
cfg = block["data"]["data"][0]["payload"]["data"]["config"]
json.dump(cfg, open(f"{work}/config.json", "w"))
crl = base64.b64encode(open(crl_file, "rb").read()).decode()
msp = cfg["channel_group"]["groups"]["Application"]["groups"]["InstAMSP"]["values"]["MSP"]["value"]["config"]
lst = msp.get("revocation_list") or []
if crl not in lst:
    lst.append(crl)
msp["revocation_list"] = lst
json.dump(cfg, open(f"{work}/modified.json", "w"))
PY
admin configtxlator proto_encode --input "$W/config.json" --type common.Config --output "$W/config.pb"
admin configtxlator proto_encode --input "$W/modified.json" --type common.Config --output "$W/modified.pb"
if ! admin configtxlator compute_update --channel_id "$CHANNEL" --original "$W/config.pb" --updated "$W/modified.pb" --output "$W/update.pb" 2>/dev/null; then
  echo "   채널 설정에 이미 같은 CRL 이 있다(변경 없음)"
  exit 0
fi
admin configtxlator proto_decode --input "$W/update.pb" --type common.ConfigUpdate --output "$W/update.json"
python3 - "$WORK" "$CHANNEL" <<'PY'
import json, sys
work, channel = sys.argv[1], sys.argv[2]
u = json.load(open(f"{work}/update.json"))
env = {"payload": {"header": {"channel_header": {"channel_id": channel, "type": 2}}, "data": {"config_update": u}}}
json.dump(env, open(f"{work}/envelope.json", "w"))
PY
admin configtxlator proto_encode --input "$W/envelope.json" --type common.Envelope --output "$W/envelope.pb"
admin peer channel update -f "$W/envelope.pb" -c "$CHANNEL" -o orderer.example.com:7050 --tls --cafile "$ORDERER_CA" >/dev/null 2>&1
echo "   채널 $CHANNEL 설정 갱신: InstAMSP revocation_list 에 $(basename "$CRL") 추가"
