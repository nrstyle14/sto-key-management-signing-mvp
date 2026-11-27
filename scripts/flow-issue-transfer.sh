#!/usr/bin/env bash
# 계좌 등록 → 발행 → 계좌대체를 stoctl 로 끝까지 수행한다(작업지시서 T3.4 완료 기준).
#
# 원장 순서는 등록이 먼저다(등록된 계좌만 보유·이전, 설계서 10.2).
#   1. 기관 A 대체 키로 계좌 A1 등록(기관 A 담당자 기안·승인 2건)
#   2. 기관 B 대체 키로 계좌 B1 등록(기관 B 담당자)
#   3. 기관 A 발행 키로 A1 에 발행
#   4. 기관 A 대체 키로 A1 → B1 계좌대체
# 각 요청의 CONFIRMED 를 기다리고, 끝에 보존된 이벤트(registry_events)에서 결과를 확인한다.
# 계좌 주소는 부트스트랩 정책의 화이트리스트 주소다(정책 변경 API 가 아직 없다, docs/01 미확정 항목).
#
# 사용: scripts/flow-issue-transfer.sh <종목 컨트랙트 주소> [발행 수량] [대체 수량]
set -euo pipefail
cd "$(dirname "$0")/.."

CONTRACT="${1:?종목 컨트랙트 주소가 필요하다}"
ISSUE="${2:-1000}"
MOVE="${3:-300}"
STOCTL="${STOCTL:-bin/stoctl}"
A1=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
B1=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC

key() { echo "--key deploy/approvers/$1.json --password-file deploy/secrets/approver_$1_password"; }

run() { # run <설명> <기관> <용도> <함수> <인자> <기안자> <승인자1> <승인자2>
  local what="$1" inst="$2" purpose="$3" fn="$4" args="$5" drafter="$6"
  local id
  id="$("$STOCTL" request draft --institution "$inst" --purpose "$purpose" --contract "$CONTRACT" \
    --function "$fn" --args "$args" --drafter "$drafter" | jq -r .request_id)"
  # shellcheck disable=SC2046
  "$STOCTL" request approve "$id" $(key "$7") >/dev/null
  # shellcheck disable=SC2046
  "$STOCTL" request approve "$id" $(key "$8") >/dev/null
  local r
  r="$("$STOCTL" request wait "$id" --timeout 120s)"
  printf '  %-40s %s block=%s tx=%s\n' "$what" "$id" "$(jq -r .block_number <<<"$r")" "$(jq -r .tx_hash <<<"$r")"
}

echo "종목 $CONTRACT"
run "계좌 등록 A1 (inst-a)" inst-a TRANSFER "registerAccount(address,string)" "$A1,inst-a" apr-a-01 apr-a-02 apr-a-03
run "계좌 등록 B1 (inst-b)" inst-b TRANSFER "registerAccount(address,string)" "$B1,inst-b" apr-b-01 apr-b-02 apr-b-03
run "발행 A1 +$ISSUE" inst-a ISSUE "issue(address,uint256)" "$A1,$ISSUE" apr-a-01 apr-a-02 apr-a-03
run "계좌대체 A1 → B1 $MOVE" inst-a TRANSFER "transferByAgent(address,address,uint256)" "$A1,$B1,$MOVE" apr-a-02 apr-a-01 apr-a-03

# 보존된 이벤트에 결과가 반영될 때까지 기다린다(수신 작업자 주기).
for _ in $(seq 1 40); do
  ev="$("$STOCTL" registry events --contract "$CONTRACT")"
  if grep -q "Transferred .*amount=$MOVE .*from=$A1 .*to=$B1" <<<"$ev"; then
    break
  fi
  sleep 0.5
done
echo "보존된 이벤트:"
sed 's/^/  /' <<<"$ev"
grep -q "AccountRegistered .*account=$A1 institutionId=inst-a" <<<"$ev"
grep -q "AccountRegistered .*account=$B1 institutionId=inst-b" <<<"$ev"
grep -q "Issued .*account=$A1 amount=$ISSUE" <<<"$ev"
grep -q "Transferred .*amount=$MOVE .*from=$A1 .*to=$B1" <<<"$ev"
echo "확인: 등록 2건, 발행, 계좌대체가 원장 이벤트로 보존됐다"
