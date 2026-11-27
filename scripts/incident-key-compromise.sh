#!/usr/bin/env bash
# 키 분실·도난 대응 시나리오(작업지시서 T3.7, 설계서 9절, FR-5.5, B-4-1).
#
#   ① 키 동결(보안관리자 1인, 서명 서버 직접)
#   (탈취된 키로 시도: 승인 2건이 붙은 계좌대체 요청이 서명 서버 4단계에서 KEY_FROZEN 으로 거부돼야 한다)
#   ② 관리 키로 온체인 역할 회수(종목마다 역할 회수 + 기관 대응 해제)
#   ③ 비상 통제 키로 종목 유통 정지
#   ④ 새 키 생성(PENDING) → 역할 부여·기관 대응 → 이전 키 퇴역과 새 키 활성화
#   ⑤ 유통 재개(그리고 새 키로 계좌대체 확인)
#   ⑥ 이전 키 폐기(HSM 객체 삭제 확인)
# 각 단계의 소요 시간과 끝난 뒤의 감사로그 seq(signer, api)를 출력한다.
# 대상 종목은 이전 키가 역할을 가진 모든 종목이다. 시연 종목 하나를 새로 배포·발행해 함께 쓴다.
#
# 사용: scripts/incident-key-compromise.sh [기관/용도]   (기본 inst-a/TRANSFER)
# 기안자·승인자: 기관 업무 요청은 apr-a-01(기안)·apr-a-02·apr-a-03, 플랫폼 요청은 sec-01(기안)·sec-02·sec-03.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET="${1:-inst-a/TRANSFER}"
INST="${TARGET%/*}"
PURPOSE="${TARGET#*/}"
STOCTL="${STOCTL:-bin/stoctl}"
SEC=(--approver sec-02 --approver sec-03)
A1=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
B1=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
case "$PURPOSE" in
  TRANSFER) ROLE=TRANSFER_AGENT ;;
  ISSUE) ROLE=ISSUER ;;
  *) echo "지원하는 대상: <기관>/TRANSFER, <기관>/ISSUE" >&2; exit 2 ;;
esac
[ -x "$STOCTL" ] || { echo "stoctl 이 없다: make build 먼저" >&2; exit 1; }

now() { python3 -c 'import time; print(f"{time.time():.3f}")'; }
key() { echo "--key deploy/approvers/$1.json --password-file deploy/secrets/approver_$1_password"; }
approve() { # approve <request_id> <승인자...>
  local id="$1" a
  shift
  # shellcheck disable=SC2046
  for a in "$@"; do "$STOCTL" request approve "$id" $(key "$a") >/dev/null; done
}
platform() { # platform <용도> <컨트랙트> <함수> <인자> : 플랫폼 요청 기안·승인·확정
  local id
  id="$("$STOCTL" request draft --institution platform --purpose "$1" --contract "$2" --function "$3" --args "$4" --drafter sec-01 | jq -r .request_id)"
  approve "$id" sec-02 sec-03
  "$STOCTL" request wait "$id" --timeout 120s >/dev/null
  echo "$id"
}

declare -a REPORT
T=""
begin() { T="$(now)"; echo "$1"; }
finish() { # finish <단계 이름>
  local dt head
  dt="$(python3 -c "print(f'{$(now) - $T:.1f}')")"
  head="$("$STOCTL" audit head)"
  REPORT+=("$1|$dt|$head")
  echo "   → ${dt}초, 감사 ${head}"
}

echo "0. 준비: 시연 종목 배포·계좌 등록·발행"
DEMO_CODE="KRIR$(date -u +%H%M%S)"
out="$(./scripts/bootstrap-security.sh "$DEMO_CODE" "도난 대응 시연 $DEMO_CODE")"
DEMO="$(sed -n 's/^CONTRACT=//p' <<<"$out")"
./scripts/flow-issue-transfer.sh "$DEMO" 1000 100 >/dev/null
OLD_LINE="$("$STOCTL" key list | awk -v i="$INST" -v p="$PURPOSE" '$3==i && $4==p && $5=="ACTIVE"')"
OLD="$(awk '{print $1}' <<<"$OLD_LINE")"
OLD_ADDR="$(awk '{print $6}' <<<"$OLD_LINE")"
[ -n "$OLD" ] || { echo "$TARGET ACTIVE 키가 없다" >&2; exit 1; }
echo "   시연 종목 $DEMO_CODE $DEMO, 탈취된 것으로 보는 키 $OLD ($OLD_ADDR)"
AFFECTED=()
while IFS=$'\t' read -r code contract _; do
  [ -n "$code" ] || continue
  if "$STOCTL" security roles --contract "$contract" --require "$OLD=$ROLE" >/dev/null 2>&1; then
    AFFECTED+=("$code=$contract")
  fi
done < <("$STOCTL" security list)
echo "   이전 키가 $ROLE 역할을 가진 종목 ${#AFFECTED[@]}개"
grep -q "=$DEMO\$" <<<"$(printf '%s\n' "${AFFECTED[@]-}")" || { echo "시연 종목에서 이전 키의 역할을 찾지 못했다" >&2; exit 1; }
START="$(now)"

begin "① 키 동결(보안관리자 sec-01 1인)"
# shellcheck disable=SC2046
"$STOCTL" freeze key "$OLD" --reason "키 탈취 의심($TARGET)" $(key sec-01) | sed 's/^/   /'
finish "① 키 동결"

begin "   탈취된 키로 계좌대체 시도(승인 2건)"
ATTEMPT="$("$STOCTL" request draft --institution "$INST" --purpose "$PURPOSE" --contract "$DEMO" \
  --function "transferByAgent(address,address,uint256)" --args "$A1,$B1,1" --drafter apr-a-01 | jq -r .request_id)"
approve "$ATTEMPT" apr-a-02 apr-a-03
if r="$("$STOCTL" request wait "$ATTEMPT" --status FAILED --timeout 60s)"; then :; else echo "탈취 키 요청이 거부되지 않았다" >&2; exit 1; fi
err="$(jq -r .error <<<"$r")"
grep -q KEY_FROZEN <<<"$err" || { echo "거부 사유가 KEY_FROZEN 이 아니다: $err" >&2; exit 1; }
"$STOCTL" audit trail "$ATTEMPT" --require "signer:SIGN_REJECTED,api:REQUEST_FAILED" >/dev/null
REJECT_SEQ="$("$STOCTL" audit trail "$ATTEMPT" | awk '$1=="signer" && $5=="SIGN_REJECTED" {print $3}' | tail -1)"
echo "   거부: 요청 $ATTEMPT, $err (서명 서버 감사 seq $REJECT_SEQ)"
finish "탈취 키 시도 거부"

begin "② 관리 키로 온체인 역할 회수"
for kv in "${AFFECTED[@]}"; do
  code="${kv%%=*}"; c="${kv#*=}"
  id="$("$STOCTL" security grant-role --contract "$c" --role "$ROLE" --key "$OLD" --revoke true --drafter sec-01)"
  approve "$id" sec-02 sec-03
  "$STOCTL" request wait "$id" --timeout 120s >/dev/null
  id2="$("$STOCTL" security set-agent --contract "$c" --key "$OLD" --clear --drafter sec-01)"
  approve "$id2" sec-02 sec-03
  "$STOCTL" request wait "$id2" --timeout 120s >/dev/null
  echo "   $code: revokeRole $ROLE $id, 기관 대응 해제 $id2"
done
finish "② 역할 회수"

begin "③ 비상 통제 키로 유통 정지"
for kv in "${AFFECTED[@]}"; do
  echo "   ${kv%%=*}: setCirculation(false) $(platform EMERGENCY "${kv#*=}" "setCirculation(bool)" false)"
done
finish "③ 유통 정지"

begin "④ 새 키 투입"
gen="$("$STOCTL" key generate --institution "$INST" --purpose "$PURPOSE" --rotated-from "$OLD" --reason "탈취 대응 새 키" "${SEC[@]}")"
NEW="$(jq -r .key_id <<<"$gen")"
NEW_ADDR="$(jq -r .address <<<"$gen")"
echo "   새 키 $NEW ($NEW_ADDR) $(jq -r .status <<<"$gen")"
for kv in "${AFFECTED[@]}"; do
  c="${kv#*=}"
  id="$("$STOCTL" security grant-role --contract "$c" --role "$ROLE" --key "$NEW" --drafter sec-01)"
  approve "$id" sec-02 sec-03
  "$STOCTL" request wait "$id" --timeout 120s >/dev/null
  id2="$("$STOCTL" security set-agent --contract "$c" --key "$NEW" --institution "$INST" --drafter sec-01)"
  approve "$id2" sec-02 sec-03
  "$STOCTL" request wait "$id2" --timeout 120s >/dev/null
  echo "   ${kv%%=*}: grantRole $ROLE $id, 기관 대응 $id2"
done
ret="$("$STOCTL" key retire --key "$OLD" --successor "$NEW" --reason "탈취 키 퇴역" "${SEC[@]}")"
echo "   이전 키 $(jq -r .status <<<"$ret"), 새 키 $(jq -r .activated <<<"$ret") ACTIVE"
finish "④ 새 키 투입"

begin "⑤ 유통 재개"
for kv in "${AFFECTED[@]}"; do
  echo "   ${kv%%=*}: setCirculation(true) $(platform EMERGENCY "${kv#*=}" "setCirculation(bool)" true)"
done
if [ "$PURPOSE" = TRANSFER ]; then
  id="$("$STOCTL" request draft --institution "$INST" --purpose TRANSFER --contract "$DEMO" \
    --function "transferByAgent(address,address,uint256)" --args "$A1,$B1,1" --drafter apr-a-01 | jq -r .request_id)"
  approve "$id" apr-a-02 apr-a-03
  r="$("$STOCTL" request wait "$id" --timeout 120s)"
  [ "$(jq -r .signer_address <<<"$r")" = "$NEW_ADDR" ] || { echo "새 키로 서명되지 않았다" >&2; exit 1; }
  echo "   새 키로 계좌대체 확정: $id (서명자 $NEW_ADDR)"
fi
finish "⑤ 유통 재개"

begin "⑥ 이전 키 폐기"
des="$("$STOCTL" key destroy --key "$OLD" --reason "탈취 키 폐기" "${SEC[@]}")"
echo "   $OLD $(jq -r .status <<<"$des"), HSM 남은 객체 $(jq -r .objects_remaining <<<"$des")"
"$STOCTL" audit trail "$OLD" --require "signer:KEY_RETIRED,signer:KEY_DESTROYED" >/dev/null
finish "⑥ 이전 키 폐기"

"$STOCTL" audit verify >/dev/null
TOTAL="$(python3 -c "print(f'{$(now) - $START:.1f}')")"
echo
echo "단계별 소요 시간과 감사로그 위치(단계가 끝난 뒤 머리 seq)"
printf '  %-22s %8s  %s\n' "단계" "초" "감사 seq"
for row in "${REPORT[@]}"; do
  IFS='|' read -r name dt head <<<"$row"
  printf '  %-22s %8s  %s\n' "$name" "$dt" "$head"
done
echo "  합계(①~⑥) ${TOTAL}초"
echo "탈취 키 시도 거부 기록: 요청 $ATTEMPT, 서명 서버 감사 seq $REJECT_SEQ (SIGN_REJECTED, KEY_FROZEN)"
echo "OLD_KEY=$OLD NEW_KEY=$NEW DEMO=$DEMO"
