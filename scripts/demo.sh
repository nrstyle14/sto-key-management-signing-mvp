#!/usr/bin/env bash
# 전체 시연(작업지시서 T4.4, NFR-6). `make up && make migrate && make demo` 로 사람 개입 없이 끝까지 돈다.
#
#   ① 정상 흐름: 종목 배포 → 연계장부 계좌 A(inst-a)·B(inst-b) 등록 → 화이트리스트 추가 → 발행 → 계좌대체 → 보유 수량
#   ② 거부 사례 다섯 가지: 승인 부족, 자기 승인, 한도 초과, 타 기관 키, calldata 바꿔치기
#   ③ 키 교체: 기관 A 발행 키 교체 → 새 키로 발행
#   ④ 도난 대응: 기관 A 대체 키 동결 → 역할 회수 → 유통 정지 → 새 키 → 재개 → 폐기(scripts/incident-key-compromise.sh)
#   ⑤ 감사 검증과 변조 탐지: 체크포인트 → 두 체인 검증 → 서버 계정 UPDATE 거부, 관리 계정 변조(복사본) 탐지
#   ⑥ 대사 불일치 탐지: 대사 일치 → 연계장부 수량 착오기재 → 그 계좌 불일치 보고 → 되돌림 → 일치
#
# 승인자·보안관리자 키 암호는 시연 편의로 deploy/secrets 파일에서 읽는다(설계서 14절). 비밀 값은 출력하지 않는다.
# 각 단계는 기대한 결과가 아니면 멈춘다(종료 코드 1). 실행마다 새 종목 코드·계좌번호를 쓴다.
set -euo pipefail
cd "$(dirname "$0")/.."

STOCTL="${STOCTL:-bin/stoctl}"
export STOCTL
[ -x "$STOCTL" ] || { echo "stoctl 이 없다: make build 먼저" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq 가 필요하다" >&2; exit 1; }
ATTACK=(go run ./scripts/demo-attack)

SFX="$(date -u +%H%M%S)$(printf '%02X' $((RANDOM % 256)))"
CODE="KRDM${SFX}"
ACC_A="DM-A-${SFX}"
ACC_B="DM-B-${SFX}"
SEC=(--approver sec-02 --approver sec-03)
declare -a SUMMARY
T0=$(date +%s)

hr() { printf '\n%s\n' "════════════════════════════════════════════════════════════════════════"; }
step() { hr; printf '%s\n' "$1"; hr; T=$(date +%s); }
ok() { printf '  ✔ %s\n' "$1"; }
done_step() { SUMMARY+=("$1|$(($(date +%s) - T))초|$2"); }
fail() { printf '  ✘ %s\n' "$1" >&2; exit 1; }
key() { echo "--key deploy/approvers/$1.json --password-file deploy/secrets/approver_$1_password"; }
approve() { # approve <request_id> <승인자...>
  local id="$1" a
  shift
  # shellcheck disable=SC2046
  for a in "$@"; do "$STOCTL" request approve "$id" $(key "$a") >/dev/null; done
}
draft() { # draft <기관> <용도> <함수> <인자> <기안자> → request_id (실패하면 오류 출력)
  "$STOCTL" request draft --institution "$1" --purpose "$2" --contract "$CONTRACT" --function "$3" --args "$4" --drafter "$5" | jq -r .request_id
}
wait_req() { "$STOCTL" request wait "$1" --timeout 120s; }
holding() { "$STOCTL" account holdings --security "$CODE" --account "$1" | awk '{print $3}'; }
wait_holding() { # wait_holding <계좌> <수량>
  local i
  for i in $(seq 1 60); do
    [ "$(holding "$1")" = "$2" ] && return 0
    sleep 0.5
  done
  fail "계좌 $1 보유 수량이 $2 가 되지 않았다(현재 $(holding "$1"))"
}

# ─────────────────────────────────────────────────────────────────────────
step "① 정상 흐름: 종목 배포 → 계좌 등록 → 발행 → 계좌대체"
out="$(./scripts/bootstrap-security.sh "$CODE" "시연 종목 $CODE")"
CONTRACT="$(sed -n 's/^CONTRACT=//p' <<<"$out")"
[ -n "$CONTRACT" ] || fail "종목 배포 실패"
ok "종목 $CODE 배포(DEPLOY, 플랫폼 관리 키) 확정: $CONTRACT, 역할 4건·기관 대응 3건 확정"

reg_a="$("$STOCTL" account register --account-no "$ACC_A" --institution inst-a --holder "시연 권리자 A" --security "$CODE" --drafter apr-a-01)"
reg_b="$("$STOCTL" account register --account-no "$ACC_B" --institution inst-b --holder "시연 권리자 B" --security "$CODE" --drafter apr-b-01)"
ADDR_A="$(jq -r .onchain_address <<<"$reg_a")"
ADDR_B="$(jq -r .onchain_address <<<"$reg_b")"
ok "연계장부 계좌 $ACC_A(inst-a) → 주소 $ADDR_A, $ACC_B(inst-b) → 주소 $ADDR_B (권리자 이름은 연계장부에만)"
for acc in "$ACC_A" "$ACC_B"; do
  "$STOCTL" policy whitelist-add --account "$acc" "${SEC[@]}" 2>&1 >/dev/null | sed 's/^/    /'
done
ok "보안관리자 sec-02·sec-03 서명으로 두 주소를 발행·대체 정책 화이트리스트에 추가"
approve "$(jq -r .request_id <<<"$reg_a")" apr-a-02 apr-a-03
approve "$(jq -r .request_id <<<"$reg_b")" apr-b-02 apr-b-03
wait_req "$(jq -r .request_id <<<"$reg_a")" >/dev/null
wait_req "$(jq -r .request_id <<<"$reg_b")" >/dev/null
ok "원장 계좌 등록 2건 확정(승인 2건씩, 기관 대체 키 서명)"

id="$(draft inst-a ISSUE "issue(address,uint256)" "$ADDR_A,1000" apr-a-01)"
approve "$id" apr-a-02 apr-a-03
r="$(wait_req "$id")"
ok "발행 $ACC_A +1000: $id CONFIRMED 블록 $(jq -r .block_number <<<"$r"), 서명 키 $(jq -r .signer_address <<<"$r")"
id="$(draft inst-a TRANSFER "transferByAgent(address,address,uint256)" "$ADDR_A,$ADDR_B,300" apr-a-01)"
approve "$id" apr-a-02 apr-a-03
r="$(wait_req "$id")"
ok "계좌대체 $ACC_A → $ACC_B 300: $id CONFIRMED 블록 $(jq -r .block_number <<<"$r")"
wait_holding "$ACC_A" 700
wait_holding "$ACC_B" 300
ok "연계장부 보유 수량(원장 이벤트 반영): $ACC_A 700, $ACC_B 300"
"$STOCTL" audit trail "$id" --require "api:REQUEST_SUBMITTED,api:APPROVAL_ADDED,api:REQUEST_SIGNED,signer:SIGN_TX,api:REQUEST_LEDGER_SUBMITTED,api:REQUEST_CONFIRMED" >/dev/null
ok "계좌대체 요청의 기안·승인·서명·확정이 두 감사 체인에 있다"
done_step "① 정상 흐름" "발행 1000·대체 300 확정, 보유 수량 A 700·B 300"

# ─────────────────────────────────────────────────────────────────────────
step "② 거부 사례 다섯 가지"
# 1. 승인 부족: 업무 서버는 승인 1건인 요청을 서명 서버로 보내지 않는다. 침해된 업무 서버가 직접 보내도 서명 서버가 거부한다.
id="$(draft inst-a ISSUE "issue(address,uint256)" "$ADDR_A,10" apr-a-01)"
approve "$id" apr-a-02
sleep 3
st="$("$STOCTL" request show "$id" | jq -r .status)"
[ "$st" = PENDING_APPROVAL ] || fail "승인 1건인데 상태가 $st"
"$STOCTL" audit trail "$id" | grep -q SIGN_TX && fail "승인 1건 요청이 서명됐다"
# shellcheck disable=SC2046
"$STOCTL" request reject "$id" $(key apr-a-03) >/dev/null
out="$("${ATTACK[@]}" insufficient-approvals --contract "$CONTRACT" --from "$ADDR_A" --to "$ADDR_B" --amount 1)" || fail "승인 1건 서명 요청이 거부되지 않았다"
sed 's/^/    /' <<<"$out" | grep -v REQUEST_ID
"$STOCTL" audit trail "$(sed -n 's/^REQUEST_ID=//p' <<<"$out")" --require "signer:SIGN_REJECTED" >/dev/null
ok "1. 승인 부족: 업무 서버에서는 승인 1/2 요청이 PENDING_APPROVAL 에 머물고, 서명 서버에 직접 보내면 6단계 APPROVAL_INSUFFICIENT(감사 SIGN_REJECTED)"

# 2. 자기 승인
id="$(draft inst-a ISSUE "issue(address,uint256)" "$ADDR_A,10" apr-a-01)"
# shellcheck disable=SC2046
if msg="$("$STOCTL" request approve "$id" $(key apr-a-01) 2>&1)"; then fail "기안자 자기 승인이 받아들여졌다"; fi
grep -q APPROVAL_SELF <<<"$msg" || fail "자기 승인 거부 사유가 다르다: $msg"
"$STOCTL" request reject "$id" $(key apr-a-02) >/dev/null
ok "2. 자기 승인: 기안자 apr-a-01 의 승인 → APPROVAL_SELF"

# 3. 한도 초과(정책 max_amount 100000)
if msg="$(draft inst-a ISSUE "issue(address,uint256)" "$ADDR_A,100001" apr-a-01 2>&1)"; then fail "한도 초과 기안이 받아들여졌다"; fi
grep -q POLICY_AMOUNT_EXCEEDED <<<"$msg" || fail "한도 초과 거부 사유가 다르다: $msg"
ok "3. 한도 초과: 발행 100001(한도 100000) 기안 → POLICY_AMOUNT_EXCEEDED"

# 4. 타 기관 키: 기관 B 대체 키로 기관 A 계좌에서 출고 → 컨트랙트가 기관 불일치로 거부(revert)
id="$(draft inst-b TRANSFER "transferByAgent(address,address,uint256)" "$ADDR_A,$ADDR_B,1" apr-b-01)"
approve "$id" apr-b-02 apr-b-03
r="$("$STOCTL" request wait "$id" --status FAILED --timeout 120s)" || fail "타 기관 키 계좌대체가 실패로 끝나지 않았다"
grep -q LEDGER_REVERTED <<<"$(jq -r .error <<<"$r")" || fail "타 기관 키 거부 사유가 다르다: $(jq -r .error <<<"$r")"
[ "$(holding "$ACC_A")" = 700 ] || fail "타 기관 키 시도 뒤 A 수량이 바뀌었다"
ok "4. 타 기관 키: inst-b 대체 키로 inst-a 계좌 출고 → 원장 revert(FAILED, LEDGER_REVERTED), A 수량 700 그대로"

# 5. calldata 바꿔치기(침해된 업무 서버 흉내)
out="$("${ATTACK[@]}" calldata-swap --contract "$CONTRACT" --from "$ADDR_A" --to "$ADDR_B" --amount 1 --swapped 99999)" || fail "calldata 바꿔치기가 거부되지 않았다"
sed 's/^/    /' <<<"$out" | grep -v REQUEST_ID
rid="$(sed -n 's/^REQUEST_ID=//p' <<<"$out")"
"$STOCTL" audit trail "$rid" --require "signer:SIGN_REJECTED" >/dev/null
ok "5. calldata 바꿔치기: 승인 수량 1, calldata 수량 99999 → 서명 서버 7단계 TX_CALLDATA_MISMATCH, 감사 SIGN_REJECTED"
done_step "② 거부 사례" "승인 부족·자기 승인·한도 초과·타 기관 키·calldata 바꿔치기 모두 거부"

# ─────────────────────────────────────────────────────────────────────────
step "③ 키 교체: 기관 A 발행 키"
old="$("$STOCTL" key list | awk '$3=="inst-a" && $4=="ISSUE" && $5=="ACTIVE" {print $1, $6}')"
# 승인 화면(intent 상세)은 줄이고 단계별 결과만 보여 준다.
"$STOCTL" key rotate --institution inst-a --purpose ISSUE --drafter sec-01 "${SEC[@]}" --reason "시연 정기 교체" |
  grep -Ev '^[[:space:]]*(요청 |원장 |컨트랙트 |함수 |인자 |기안자 |intent_hash |sec-0[0-9] (APPROVE|REJECT))' | sed 's/^/    /'
new="$("$STOCTL" key list | awk '$3=="inst-a" && $4=="ISSUE" && $5=="ACTIVE" {print $1, $6}')"
[ "$old" != "$new" ] || fail "ACTIVE 키가 바뀌지 않았다"
id="$(draft inst-a ISSUE "issue(address,uint256)" "$ADDR_A,50" apr-a-01)"
approve "$id" apr-a-02 apr-a-03
r="$(wait_req "$id")"
[ "$(jq -r .signer_address <<<"$r")" = "$(awk '{print $2}' <<<"$new")" ] || fail "새 키로 서명되지 않았다"
wait_holding "$ACC_A" 750
ok "이전 키 ${old%% *} RETIRED, 새 키 ${new%% *} ACTIVE. 새 키로 발행 50 확정 → $ACC_A 750"
done_step "③ 키 교체" "새 키 ${new%% *} 로 발행 확정"

# ─────────────────────────────────────────────────────────────────────────
step "④ 도난 대응: 기관 A 대체 키"
./scripts/incident-key-compromise.sh inst-a/TRANSFER | sed 's/^/    /'
ok "동결 → 탈취 키 시도 거부(KEY_FROZEN) → 역할 회수 → 유통 정지 → 새 키 → 재개 → 이전 키 폐기"
done_step "④ 도난 대응" "탈취 키 요청 거부, 새 키로 재개, 이전 키 폐기"

# ─────────────────────────────────────────────────────────────────────────
step "⑤ 감사 검증과 변조 탐지"
"$STOCTL" audit checkpoint >/dev/null
"$STOCTL" audit verify | sed 's/^/    /'
ok "두 감사 체인(signer, api)과 HSM 서명 체크포인트 검증 통과"
"${ATTACK[@]}" audit-tamper | sed 's/^/    /' || fail "감사로그 변조를 탐지하지 못했다"
ok "서버 계정은 감사로그를 고칠 수 없고, 관리 계정의 변조는 체인 검증이 그 seq 에서 찾는다(운영 로그는 그대로)"
done_step "⑤ 감사" "체인·체크포인트 검증 통과, 변조 탐지"

# ─────────────────────────────────────────────────────────────────────────
step "⑥ 대사 불일치 탐지"
"$STOCTL" recon run --security "$CODE" | sed 's/^/    /' || fail "변경 전 대사가 일치하지 않는다"
ok "대사 일치(계좌 잔고·총발행량·이벤트 재생)"
"${ATTACK[@]}" holding-skew --account "$ACC_B" --security "$CODE" --delta 13 | sed 's/^/    /'
set +e
rep="$("$STOCTL" recon run --security "$CODE")"
rc=$?
set -e
sed 's/^/    /' <<<"$rep"
[ "$rc" = 3 ] || fail "착오기재 뒤 대사가 불일치를 보고하지 않았다(종료 코드 $rc)"
grep -q "BALANCE .*$ACC_B" <<<"$rep" && grep -q "EVENT_REPLAY .*$ACC_B" <<<"$rep" && grep -q TOTAL_SUPPLY <<<"$rep" || fail "불일치 보고가 기대와 다르다"
[ "$(grep -c "$ACC_A" <<<"$rep" || true)" = 0 ] || fail "바꾸지 않은 계좌 $ACC_A 가 보고됐다"
ok "착오기재한 $ACC_B 만 BALANCE·EVENT_REPLAY 불일치, 총발행량 차이 13 보고, 알람 TOTAL_MISMATCH"
"${ATTACK[@]}" holding-skew --account "$ACC_B" --security "$CODE" --delta -13 | sed 's/^/    /'
"$STOCTL" recon run --security "$CODE" >/dev/null || fail "되돌린 뒤 대사가 일치하지 않는다"
ok "되돌린 뒤 대사 일치"
done_step "⑥ 대사" "착오기재 계좌·차이를 정확히 보고"

# ─────────────────────────────────────────────────────────────────────────
hr
echo "시연 결과 (종목 $CODE, 계좌 $ACC_A·$ACC_B, 전체 $(($(date +%s) - T0))초)"
for row in "${SUMMARY[@]}"; do
  IFS='|' read -r name dt what <<<"$row"
  printf '  ✔ %-14s %6s  %s\n' "$name" "$dt" "$what"
done
echo "읽기 전용 웹: http://127.0.0.1:9080/"
