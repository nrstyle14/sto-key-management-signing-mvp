#!/usr/bin/env bash
# 종목 하나를 배포하고 기관 키에 역할을 부여한다(작업지시서 T3.3, 설계서 2절·10.2).
#
# 모든 단계는 승인이 붙은 요청이다. 배포는 플랫폼 CONTRACT_ADMIN 키로 서명되고, 서명 서버가 배포 바이트코드
# 해시(intent 의 code_hash)와 생성자 인자를 대조한다(5.3 의 7단계, D-19).
#   1. 종목 배포(DEPLOY) → 확정 → 컨트랙트 주소
#   2. 역할 부여: 기관 A 발행 키 ISSUER, 기관 A·B 대체 키 TRANSFER_AGENT, 플랫폼 비상 통제 키 CONTROLLER
#   3. 기관 대응: 기관 A 발행·대체 키 → inst-a, 기관 B 대체 키 → inst-b (D-17)
#   4. 원장에서 역할·기관 대응을 읽어 확인하고, 요청마다 두 감사 체인의 기록을 확인한다
# 키는 레지스트리의 "기관/용도" ACTIVE 키로 찾는다(키 교체 뒤에도 같은 스크립트를 쓴다).
#
# 사용: scripts/bootstrap-security.sh [종목코드] [종목명]
# 출력: 마지막 줄에 "CONTRACT=<주소>"
# 기안자는 sec-01, 승인자는 sec-02·sec-03(플랫폼 보안관리자, 시연용 키 파일과 암호 파일, 설계서 14절).
set -euo pipefail
cd "$(dirname "$0")/.."

CODE="${1:-KRDEMO$(date -u +%H%M%S)}"
NAME="${2:-데모 채권 ${CODE}}"
STOCTL="${STOCTL:-bin/stoctl}"
DRAFTER=sec-01
APPROVERS=(sec-02 sec-03)
[ -x "$STOCTL" ] || { echo "stoctl 이 없다: make build 먼저" >&2; exit 1; }

approve() { # approve <request_id>
  local a
  for a in "${APPROVERS[@]}"; do
    "$STOCTL" request approve "$1" --key "deploy/approvers/$a.json" --password-file "deploy/secrets/approver_${a}_password" >/dev/null
  done
}

ids=()
step() { # step <설명> <stoctl security 하위 명령과 인자...>: 기안 → 승인 2건, 요청 ID 를 ids 에 넣는다
  local what="$1"; shift
  local id
  id="$("$STOCTL" security "$@" --drafter "$DRAFTER")"
  approve "$id"
  ids+=("$id")
  printf '  %-44s %s\n' "$what" "$id"
}

echo "1. 종목 배포 요청: $CODE ($NAME)"
step "DEPLOY $CODE" deploy --code "$CODE" --name "$NAME"
contract="$("$STOCTL" request wait "${ids[0]}" --timeout 120s | jq -r .contract_address)"
if [ -z "$contract" ] || [ "$contract" = "null" ]; then
  echo "배포 결과에 컨트랙트 주소가 없다" >&2
  exit 1
fi
echo "   배포 확정: $contract"

echo "2. 역할 부여 요청"
step "ISSUER ← inst-a/ISSUE" grant-role --contract "$contract" --role ISSUER --key inst-a/ISSUE
step "TRANSFER_AGENT ← inst-a/TRANSFER" grant-role --contract "$contract" --role TRANSFER_AGENT --key inst-a/TRANSFER
step "TRANSFER_AGENT ← inst-b/TRANSFER" grant-role --contract "$contract" --role TRANSFER_AGENT --key inst-b/TRANSFER
step "CONTROLLER ← platform/EMERGENCY" grant-role --contract "$contract" --role CONTROLLER --key platform/EMERGENCY
echo "3. 기관 대응 요청"
step "inst-a/ISSUE → inst-a" set-agent --contract "$contract" --key inst-a/ISSUE
step "inst-a/TRANSFER → inst-a" set-agent --contract "$contract" --key inst-a/TRANSFER
step "inst-b/TRANSFER → inst-b" set-agent --contract "$contract" --key inst-b/TRANSFER

echo "4. 확정 대기와 확인"
for id in "${ids[@]:1}"; do
  "$STOCTL" request wait "$id" --timeout 120s >/dev/null
done
"$STOCTL" security roles --contract "$contract" --require \
  "platform/CONTRACT_ADMIN=DEFAULT_ADMIN,inst-a/ISSUE=ISSUER,inst-a/TRANSFER=TRANSFER_AGENT,inst-b/TRANSFER=TRANSFER_AGENT,platform/EMERGENCY=CONTROLLER,inst-a/ISSUE=@inst-a,inst-a/TRANSFER=@inst-a,inst-b/TRANSFER=@inst-b"

# 요청마다 기안 → 승인 2건 → 서명(서명 서버) → 제출 → 확정이 두 감사 체인에 남았는지 확인한다.
need="api:REQUEST_SUBMITTED,api:APPROVAL_ADDED,api:REQUEST_APPROVED,api:REQUEST_SIGNED,api:REQUEST_LEDGER_SUBMITTED,api:REQUEST_CONFIRMED,signer:SIGN_TX"
for id in "${ids[@]}"; do
  "$STOCTL" audit trail "$id" --require "$need" >/dev/null
done
"$STOCTL" audit trail "$CODE" --require "api:SECURITY_REGISTERED" >/dev/null
echo "   감사 기록 확인: 요청 ${#ids[@]}건 모두 기안·승인·서명·제출·확정 기록, 종목 등록 기록"
"$STOCTL" audit verify >/dev/null
echo "   감사 체인·체크포인트 검증 통과"
echo "CONTRACT=$contract"
