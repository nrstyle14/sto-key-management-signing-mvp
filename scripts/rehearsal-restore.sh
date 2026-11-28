#!/usr/bin/env bash
# 루트 키 백업·복구 리허설(작업지시서 T3.6, 설계서 6.3, FR-5.4).
#
#   1. 래핑 키 의식: stoctl 이 AES-256 래핑 키를 만들고 Shamir 2-of-3 조각을 보관자별 파일로 내보낸 뒤
#      보안관리자 2명 서명으로 플랫폼 토큰에 추출 불가 객체로 넣는다(deploy/ceremony/, 커밋 금지).
#   2. 백업: 플랫폼 루트 키(CONTRACT_ADMIN, EMERGENCY)를 C_WrapKey 해 백업 파일로 저장한다(deploy/backups/, 커밋 금지).
#   3. 복구: 서명 서버 이미지의 일회용 컨테이너(네트워크 없음, tmpfs 토큰 저장소 = 빈 토큰)에서 조각 2개로 래핑 키를
#      복원·주입하고 루트 키를 C_UnwrapKey 로 복원한 뒤, 복원한 키로 서명해 같은 주소가 나오는지 확인한다.
#      운영 토큰 볼륨은 건드리지 않는다.
#   4. 조각 1개로는 복구가 실패하는지 확인한다.
#   5. 결과를 docs/증빙/복구리허설_YYYYMMDD.md 로 남긴다(키·조각·PIN 은 기록하지 않는다).
set -euo pipefail
cd "$(dirname "$0")/.."

STOCTL="${STOCTL:-bin/stoctl}"
IMAGE="${SIGNERD_IMAGE:-sto-kms/signerd:dev}"
SEC=(--approver sec-02 --approver sec-03)
DAY="$(date -u +%Y%m%d)"
DOC="docs/증빙/복구리허설_${DAY}.md"
[ -x "$STOCTL" ] || { echo "stoctl 이 없다: make build 먼저" >&2; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "서명 서버 이미지 $IMAGE 가 없다: make up 먼저" >&2; exit 1; }
t0=$(date +%s)

echo "1. 래핑 키 의식(2-of-3)"
cer="$("$STOCTL" key ceremony --institution platform --threshold 2 \
  --custodian custodian-1 --custodian custodian-2 --custodian custodian-3 "${SEC[@]}")"
grep -v '^\(WRAP_KEY\|SHARES_DIR\)=' <<<"$cer" | sed 's/^/   /'
WRAP="$(sed -n 's/^WRAP_KEY=//p' <<<"$cer")"
SHARES="$(sed -n 's/^SHARES_DIR=//p' <<<"$cer")"
CEREMONY="$(basename "$SHARES" | tr '[:lower:]' '[:upper:]')"

echo "2. 루트 키 백업"
keys="$("$STOCTL" key list)"
BK="deploy/backups/${DAY}-$(basename "$SHARES")"
backup_args=()
declare -a want_addr
for purpose in CONTRACT_ADMIN EMERGENCY; do
  line="$(awk -v p="$purpose" '$2=="besu-local" && $3=="platform" && $4==p && $5=="ACTIVE"' <<<"$keys")"
  [ "$(wc -l <<<"$line" | tr -d ' ')" = 1 ] && [ -n "$line" ] || { echo "플랫폼 $purpose ACTIVE 키가 하나가 아니다" >&2; exit 1; }
  kid="$(awk '{print $1}' <<<"$line")"
  addr="$(awk '{print $6}' <<<"$line")"
  out="$("$STOCTL" key backup --key "$kid" --wrap-key "$WRAP" --out "$BK/$kid.json" "${SEC[@]}")"
  sed -n 's/^\(백업 .*\)$/   \1/p' <<<"$out"
  backup_args+=(--backup "/in/backups/$kid.json")
  want_addr+=("$kid=$addr")
done

run_rehearsal() { # run_rehearsal <조각 파일 이름...>
  local args=() s
  for s in "$@"; do args+=(--share "/in/shares/$s.share"); done
  docker run --rm --network none \
    --tmpfs /var/lib/softhsm/tokens:rw,mode=1777 \
    -v "$PWD/$BK:/in/backups:ro" -v "$PWD/$SHARES:/in/shares:ro" \
    "$IMAGE" rehearse-restore "${backup_args[@]}" "${args[@]}"
}

echo "3. 빈 토큰에 복구(조각 custodian-1, custodian-3)"
t1=$(date +%s)
res="$(run_rehearsal custodian-1 custodian-3)"
t2=$(date +%s)
jq -r '"   토큰 \(.token), 래핑 키 \(.wrap_key_id), 조각 \(.custodians_used|join(",")) (\(.threshold)-of-\(.total)), \(.mechanism)"' <<<"$res"
jq -r '.keys[] | "   \(.key_id) \(.purpose): 백업 \(.backup_address) → 복원 \(.restored_address) 주소일치=\(.address_match) 서명검증=\(.signature_valid) 객체=\(.objects)"' <<<"$res"
[ "$(jq -r .ok <<<"$res")" = true ] || { echo "복구 확인 실패" >&2; exit 1; }
for kv in "${want_addr[@]}"; do
  kid="${kv%%=*}"; addr="${kv#*=}"
  got="$(jq -r --arg k "$kid" '.keys[] | select(.key_id==$k) | .restored_address' <<<"$res")"
  [ "$got" = "$addr" ] || { echo "$kid 복원 주소 $got 가 레지스트리 주소 $addr 와 다르다" >&2; exit 1; }
done
echo "   레지스트리 주소와 일치"

echo "4. 조각 1개로 복구 시도(실패해야 한다)"
if one="$(run_rehearsal custodian-2 2>&1)"; then
  echo "조각 1개로 복구됐다" >&2
  exit 1
fi
onemsg="$(grep -o '조각 1개로는 복구할 수 없다[^"]*' <<<"$one" | head -1)"
[ -n "$onemsg" ] || { echo "조각 1개 시도의 실패 사유가 예상과 다르다: $one" >&2; exit 1; }
echo "   거부: $onemsg"

# 감사 기록(서명 서버 체인): 의식·백업
"$STOCTL" audit trail "$WRAP" --require "signer:KEY_WRAP_INSTALLED" >/dev/null
trail="$("$STOCTL" audit trail "$WRAP")"
for kv in "${want_addr[@]}"; do
  "$STOCTL" audit trail "${kv%%=*}" --require "signer:KEY_BACKED_UP" >/dev/null
done
backups_audit="$(for kv in "${want_addr[@]}"; do "$STOCTL" audit trail "${kv%%=*}" | grep KEY_BACKED_UP | tail -1; done)"
softhsm="$(docker run --rm --network none --entrypoint sh "$IMAGE" -c 'dpkg-query -W -f "\${Version}" softhsm2' 2>/dev/null || echo 확인 불가)"
t3=$(date +%s)

mkdir -p "$(dirname "$DOC")"
{
  echo "# 복구 리허설 ${DAY}"
  echo
  echo "> 작업지시서 T3.6, 설계서 6.3, FR-5.4. \`scripts/rehearsal-restore.sh\`가 생성했다. 키·조각·PIN 값은 기록하지 않는다."
  echo
  echo "## 환경"
  echo
  echo "| 항목 | 값 |"
  echo "|---|---|"
  echo "| 실행 시각(UTC) | $(jq -r .started_at <<<"$res") |"
  echo "| HSM | SoftHSM2 ${softhsm} (서명 서버 이미지 \`${IMAGE}\`) |"
  echo "| 복구 환경 | 일회용 컨테이너, 네트워크 없음, tmpfs 토큰 저장소에 새로 초기화한 빈 토큰 \`$(jq -r .token <<<"$res")\` |"
  echo "| 래핑 메커니즘 | $(jq -r .mechanism <<<"$res") (AES-256 래핑 키, D-11) |"
  echo "| 래핑 키 | \`${WRAP}\` (의식 ${CEREMONY}) |"
  echo "| 조각 | Shamir $(jq -r .threshold <<<"$res")-of-$(jq -r .total <<<"$res"), 보관자별 파일 \`${SHARES}/*.share\` (0600, 커밋 금지) |"
  echo "| 사용한 조각 | $(jq -r '.custodians_used|join(", ")' <<<"$res") |"
  echo "| 백업 파일 | \`${BK}/\` (커밋 금지) |"
  echo
  echo "## 절차와 결과"
  echo
  echo "1. 래핑 키 의식: stoctl 메모리에서 래핑 키 생성 → 2-of-3 분할, 보관자 3명 파일 → 보안관리자 2명(sec-02, sec-03) 서명으로 플랫폼 토큰에 추출 불가 객체로 주입."
  echo "2. 백업: 플랫폼 루트 키 2개를 \`C_WrapKey\`로 백업 파일에 저장(보안관리자 2명 서명)."
  echo "3. 복구: 빈 토큰을 새로 초기화 → 조각 2개로 래핑 키 복원(약속값 SHA-256 대조) → 주입 → \`C_UnwrapKey\`로 루트 키 복원 → 공개키 객체 생성 → 복원한 키로 무작위 다이제스트에 서명 → 공개키 복구로 주소 확인."
  echo "4. 조각 1개로 복구 시도 → 거부."
  echo
  echo "| 키 | 용도 | 레지스트리·백업 주소 | 복원 키 서명에서 복구한 주소 | 주소 일치 | 서명 검증 | 복원 객체 수 | 소요(ms) |"
  echo "|---|---|---|---|---|---|---|---|"
  jq -r '.keys[] | "| `\(.key_id)` | \(.purpose) | \(.backup_address) | \(.restored_address) | \(.address_match) | \(.signature_valid) | \(.objects) | \(.millis) |"' <<<"$res"
  echo
  echo "- 조각 1개(custodian-2)로 복구 시도: 실패(\`${onemsg}\`)."
  echo "- 소요 시간: 의식·백업 $((t1 - t0))초, 빈 토큰 복구 $((t2 - t1))초, 전체 $((t3 - t0))초."
  echo
  echo "## 감사 기록(서명 서버 체인)"
  echo
  echo '```'
  echo "$trail"
  echo "$backups_audit"
  echo '```'
  echo
  echo "## 판정"
  echo
  echo "- 조각 2개로 빈 토큰에 복구한 루트 키가 원래 주소와 같고 서명이 검증된다: 통과"
  echo "- 조각 1개로는 복구되지 않는다: 통과"
} >"$DOC"
echo "5. 증빙: $DOC"
