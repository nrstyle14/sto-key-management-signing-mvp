#!/usr/bin/env bash
# 요건 대응표(docs/05)의 코드 경로와 테스트 이름이 실제로 있는지 확인한다(작업지시서 T4.6 완료 기준).
#   - 백틱 안의 경로(internal/…, cmd/…, scripts/…, contracts/…, deploy/…, test/…)는 파일·디렉터리가 있어야 한다.
#   - 백틱 안의 Test…(Go)·test_…/testFuzz_…(Foundry) 이름은 시험 파일에 정의돼 있어야 한다.
set -euo pipefail
cd "$(dirname "$0")/.."
DOC="${1:-docs/05_요건_대응표.md}"
fail=0
paths=0
tests=0
while read -r p; do
  paths=$((paths + 1))
  [ -e "$p" ] || { echo "없는 경로: $p" >&2; fail=1; }
done < <(grep -oE '`(internal|cmd|scripts|contracts|deploy|test)/[^` ]+`' "$DOC" | tr -d '`' | sort -u)
while read -r t; do
  tests=$((tests + 1))
  case "$t" in
    Test*) grep -rqE "^func $t\(" --include='*_test.go' internal cmd test scripts || { echo "없는 Go 시험: $t" >&2; fail=1; } ;;
    *) grep -qE "function $t\(" contracts/test/*.sol || { echo "없는 Foundry 시험: $t" >&2; fail=1; } ;;
  esac
done < <(grep -oE '`(Test[A-Za-z0-9_]+|test_[A-Za-z0-9_]+|testFuzz_[A-Za-z0-9_]+)`' "$DOC" | tr -d '`' | sort -u)
[ "$fail" = 0 ] || exit 1
echo "요건 대응표 확인 통과: 경로 ${paths}개, 시험 ${tests}개가 실제로 있다($DOC)"
