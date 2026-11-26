#!/usr/bin/env bash
# 업무 서버(cmd/apid)와 그것이 의존하는 패키지가 internal/hsm 을 import하지 않는지 검사한다.
# 직접·간접 의존을 모두 보기 위해 go list -deps 를 쓴다.
set -euo pipefail

MODULE="$(go list -m)"
FORBIDDEN="${MODULE}/internal/hsm"
TARGETS=("./cmd/apid")

fail=0
for t in "${TARGETS[@]}"; do
  if go list -deps "$t" | grep -E "^${FORBIDDEN}(/|$)" >/dev/null; then
    echo "import 경계 위반: ${t} 가 ${FORBIDDEN} 에 의존한다" >&2
    go list -deps -f '{{.ImportPath}}: {{join .Imports " "}}' "$t" | grep -E "${FORBIDDEN}" >&2 || true
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "import 경계 검사 통과: ${TARGETS[*]} 는 ${FORBIDDEN} 에 의존하지 않는다"
