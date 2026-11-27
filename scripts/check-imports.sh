#!/usr/bin/env bash
# import 경계 검사(작업지시서 보안 규칙, 설계서 6.4·10.3). 직접·간접 의존을 모두 보기 위해 go list -deps 를 쓴다.
#   1. 업무 서버(cmd/apid)와 그 의존 패키지는 internal/hsm 을 import 하지 않는다.
#   2. 서명 서버(cmd/signerd)는 원장 노드에 접속하는 코드(JSON-RPC 클라이언트, 원장 어댑터)를 링크하지 않는다.
set -euo pipefail

MODULE="$(go list -m)"
fail=0

check() { # check <대상> <금지 패턴(정규식)> <설명>
  local target="$1" pattern="$2" what="$3"
  if go list -deps "$target" | grep -E "$pattern" >/dev/null; then
    echo "import 경계 위반: ${target} 가 ${what} 에 의존한다" >&2
    go list -deps "$target" | grep -E "$pattern" >&2 || true
    fail=1
  else
    echo "import 경계 검사 통과: ${target} 는 ${what} 에 의존하지 않는다"
  fi
}

check ./cmd/apid "^${MODULE}/internal/hsm(/|$)" "${MODULE}/internal/hsm"
check ./cmd/signerd "^(github.com/ethereum/go-ethereum/(ethclient|rpc)|${MODULE}/internal/ledger/besu)(/|$)" "원장 RPC 클라이언트(ethclient, rpc, internal/ledger/besu)"

exit "$fail"
