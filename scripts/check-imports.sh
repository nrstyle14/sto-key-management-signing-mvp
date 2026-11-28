#!/usr/bin/env bash
# import 경계 검사(작업지시서 보안 규칙, 설계서 6.4·10.3). 직접·간접 의존을 모두 보기 위해 go list -deps 를 쓴다.
#   1. 업무 서버(cmd/apid)와 그 의존 패키지는 internal/hsm 을 import 하지 않는다.
#   2. 서명 서버(cmd/signerd)는 원장 노드에 접속하는 코드(JSON-RPC 클라이언트, 원장 어댑터)를 링크하지 않는다.
#   3. MPC 라이브러리(alice)는 MPC 노드(cmd/mpcd)만 링크한다. 서명 서버는 봉투를 중계만 한다(D-25).
#   4. MPC 노드(cmd/mpcd)는 HSM 과 원장 RPC 클라이언트를 링크하지 않는다.
#   5. 서명 서버는 Fabric proto 는 해석용으로 링크하지만 원장 접속 코드(fabric-gateway 클라이언트)는 링크하지 않는다(D-26).
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

check ./cmd/signerd "^github.com/hyperledger/fabric-gateway(/|$)" "Fabric 원장 접속 코드(github.com/hyperledger/fabric-gateway)"
check ./cmd/signerd "^github.com/getamis/alice(/|$)" "MPC 라이브러리(github.com/getamis/alice)"
check ./cmd/apid "^github.com/getamis/alice(/|$)" "MPC 라이브러리(github.com/getamis/alice)"
check ./cmd/mpcd "^(${MODULE}/internal/hsm|github.com/miekg/pkcs11|github.com/ethereum/go-ethereum/(ethclient|rpc)|${MODULE}/internal/ledger)(/|$)" "HSM·원장 RPC(internal/hsm, pkcs11, ethclient, rpc, internal/ledger)"

exit "$fail"
