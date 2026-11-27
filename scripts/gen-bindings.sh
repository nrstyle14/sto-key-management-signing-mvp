#!/usr/bin/env bash
# 컨트랙트를 컴파일하고 abigen 으로 Go 바인딩을 만든다(작업지시서 T3.1, make gen).
# abigen 은 go.mod 에 고정한 go-ethereum 버전으로 실행한다(모듈 의존성에 넣지 않으려고 @버전으로 실행).
# 바인딩은 커밋한다. 배포 바이트코드와 그 해시(배포 intent 의 code_hash)의 기준이다.
#
#   scripts/gen-bindings.sh          바인딩을 다시 만든다
#   scripts/gen-bindings.sh --check  다시 만든 결과가 커밋된 바인딩과 같은지만 확인한다
set -euo pipefail
cd "$(dirname "$0")/.."

check=0
[ "${1:-}" = "--check" ] && check=1

target=internal/ledger/besu/sectoken/sectoken.go
(cd contracts && forge build --force >/dev/null)

out=contracts/out/SecurityToken.sol/SecurityToken.json
work="$(mktemp -d)"
cleanup() { rm -f "$work"/SecurityToken.abi "$work"/SecurityToken.bin "$work"/sectoken.go; rmdir "$work"; }
trap cleanup EXIT
jq -c .abi "$out" >"$work/SecurityToken.abi"
jq -r .bytecode.object "$out" | sed 's/^0x//' >"$work/SecurityToken.bin"

gethver="$(go list -m -f '{{.Version}}' github.com/ethereum/go-ethereum)"
go run "github.com/ethereum/go-ethereum/cmd/abigen@${gethver}" \
  --abi "$work/SecurityToken.abi" --bin "$work/SecurityToken.bin" \
  --pkg sectoken --type SecurityToken \
  --out "$work/sectoken.go"

if [ "$check" -eq 1 ]; then
  if ! cmp -s "$work/sectoken.go" "$target"; then
    echo "바인딩이 컨트랙트 소스와 다르다: make gen 을 실행해" >&2
    exit 1
  fi
  echo "바인딩 확인: $target 이 컨트랙트 소스와 같다"
  exit 0
fi
mkdir -p "$(dirname "$target")"
cp "$work/sectoken.go" "$target"
echo "바인딩 생성: $target"
