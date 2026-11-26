#!/usr/bin/env bash
# HSM 통합 테스트를 SoftHSM2 가 든 컨테이너에서 실행한다(T1.2, T1.3).
# - 토큰 저장소는 tmpfs 로 매번 새로 만든다. 서명 서버(signerd)의 토큰 볼륨은 쓰지 않는다.
# - T1.3 의 "HSM 서명 tx 확정" 시험을 위해 이 시험 컨테이너만 Besu 네트워크에 붙는다.
#   서명 서버(signerd) 서비스는 원장 네트워크에 붙지 않는다.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="sto-kms/hsmtest:dev"
PKGS="${HSM_TEST_PKGS:-./internal/hsm/... ./internal/signer/...}"

docker build -q --target hsmtest -f "$ROOT/deploy/signerd/Dockerfile" -t "$IMAGE" "$ROOT" >/dev/null
# shellcheck disable=SC2086
docker run --rm \
  --network sto-kms_besu \
  --tmpfs /var/lib/softhsm/tokens:rw,mode=0700 \
  -v "$ROOT:/src:ro" \
  -v sto-kms-gomod:/go/pkg/mod \
  -v sto-kms-gocache:/root/.cache/go-build \
  -e STO_TEST_RPC=http://besu-node1:8545 \
  "$IMAGE" go test -count=1 -tags integration $PKGS
