#!/usr/bin/env bash
# 로컬 CA 와 apid, signerd, stoctl 인증서를 deploy/certs/ 에 만든다(커밋 금지). 멱등.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
go run ./scripts/gen-certs -out deploy/certs
