#!/usr/bin/env bash
# 로컬 환경의 비밀 파일을 deploy/secrets/ 에 만든다(커밋 금지, .gitignore).
# 이미 있는 파일은 건드리지 않는다(멱등). 값은 화면에 출력하지 않는다.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/deploy/secrets"
NAMES=(
  mysql_root_password
  api_migrator_password
  signer_migrator_password
  api_app_password
  signer_app_password
  hsm_pin_platform
  hsm_so_pin_platform
  hsm_pin_inst-a
  hsm_so_pin_inst-a
  hsm_pin_inst-b
  hsm_so_pin_inst-b
  hsm_pin_audit
  hsm_so_pin_audit
  hsm_pin_fabric-inst-a
  hsm_so_pin_fabric-inst-a
  fabric_ca_registrar_password
)

mkdir -p "$DIR"
chmod 700 "$DIR"
umask 077
for n in "${NAMES[@]}"; do
  f="$DIR/$n"
  if [ ! -s "$f" ]; then
    # 16진수만 쓴다(DSN·SQL 인용 문제 방지). 24바이트 난수 = 48자.
    openssl rand -hex 24 | tr -d '\n' > "$f"
    echo "생성: deploy/secrets/$n"
  fi
done
# 비밀 파일은 소유자 전용(0600), 디렉터리는 0700 이다. Docker Desktop 은 바인드 마운트 파일을
# 컨테이너 사용자 소유로 보여 주므로 비 root 컨테이너(MySQL, signerd, apid)도 읽는다.
# Linux Docker Engine 에서는 파일 소유자를 각 컨테이너 uid 로 바꿔야 한다.
chmod 600 "$DIR"/*
