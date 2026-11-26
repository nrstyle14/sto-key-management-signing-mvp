#!/bin/bash
# MySQL 최초 기동 시 한 번 실행된다(docker-entrypoint-initdb.d).
# 실행 권한이 있는 .sh 는 엔트리포인트가 별도 프로세스로 실행하므로, 엔트리포인트의 mysql 함수·배열에
# 기대지 않고 로컬 소켓으로 직접 접속한다.
# api, signer 스키마와 계정을 만든다. 비밀번호는 Docker secret 파일에서 읽고 출력하지 않는다.
#  - <schema>_migrator : 해당 스키마의 DDL·DML 전부(마이그레이션 전용)
#  - <schema>_app      : 서버용. 테이블 단위 권한은 마이그레이션 뒤 scripts/dbmigrate 가 부여한다
#                        (감사 테이블은 INSERT, SELECT 만 — NFR-2)
set -euo pipefail

read_secret() { tr -d '\n' < "/run/secrets/$1"; }

MYSQL_PWD="$(read_secret mysql_root_password)"
export MYSQL_PWD
API_MIGRATOR_PW="$(read_secret api_migrator_password)"
SIGNER_MIGRATOR_PW="$(read_secret signer_migrator_password)"
API_APP_PW="$(read_secret api_app_password)"
SIGNER_APP_PW="$(read_secret signer_app_password)"

run_sql() { mysql --protocol=socket -uroot "$@"; }

# 비밀번호가 명령행 인자에 남지 않도록 표준 입력으로 SQL 을 넘긴다.
run_sql <<SQL
CREATE DATABASE IF NOT EXISTS api CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE DATABASE IF NOT EXISTS signer CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;

CREATE USER IF NOT EXISTS 'api_migrator'@'%' IDENTIFIED BY '${API_MIGRATOR_PW}';
CREATE USER IF NOT EXISTS 'signer_migrator'@'%' IDENTIFIED BY '${SIGNER_MIGRATOR_PW}';
CREATE USER IF NOT EXISTS 'api_app'@'%' IDENTIFIED BY '${API_APP_PW}';
CREATE USER IF NOT EXISTS 'signer_app'@'%' IDENTIFIED BY '${SIGNER_APP_PW}';

GRANT ALL PRIVILEGES ON api.* TO 'api_migrator'@'%';
GRANT ALL PRIVILEGES ON signer.* TO 'signer_migrator'@'%';
FLUSH PRIVILEGES;
SQL

n="$(run_sql -N -e "SELECT COUNT(*) FROM mysql.user WHERE user IN ('api_migrator','signer_migrator','api_app','signer_app')")"
if [ "$n" != "4" ]; then
  echo "계정 생성 확인 실패: $n/4" >&2
  exit 1
fi
echo "api, signer 스키마와 계정 4개 생성 완료"
