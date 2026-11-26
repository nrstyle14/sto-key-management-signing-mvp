#!/bin/bash
# MySQL 헬스체크: 초기화 스크립트가 끝나 계정이 만들어지고 TCP 로 접속되는지 확인한다.
# (초기화 중의 임시 서버는 TCP 를 열지 않으므로 127.0.0.1 접속 성공이 곧 초기화 완료다.)
set -euo pipefail
export MYSQL_PWD="$(tr -d '\n' < /run/secrets/mysql_root_password)"
n="$(mysql -h127.0.0.1 -uroot -N -e "SELECT COUNT(*) FROM mysql.user WHERE user IN ('api_app','signer_app','api_migrator','signer_migrator')")"
[ "$n" = "4" ]
