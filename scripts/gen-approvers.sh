#!/usr/bin/env bash
# 시연용 승인자 키 파일과 부트스트랩 파일을 만든다(T2.2). 멱등.
# - 승인자별 암호는 deploy/secrets/approver_<ID>_password(0600), 키 파일은 deploy/approvers/<ID>.json(0600, 암호화).
#   둘 다 커밋 금지(.gitignore). 개인키와 암호는 화면에 출력하지 않는다.
# - deploy/signerd/bootstrap.tmpl.yaml 의 @key:<ID> 를 공개키로 채워 deploy/signerd/generated/bootstrap.yaml 을 만든다.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
APPROVERS=(apr-a-01 apr-a-02 apr-a-03 apr-b-01 apr-b-02 apr-b-03 sec-01 sec-02 sec-03)

mkdir -p deploy/secrets deploy/approvers
chmod 700 deploy/secrets deploy/approvers
go build -o bin/stoctl ./cmd/stoctl
for id in "${APPROVERS[@]}"; do
  pw="deploy/secrets/approver_${id}_password"
  key="deploy/approvers/${id}.json"
  if [ ! -s "$pw" ]; then
    (umask 077; openssl rand -hex 24 | tr -d '\n' > "$pw")
  fi
  chmod 600 "$pw"
  if [ ! -s "$key" ]; then
    ./bin/stoctl approver keygen --id "$id" --out "$key" --password-file "$pw" >/dev/null
    echo "승인자 키 생성: $id"
  fi
done
./bin/stoctl approver render-bootstrap --template deploy/signerd/bootstrap.tmpl.yaml --keys deploy/approvers \
  --out deploy/signerd/generated/bootstrap.yaml
echo "부트스트랩 파일: deploy/signerd/generated/bootstrap.yaml"
