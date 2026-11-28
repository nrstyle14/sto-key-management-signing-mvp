#!/bin/sh
# Fabric CA 기동(T5.2). InstAMSP 루트 CA 키(cryptogen)로 뜨고, registrar 비밀번호는 Docker secret 에서 읽는다.
set -eu
PW="$(cat /run/secrets/fabric_ca_registrar_password)"
exec fabric-ca-server start -b "registrar:${PW}" \
  --ca.certfile /ca/ca.insta.example.com-cert.pem --ca.keyfile /ca/priv_sk --port 7054
