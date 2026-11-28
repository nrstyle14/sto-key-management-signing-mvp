-- Fabric 어댑터(설계서 10.5·12.1, D-26).
-- 키 곡선(SECP256K1, P256). P-256 키(Fabric 신원)는 EVM 주소가 없다.
ALTER TABLE `keys`
  ADD COLUMN curve VARCHAR(16) NOT NULL DEFAULT 'SECP256K1' COMMENT 'SECP256K1, P256' AFTER backend,
  MODIFY COLUMN address CHAR(42) NULL;
-- 요청 하나에 서명 종류별 1회(EVM_TX, PROPOSAL, TRANSACTION, COMMIT). 기존 행은 EVM_TX 다.
ALTER TABLE signatures
  ADD COLUMN kind VARCHAR(16) NOT NULL DEFAULT 'EVM_TX' AFTER request_id,
  DROP PRIMARY KEY,
  ADD PRIMARY KEY (request_id, kind);
-- Fabric 신원 인증서(키당 하나, 재발급은 새 키).
CREATE TABLE fabric_identities (
  key_id        VARCHAR(64)  NOT NULL,
  msp_id        VARCHAR(64)  NOT NULL,
  enrollment_id VARCHAR(64)  NOT NULL,
  cert_pem      TEXT         NOT NULL,
  serial        VARCHAR(80)  NOT NULL COMMENT '16진수',
  aki           VARCHAR(80)  NOT NULL COMMENT '16진수',
  not_after     DATETIME(6)  NOT NULL,
  status        VARCHAR(16)  NOT NULL COMMENT 'ENROLLED, REVOKED',
  crl_sha256    BINARY(32)   NULL,
  created_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  revoked_at    DATETIME(6)  NULL,
  PRIMARY KEY (key_id),
  UNIQUE KEY uk_fabric_identities_serial (aki, serial),
  CONSTRAINT fk_fabric_identities_key FOREIGN KEY (key_id) REFERENCES `keys` (key_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- Fabric 서명(PROPOSAL)은 다음 종류(TRANSACTION, COMMIT)의 대조에 쓸 원문(ProposalBytes)을 남긴다.
ALTER TABLE signatures ADD COLUMN payload MEDIUMBLOB NULL AFTER signed_tx;
