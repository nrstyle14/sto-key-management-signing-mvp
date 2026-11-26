-- signer 스키마 초기 테이블(설계서 12.1)
-- 해시·서명 대상이 되는 JSON(payload_json, body_json)은 MySQL JSON 형식이 값을 재정렬하므로
-- 바이트를 그대로 보존하도록 utf8mb4_bin 텍스트로 저장한다.

CREATE TABLE hsm_tokens (
  token_id       VARCHAR(64)  NOT NULL,
  label          VARCHAR(64)  NOT NULL,
  ledger_id      VARCHAR(64)  NOT NULL,
  institution_id VARCHAR(64)  NOT NULL,
  status         VARCHAR(16)  NOT NULL,
  created_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (token_id),
  UNIQUE KEY uk_hsm_tokens_label (label),
  UNIQUE KEY uk_hsm_tokens_scope (ledger_id, institution_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `keys` (
  key_id       VARCHAR(64)   NOT NULL,
  token_id     VARCHAR(64)   NOT NULL,
  purpose      VARCHAR(32)   NOT NULL COMMENT 'ISSUE, TRANSFER, CONTRACT_ADMIN, EMERGENCY, AUDIT',
  class        VARCHAR(16)   NOT NULL COMMENT 'OPERATIONAL, ROOT, AUDIT',
  public_key   VARBINARY(65) NOT NULL COMMENT '비압축 secp256k1 공개키 65바이트',
  address      CHAR(42)      NOT NULL,
  status       VARCHAR(16)   NOT NULL COMMENT 'ACTIVE, FROZEN, RETIRED, DESTROYED',
  rotated_from VARCHAR(64)   NULL,
  created_at   DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  retired_at   DATETIME(6)   NULL,
  destroyed_at DATETIME(6)   NULL,
  PRIMARY KEY (key_id),
  UNIQUE KEY uk_keys_address (address),
  KEY ix_keys_lookup (token_id, purpose, status),
  CONSTRAINT fk_keys_token FOREIGN KEY (token_id) REFERENCES hsm_tokens (token_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE approvers (
  approver_id    VARCHAR(64)   NOT NULL,
  name           VARCHAR(128)  NOT NULL,
  institution_id VARCHAR(64)   NOT NULL,
  role           VARCHAR(32)   NOT NULL COMMENT 'DRAFTER, APPROVER, SECURITY_ADMIN',
  ed25519_pubkey VARBINARY(32) NOT NULL,
  status         VARCHAR(16)   NOT NULL,
  PRIMARY KEY (approver_id),
  UNIQUE KEY uk_approvers_pubkey (ed25519_pubkey)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE approver_groups (
  group_id    VARCHAR(64) NOT NULL,
  approver_id VARCHAR(64) NOT NULL,
  PRIMARY KEY (group_id, approver_id),
  CONSTRAINT fk_approver_groups_approver FOREIGN KEY (approver_id) REFERENCES approvers (approver_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE policies (
  policy_id      VARCHAR(64)  NOT NULL,
  version        INT UNSIGNED NOT NULL,
  ledger_id      VARCHAR(64)  NOT NULL,
  institution_id VARCHAR(64)  NOT NULL,
  key_purpose    VARCHAR(32)  NOT NULL,
  body_json      MEDIUMTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  status         VARCHAR(16)  NOT NULL,
  PRIMARY KEY (policy_id, version),
  KEY ix_policies_scope (ledger_id, institution_id, key_purpose, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE whitelists (
  policy_id       VARCHAR(64) NOT NULL,
  account_address CHAR(42)    NOT NULL,
  PRIMARY KEY (policy_id, account_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE signatures (
  request_id       VARCHAR(64) NOT NULL,
  key_id           VARCHAR(64) NOT NULL,
  intent_hash      BINARY(32)  NOT NULL,
  unsigned_tx_hash BINARY(32)  NOT NULL,
  tx_hash          BINARY(32)  NOT NULL,
  signed_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (request_id),
  KEY ix_signatures_key (key_id, signed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE key_ops (
  request_id  VARCHAR(64) NOT NULL,
  type        VARCHAR(32) NOT NULL COMMENT 'GENERATE, RETIRE, DESTROY, BACKUP, RESTORE',
  intent_hash BINARY(32)  NOT NULL,
  key_id      VARCHAR(64) NULL,
  result      VARCHAR(32) NOT NULL,
  done_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (request_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE freezes (
  freeze_id           VARCHAR(64)  NOT NULL,
  scope               VARCHAR(16)  NOT NULL COMMENT 'KEY, INSTITUTION, LEDGER',
  target              VARCHAR(64)  NOT NULL,
  reason              VARCHAR(512) NOT NULL,
  frozen_by           VARCHAR(64)  NOT NULL,
  frozen_at           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  released_request_id VARCHAR(64)  NULL,
  released_at         DATETIME(6)  NULL,
  PRIMARY KEY (freeze_id),
  KEY ix_freezes_target (scope, target, released_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 추가 전용 해시 체인(설계서 8절). 서버 계정은 INSERT, SELECT 만 가진다(NFR-2).
CREATE TABLE audit_log (
  seq          BIGINT UNSIGNED NOT NULL,
  ts           DATETIME(6)     NOT NULL,
  actor        VARCHAR(128)    NOT NULL,
  action       VARCHAR(64)     NOT NULL,
  subject      VARCHAR(256)    NOT NULL,
  payload_json MEDIUMTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  prev_hash    BINARY(32)      NOT NULL,
  hash         BINARY(32)      NOT NULL,
  PRIMARY KEY (seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE audit_checkpoints (
  id        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  chain     VARCHAR(16)     NOT NULL COMMENT 'api, signer',
  seq       BIGINT UNSIGNED NOT NULL,
  head_hash BINARY(32)      NOT NULL,
  key_id    VARCHAR(64)     NOT NULL,
  signature VARBINARY(72)   NOT NULL,
  ts        DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  KEY ix_audit_checkpoints_chain (chain, seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
