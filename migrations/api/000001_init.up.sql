-- api 스키마 초기 테이블(설계서 12.2)
-- intent_json, payload_json 은 해시 대상이므로 바이트를 보존하도록 utf8mb4_bin 텍스트로 저장한다.
-- 금액·수량은 DECIMAL(65,0)로 저장한다.

CREATE TABLE requests (
  request_id     VARCHAR(64)     NOT NULL COMMENT 'ULID',
  type           VARCHAR(32)     NOT NULL,
  ledger_id      VARCHAR(64)     NOT NULL,
  institution_id VARCHAR(64)     NOT NULL,
  intent_json    MEDIUMTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  intent_hash    BINARY(32)      NOT NULL,
  status         VARCHAR(24)     NOT NULL,
  drafter_id     VARCHAR(64)     NOT NULL,
  signer_address CHAR(42)        NULL,
  nonce          BIGINT UNSIGNED NULL,
  unsigned_tx    MEDIUMBLOB      NULL,
  raw_tx         MEDIUMBLOB      NULL,
  tx_hash        BINARY(32)      NULL,
  error          TEXT            NULL,
  expires_at     DATETIME(6)     NOT NULL,
  created_at     DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at     DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (request_id),
  KEY ix_requests_status (status, updated_at),
  KEY ix_requests_tx_hash (tx_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE approvals (
  request_id  VARCHAR(64)   NOT NULL,
  approver_id VARCHAR(64)   NOT NULL,
  decision    VARCHAR(8)    NOT NULL COMMENT 'APPROVE, REJECT',
  signature   VARBINARY(64) NOT NULL COMMENT 'Ed25519 서명',
  created_at  DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (request_id, approver_id),
  CONSTRAINT fk_approvals_request FOREIGN KEY (request_id) REFERENCES requests (request_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE nonces (
  ledger_id  VARCHAR(64)     NOT NULL,
  address    CHAR(42)        NOT NULL,
  next_nonce BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (ledger_id, address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE securities (
  issue_code         VARCHAR(32)  NOT NULL,
  name               VARCHAR(128) NOT NULL,
  ledger_id          VARCHAR(64)  NOT NULL,
  contract_address   CHAR(42)     NULL,
  circulation_status VARCHAR(16)  NOT NULL,
  PRIMARY KEY (issue_code),
  UNIQUE KEY uk_securities_contract (ledger_id, contract_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE ledger_cursor (
  ledger_id        VARCHAR(64)     NOT NULL,
  contract_address CHAR(42)        NOT NULL,
  last_block       BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (ledger_id, contract_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE registry_events (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  ledger_id    VARCHAR(64)     NOT NULL,
  block_number BIGINT UNSIGNED NOT NULL,
  block_hash   BINARY(32)      NOT NULL,
  block_time   DATETIME(6)     NOT NULL,
  tx_hash      BINARY(32)      NOT NULL,
  log_index    INT UNSIGNED    NOT NULL,
  event        VARCHAR(64)     NOT NULL,
  payload_json MEDIUMTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  raw_log      MEDIUMTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uk_registry_events_log (ledger_id, tx_hash, log_index),
  KEY ix_registry_events_block (ledger_id, block_number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE accounts (
  account_no      VARCHAR(32)  NOT NULL,
  institution_id  VARCHAR(64)  NOT NULL,
  holder_name     VARCHAR(128) NOT NULL COMMENT '모의 권리자 이름. 원장에 올리지 않는다(E-2-1)',
  onchain_address CHAR(42)     NOT NULL,
  status          VARCHAR(16)  NOT NULL,
  PRIMARY KEY (account_no),
  UNIQUE KEY uk_accounts_address (onchain_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE holdings (
  account_no VARCHAR(32)    NOT NULL,
  issue_code VARCHAR(32)    NOT NULL,
  quantity   DECIMAL(65, 0) NOT NULL,
  PRIMARY KEY (account_no, issue_code),
  CONSTRAINT fk_holdings_account FOREIGN KEY (account_no) REFERENCES accounts (account_no),
  CONSTRAINT fk_holdings_security FOREIGN KEY (issue_code) REFERENCES securities (issue_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE recon_runs (
  run_id      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  started_at  DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  finished_at DATETIME(6)     NULL,
  status      VARCHAR(16)     NOT NULL,
  diff_count  INT UNSIGNED    NOT NULL DEFAULT 0,
  PRIMARY KEY (run_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE recon_diffs (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  run_id     BIGINT UNSIGNED NOT NULL,
  issue_code VARCHAR(32)     NOT NULL,
  kind       VARCHAR(32)     NOT NULL COMMENT 'BALANCE, TOTAL_SUPPLY, EVENT_REPLAY',
  account_no VARCHAR(32)     NULL,
  expected   DECIMAL(65, 0)  NOT NULL,
  actual     DECIMAL(65, 0)  NOT NULL,
  PRIMARY KEY (id),
  KEY ix_recon_diffs_run (run_id),
  CONSTRAINT fk_recon_diffs_run FOREIGN KEY (run_id) REFERENCES recon_runs (run_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE alarms (
  alarm_id    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  rule        VARCHAR(32)     NOT NULL,
  subject     VARCHAR(256)    NOT NULL,
  detail_json JSON            NOT NULL,
  created_at  DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (alarm_id),
  KEY ix_alarms_created (created_at)
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
