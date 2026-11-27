-- 정책 변경 요청 기록(설계서 7.2·12.1, D-22). change_id 는 한 번만 쓰인다(재전송 방지).
CREATE TABLE policy_changes (
  change_id   VARCHAR(64)  NOT NULL COMMENT 'ULID',
  type        VARCHAR(32)  NOT NULL COMMENT 'WHITELIST_ADD',
  intent_hash BINARY(32)   NOT NULL COMMENT 'SHA-256(서명 대상)',
  policy_ids  VARCHAR(512) NOT NULL,
  address     CHAR(42)     NOT NULL,
  done_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (change_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
