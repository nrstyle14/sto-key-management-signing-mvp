-- 감사 체인 머리(설계서 8절). 추가를 직렬화하는 잠금 행이다. 서버용 계정은 SELECT, UPDATE 만 가진다.
-- 검증은 이 테이블을 읽지 않고 audit_log 만으로 한다.
CREATE TABLE audit_head (
  id   TINYINT UNSIGNED NOT NULL,
  seq  BIGINT UNSIGNED  NOT NULL,
  hash BINARY(32)       NOT NULL,
  PRIMARY KEY (id),
  CONSTRAINT ck_audit_head_single CHECK (id = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO audit_head (id, seq, hash)
SELECT 1, COALESCE(MAX(seq), 0),
       COALESCE((SELECT a.hash FROM audit_log a ORDER BY a.seq DESC LIMIT 1), REPEAT(CHAR(0), 32))
FROM audit_log;
