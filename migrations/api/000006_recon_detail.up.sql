-- 대사 상세(설계서 11절·12.2, T4.2). 대사는 종목마다 연계장부가 반영한 블록(ledger_cursor.last_block) 시점의 원장과 비교한다.
ALTER TABLE recon_runs
  ADD COLUMN scope VARCHAR(32) NULL COMMENT '종목 코드(NULL 이면 전체)' AFTER run_id,
  ADD COLUMN error TEXT NULL AFTER diff_count;
ALTER TABLE recon_diffs
  MODIFY COLUMN kind VARCHAR(32) NOT NULL COMMENT 'BALANCE, TOTAL_SUPPLY, EVENT_REPLAY, UNLINKED_HOLDER',
  ADD COLUMN address CHAR(42) NULL AFTER account_no,
  ADD COLUMN block_number BIGINT UNSIGNED NULL AFTER actual;
