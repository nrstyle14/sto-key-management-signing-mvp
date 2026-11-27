-- 원장 확정 결과(T3.3·T3.4). 확정 블록과, 배포 요청이면 만들어진 컨트랙트 주소를 남긴다.
ALTER TABLE requests
  ADD COLUMN block_number     BIGINT UNSIGNED NULL AFTER submitted_at,
  ADD COLUMN contract_address CHAR(42)        NULL AFTER block_number;
