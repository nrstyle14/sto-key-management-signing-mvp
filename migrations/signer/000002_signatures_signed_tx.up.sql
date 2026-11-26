-- 같은 request_id 재호출에 다시 서명하지 않고 저장된 결과를 돌려주기 위해 서명된 tx 원문을 남긴다(D-6, 설계서 5.3).
-- 서명 전 예약 단계에서는 tx_hash, signed_tx 가 비어 있다(같은 DB 트랜잭션 안에서 채운다).
ALTER TABLE signatures
  MODIFY tx_hash BINARY(32) NULL,
  ADD COLUMN signed_tx MEDIUMBLOB NULL AFTER tx_hash;
