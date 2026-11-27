-- 원장 제출 시각(T3.2). 한 번이라도 노드가 받아 준 tx 의 nonce 는 빈자리로 재사용하지 않는다(설계서 5.5).
ALTER TABLE requests
  ADD COLUMN submitted_at DATETIME(6) NULL AFTER tx_hash,
  ADD KEY ix_requests_signer_nonce (ledger_id, signer_address, nonce);
