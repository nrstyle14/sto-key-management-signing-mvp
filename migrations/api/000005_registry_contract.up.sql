-- 이벤트를 낸 종목 컨트랙트 주소(T3.4). 종목별 조회·재생(대사, T4.2)에 쓴다.
ALTER TABLE registry_events
  ADD COLUMN contract_address CHAR(42) NOT NULL AFTER ledger_id,
  ADD KEY ix_registry_events_contract (ledger_id, contract_address, block_number, log_index);
