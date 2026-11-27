ALTER TABLE registry_events
  DROP KEY ix_registry_events_contract,
  DROP COLUMN contract_address;
