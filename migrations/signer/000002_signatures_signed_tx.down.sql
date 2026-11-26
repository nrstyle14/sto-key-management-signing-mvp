ALTER TABLE signatures
  DROP COLUMN signed_tx,
  MODIFY tx_hash BINARY(32) NOT NULL;
