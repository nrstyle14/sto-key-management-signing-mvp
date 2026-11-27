ALTER TABLE requests
  DROP KEY ix_requests_signer_nonce,
  DROP COLUMN submitted_at;
