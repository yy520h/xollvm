CREATE TABLE IF NOT EXISTS schema_migrations (
  version integer PRIMARY KEY,
  checksum bytea NOT NULL CHECK (octet_length(checksum) = 32),
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE builds (
  build_id text PRIMARY KEY CHECK (build_id ~ '^[0-9a-f]{64}$'),
  software_id text NOT NULL CHECK (software_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
  registration_identity bytea NOT NULL CHECK (octet_length(registration_identity) = 32),
  manifest jsonb NOT NULL,
  registration jsonb NOT NULL,
  state text NOT NULL CHECK (state IN ('pending', 'validated', 'enabled', 'revoked')),
  revision numeric(20, 0) NOT NULL CHECK (revision > 0),
  final_artifact_hash text CHECK (final_artifact_hash IS NULL OR final_artifact_hash ~ '^[0-9a-f]{64}$'),
  counter_epoch text NOT NULL CHECK (counter_epoch ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE verifier_sidecars (
  build_id text NOT NULL REFERENCES builds(build_id) ON DELETE RESTRICT,
  region_id text NOT NULL CHECK (region_id ~ '^[0-9a-f]{64}$'),
  verifier bytea NOT NULL CHECK (octet_length(verifier) BETWEEN 1 AND 65536),
  verifier_hash bytea NOT NULL CHECK (octet_length(verifier_hash) = 32),
  PRIMARY KEY (build_id, region_id)
);

CREATE TABLE sessions (
  session_id text PRIMARY KEY CHECK (session_id ~ '^[0-9a-f]{64}$'),
  build_id text NOT NULL REFERENCES builds(build_id) ON DELETE RESTRICT,
  issuer_id text NOT NULL,
  subject_id text NOT NULL,
  software_id text NOT NULL,
  device_binding text NOT NULL,
  final_artifact_hash text NOT NULL CHECK (final_artifact_hash ~ '^[0-9a-f]{64}$'),
  counter_epoch text NOT NULL CHECK (counter_epoch ~ '^[0-9a-f]{64}$'),
  session_valid_until_ms numeric(20, 0) NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'closed')),
  control_counter numeric(20, 0) NOT NULL CHECK (control_counter >= 0),
  value jsonb NOT NULL
);

CREATE TABLE request_replies (
  issuer_id text NOT NULL,
  subject_id text NOT NULL,
  software_id text NOT NULL,
  device_binding text NOT NULL,
  request_id text NOT NULL,
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  scope text NOT NULL,
  response bytea NOT NULL CHECK (octet_length(response) <= 16777216),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (issuer_id, subject_id, software_id, device_binding, request_id)
);

CREATE TABLE request_tombstones (
  issuer_id text NOT NULL,
  subject_id text NOT NULL,
  software_id text NOT NULL,
  device_binding text NOT NULL,
  request_id text NOT NULL,
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  scope text NOT NULL,
  PRIMARY KEY (issuer_id, subject_id, software_id, device_binding, request_id)
);

CREATE TABLE ephemeral_claims (
  issuer_id text NOT NULL,
  subject_id text NOT NULL,
  software_id text NOT NULL,
  device_binding text NOT NULL,
  build_id text NOT NULL REFERENCES builds(build_id) ON DELETE RESTRICT,
  claim_kind text NOT NULL CHECK (claim_kind IN ('client_nonce', 'client_key', 'server_nonce', 'server_key')),
  claim_value text NOT NULL,
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  PRIMARY KEY (issuer_id, subject_id, software_id, device_binding, build_id, claim_kind, claim_value)
);

CREATE TABLE material_generations (
  session_id text NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
  region_id text NOT NULL CHECK (region_id ~ '^[0-9a-f]{64}$'),
  generation numeric(20, 0) NOT NULL CHECK (generation >= 0 AND generation <= 18446744073709551615),
  PRIMARY KEY (session_id, region_id)
);

CREATE TABLE counters (
  counter_epoch text NOT NULL CHECK (counter_epoch ~ '^[0-9a-f]{64}$'),
  software_id text NOT NULL,
  build_id text NOT NULL REFERENCES builds(build_id) ON DELETE RESTRICT,
  stream text NOT NULL,
  counter numeric(20, 0) NOT NULL CHECK (counter >= 0 AND counter <= 18446744073709551615),
  PRIMARY KEY (counter_epoch, software_id, build_id, stream)
);

CREATE TABLE anonymous_policy (
  build_id text PRIMARY KEY REFERENCES builds(build_id) ON DELETE RESTRICT,
  enabled boolean NOT NULL DEFAULT false,
  modes text[] NOT NULL DEFAULT '{}',
  region_ids text[] NOT NULL DEFAULT '{}',
  valid_until_ms numeric(20, 0) NOT NULL,
  request_budget bigint NOT NULL CHECK (request_budget >= 0),
  requests_used bigint NOT NULL DEFAULT 0 CHECK (requests_used >= 0),
  revision numeric(20, 0) NOT NULL CHECK (revision > 0)
);

CREATE TABLE signing_keys (
  key_id text PRIMARY KEY,
  public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
  status text NOT NULL CHECK (status IN ('active', 'retired', 'revoked')),
  not_before_ms numeric(20, 0) NOT NULL,
  signing_until_ms numeric(20, 0) NOT NULL,
  not_after_ms numeric(20, 0) NOT NULL,
  private_key_reference text NOT NULL,
  CHECK (not_before_ms < signing_until_ms AND signing_until_ms <= not_after_ms)
);

CREATE TABLE protocol_state (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  counter_epoch text NOT NULL CHECK (counter_epoch ~ '^[0-9a-f]{64}$'),
  trust_epoch numeric(20, 0) NOT NULL CHECK (trust_epoch > 0),
  root_key_id text NOT NULL,
  bundle_valid_until_ms numeric(20, 0) NOT NULL,
  revision numeric(20, 0) NOT NULL CHECK (revision > 0)
);
