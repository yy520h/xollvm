PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;

CREATE TABLE IF NOT EXISTS builds (
    build_id TEXT PRIMARY KEY CHECK(length(build_id) = 64 AND build_id NOT GLOB '*[^0-9a-f]*'),
    software_id TEXT NOT NULL CHECK(length(software_id) BETWEEN 1 AND 64 AND
        substr(software_id, 1, 1) GLOB '[A-Za-z0-9]' AND
        software_id NOT GLOB '*[^A-Za-z0-9._-]*'),
    public_manifest BLOB NOT NULL CHECK(length(public_manifest) BETWEEN 1 AND 4194304),
    private_registration BLOB NOT NULL CHECK(length(private_registration) BETWEEN 1 AND 536870912),
    identity_hash BLOB NOT NULL CHECK(length(identity_hash) = 32),
    state TEXT NOT NULL CHECK(state IN ('pending', 'validated', 'enabled', 'revoked')),
    final_artifact_hash TEXT CHECK(final_artifact_hash IS NULL OR
        (length(final_artifact_hash) = 64 AND final_artifact_hash NOT GLOB '*[^0-9a-f]*')),
    policy_revision INTEGER NOT NULL CHECK(policy_revision > 0),
    created_at INTEGER NOT NULL DEFAULT(CAST(strftime('%s','now') AS INTEGER)),
    CHECK((state = 'enabled' AND final_artifact_hash IS NOT NULL) OR
          (state != 'enabled' AND (final_artifact_hash IS NULL OR state = 'revoked')))
);

CREATE TABLE IF NOT EXISTS verifier_sidecars (
    build_id TEXT NOT NULL REFERENCES builds(build_id) ON DELETE RESTRICT,
    region_id TEXT NOT NULL CHECK(length(region_id) = 64 AND region_id NOT GLOB '*[^0-9a-f]*'),
    verifier BLOB NOT NULL CHECK(length(verifier) BETWEEN 1 AND 201326592),
    verifier_hash BLOB NOT NULL CHECK(length(verifier_hash) = 32),
    PRIMARY KEY(build_id, region_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS builds_artifact_identity
    ON builds(build_id, final_artifact_hash)
    WHERE final_artifact_hash IS NOT NULL;
