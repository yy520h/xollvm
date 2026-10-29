# XOVM2 Cloud Material Backend

This directory documents the initial non-root deployment contract. It does not
provide a service-manager unit, container image, or credential provisioning
script.

## Runtime contract

- Run `xovm-cloud-material-backend-server` as a dedicated non-root account.
- Keep the application binary and read-only migration files outside writable
  state directories.
- Set `XOVM_SQLITE_PATH` to the administrator-owned SQLite database and
  `XOVM_STATE_DIR` to a separate directory for `.xovm.lock`, `checkpoint.bin`,
  and `state.wal`.
- Set distinct, randomly generated `XOVM_RELAY_TOKEN` and
  `XOVM_ADMIN_TOKEN` values. Do not place either secret in an image layer,
  repository, command line, or log.
- Configure all four provider identifiers: trusted time, signing key,
  anonymous policy, and trust root. The server exits before listening when
  production provider adapters are unavailable.
- The backend binds only to `127.0.0.1`. Terminate TLS and validate the client
  or proxy identity at a local reverse proxy before forwarding the fixed paths.

## Permissions

- The service account must be able to read the binary and migration files.
- The service account must have read/write access to the SQLite file and its
  parent directory. Provision the state directory as owner-only mode `0700`;
  when the backend creates a missing state directory, it applies that mode.
- Keep the SQLite and state directories outside application release paths.
- Do not grant the service account access to signing-key material beyond the
  configured provider interface.
- Backups must be created by an operator with access to both the SQLite WAL
  files and the application state directory. Copying only the main SQLite
  file or only `checkpoint.bin` is not a complete backup.

## Fixed HTTP boundary

- `GET /healthz` reports readiness and returns `503` until every startup stage
  has succeeded.
- `POST /v2/relay` accepts only the closed JSON relay envelope and the relay
  credential.
- `POST /v2/admin/builds/import`,
  `POST /v2/admin/builds/{build_id}/enable`, and
  `POST /v2/admin/builds/{build_id}/revoke` use only the administrator
  credential.
- `GET /v2/trust/{software_id}` is a public trust-bundle route and must never
  serialize private registrations or signing-key material.
- The proxy must forward the path and body unchanged, must not add a fallback
  route, and must not substitute one credential for another.

## Recovery and rotation

- Acquire the single-writer lock before opening mutable state. Never run two
  backend instances against the same state directory.
- On startup, the backend validates the SQLite schema, recovers checkpoint
  and WAL state, validates the full snapshot, checks providers, and only then
  listens.
- Treat any checksum, sequence, schema, provider, or snapshot failure as a
  startup failure. Do not delete WAL or checkpoint files to force startup.
- Test backup restoration on an isolated copy before using it for recovery.
- To reclaim expired exact-response payloads and rotate the state WAL, stop the
  backend and run
  `xovm-cloud-material-state-maintenance reclaim-expired` as the same non-root
  service account with only `XOVM_STATE_DIR` and
  `XOVM_TRUSTED_TIME_PROVIDER` configured. The command fails with `lock_busy`
  if the backend or another maintenance process still owns the state directory.
- Each maintenance invocation performs one bounded batch. Invoke it again only
  when it reports `more_work=true`, and restart the backend only after exit 0.
  Never delete `.xovm.lock`, checkpoint, WAL, or quarantine files to bypass a
  failure.
- Rotate relay and administrator credentials independently. Revoke old
  credentials at the proxy and backend configuration boundary before deleting
  them.

## Current implementation boundary

The C++ transport, startup order, SQLite schema check, WAL/checkpoint recovery
entry point, and credential-separated routes are implemented and tested.
Provider construction for trusted time, signing, anonymous policy, trust root,
and the complete production snapshot remains an explicit integration boundary.
Until those adapters are supplied and validated, startup intentionally fails
closed and does not expose a listening service.
