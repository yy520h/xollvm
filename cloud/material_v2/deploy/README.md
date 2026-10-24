# XOVM2 Material Backend Deployment

Production deployment is blocked until PostgreSQL-backed service/store, trusted-time, signing-key, trust-root, and anonymous-policy providers are configured and pass startup self-checks. The reference-memory store is test-only and must never be exposed as a runtime backend.

## Runtime

Run the container behind a TLS-terminating reverse proxy. The Node process binds only to `127.0.0.1`; do not publish port 8080 directly. The reverse proxy must preserve the request body and must not rewrite `/v2/relay`, `/v2/admin/*`, or `/v2/trust/*`. Forwarded headers are not authorization inputs.

Provision PostgreSQL independently with durable storage, encrypted backups, monitored capacity, and network access restricted to the backend. Apply versioned migrations before readiness. Exercise restore procedures before enabling anonymous issuance.

## Required Configuration

- `DATABASE_URL`: PostgreSQL connection URI from the host secret manager.
- `XOVM_RELAY_TOKEN`: random service credential for cloud-function requests; rotate independently from all other secrets.
- `XOVM_ADMIN_TOKEN`: separate random credential for registration import, enable, and revoke.
- `XOVM_TRUSTED_TIME_PROVIDER`: trusted time provider identifier.
- `XOVM_SIGNING_KEY_PROVIDER`: Ed25519 signing key provider identifier.
- `XOVM_ANONYMOUS_POLICY_PROVIDER`: per-build anonymous issuance policy provider identifier. Default policy must deny.
- `XOVM_TRUST_ROOT_PROVIDER`: root-signing and bootstrap metadata provider identifier.
- `PORT`: optional loopback listener port, default 8080.
- `REQUEST_TIMEOUT_MS`: optional request timeout from 100 to 120000 milliseconds, default 10000.
- `MAX_CONCURRENT_REQUESTS`: optional active request cap from 1 to 10000, default 128.

Never put secret values in the image, source tree, command line, deployment manifest, health output, or application logs. Runtime relay and administrator credentials have separate scopes and rotation procedures.

## Routes

- `POST /v2/relay`: authenticated XOVM2 runtime envelope.
- `POST /v2/admin/builds/import`: administrator-only registration import.
- `POST /v2/admin/builds/{build_id}/enable`: administrator-only artifact binding and enablement.
- `POST /v2/admin/builds/{build_id}/revoke`: administrator-only revocation.
- `GET /v2/trust/{software_id}`: bounded signed public trust bundle and bootstrap metadata.
- `GET /healthz`: readiness only; returns no provider details or secret state.

Registration import takes canonical base64 fields for the public manifest, private registration, and verifier sidecars. Keep the source archive in an approved private operator workflow and delete temporary copies according to the operator's retention policy after import verification.

## Operational Checks

1. Deploy with anonymous policy disabled and verify health/readiness remains false until migrations and all production providers are ready.
2. Import a synthetic test build through the administrative route and verify exact manifest, registration, sidecar, and final-artifact binding.
3. Exercise denied and allowed test-build flows through the configured cloud-function relay; verify the client authenticates the returned XOVM2 envelope.
4. Verify relay credential rotation and revocation, administrator credential rotation, database restore, key rotation, and build revocation.
5. Enable a build only after explicit policy review. Live tests require the user's explicit request after the operator deploys the backend and cloud function.
