# XOVM2 Cloud Relay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a self-hosted, production-adapted XOVM2 backend and an isolated Zeno cloud-function relay mode while preserving `capability_v1` behavior and configuration.

**Architecture:** The backend owns persistent registrations/verifier sidecars, authorization policy, trusted time, signing keys, sessions, replay/idempotency state, and serializable transactions. The existing Zeno entry point dispatches legacy `capability_v1` requests unchanged or forwards a closed XOVM2 request over fixed HTTPS with a separate service credential; it never handles private registrations or XOVM2 signing keys.

**Tech Stack:** Node.js 20+, PostgreSQL via `pg`, existing `cloud/material_v2/{codec,protocol,package,service,store}.mjs`, Node built-in HTTP/HTTPS/crypto, existing `capability_v1.js` CommonJS handler, pytest/node:test.

**Spec:** `docs/superpowers/specs/2026-10-22-cloud-material-relay-design.md`; protocol authority: `docs/superpowers/specs/2026-10-18-cloud-vm-protocol-design.md`.

## Global Constraints

- Preserve `capability_v1` valid/invalid request behavior, signatures, and response shape exactly.
- Relay protocol discriminator is explicit; protocol errors fail closed and never fall back between modes.
- XOVM2 suite is `X25519-Ed25519-HKDF-SHA256-AES256GCM`, canonical request limit is 8192 decoded bytes, and raw success response limit is 16777216 decoded bytes.
- HTTP envelope byte limits include base64 expansion and JSON framing: compute exact maximum lengths from the closed envelope fields and raw limits; enforce while streaming without trusting `Content-Length`.
- Registration import must keep public manifest, private registration, and verifier sidecars private; do not expose registration via runtime relay.
- Runtime relay and administrative registration use distinct credentials, routes, scopes, and rate limits.
- Never trust caller-provided `device_id`, `subject_id`, scopes, session expiry, or wall clock as authentication authority.
- Anonymous relay means no Zeno card/user authentication; only explicit backend build/region policy may authorize issuance.
- No production start while trusted host authorization, cross-instance serializable transactions, durability, trusted time, or production key provider is missing.
- Never place real credentials, private registration bytes, or production keys in tests, logs, reports, or Git.
- PostgreSQL is the production persistence baseline; all authorization-sensitive mutations use serializable transactions and versioned migrations.
- Live deployment tests run only after the user deploys/configures the backend and explicitly asks for live testing.

## Review Focus

- Legacy event accidentally enters relay or changes its response bytes: Task 5 routing regression tests both valid and invalid legacy vectors.
- Caller-controlled URL/header, redirect, DNS destination, or protocol confusion enables SSRF: Task 4 tests fixed HTTPS origin/path, no redirects, and closed headers.
- Anonymous relay credential is mistaken for an end-user identity or arbitrary build authority: Task 2 tests policy denial by default and per-build allow/deny; Task 3 tests no caller scope override.
- Oversized/slow/chunked/compressed backend response exhausts function memory or runtime: Task 4 tests streaming caps, timeout, compression rejection, and cancellation.
- Admin registration import races enablement or admits mismatched sidecars: Task 2 tests atomic validation/enablement, idempotency, and conflicting identities.

---

### Task 1: Freeze Relay HTTP and Runtime Configuration Contract

**Files:**
- Create: `cloud/material_v2/http_contract.mjs`
- Create: `cloud/material_v2/strict_json.mjs`
- Create: `cloud/material_v2/test/http_contract.test.mjs`
- Test fixtures: `cloud/material_v2/test/protocol.test.mjs` request builders; add reusable exports only if required by the test runner.

**Interfaces:**
- Zeno request envelope is exactly `{protocol: 'xovm2_relay', request_b64: string}` after supported event-wrapper normalization.
- Backend route is fixed `POST /v2/relay`; its body uses that same closed object. Success is exactly `{protocol: 'xovm2_relay', response_b64: string}`. Both base64 strings are canonical RFC 4648 and decode to the original bytes.
- Produces `parseRelayRequest(headers, bodyBytes) -> {requestBytes}` and `encodeRelaySuccess(responseBytes) -> Buffer`.
- Authenticated relay principal comes from the server credential header, never request JSON.

- [ ] **Step 1: Write failing contract tests.** Cover valid `material.issue` and `session.open` canonical requests using builders from `protocol.test.mjs`, duplicate/unknown JSON fields, invalid and non-canonical base64, malformed canonical bytes, raw request >8192 bytes, envelope body above its derived maximum, wrong content type, and unsupported protocol discriminator.
- [ ] **Step 2: Run `node --test cloud/material_v2/test/http_contract.test.mjs`;** confirm the missing contract implementation is the failure.
- [ ] **Step 3: Implement duplicate-key-rejecting JSON parsing in `strict_json.mjs`, then closed-schema validation, canonical base64 checks, and existing `parseRequest`;** derive envelope maximum from the fixed fields and base64 expansion, and do not parse then reserialize signed bytes.
- [ ] **Step 4: Add round-trip assertions proving `requestBytes` and response bytes are byte-identical after transport encoding.**
- [ ] **Step 5: Run `node --test cloud/material_v2/test/http_contract.test.mjs cloud/material_v2/test/protocol.test.mjs`.**

### Task 2: Add PostgreSQL Persistence, Production Adapters, and Anonymous Build Policy

**Files:**
- Create: `cloud/material_v2/production.mjs`
- Create: `cloud/material_v2/admin.mjs`
- Create: `cloud/material_v2/test/production.test.mjs`
- Create: `cloud/material_v2/test/admin.test.mjs`
- Create: `cloud/material_v2/migrations/001_material_v2.sql`
- Create: `cloud/material_v2/postgres_store.mjs`
- Create: `cloud/material_v2/postgres_auth.mjs`
- Create: `cloud/material_v2/pg_transaction.mjs`
- Create: `cloud/material_v2/trust_bundle.mjs`
- Create: `cloud/material_v2/test/postgres_store.test.mjs`
- Create: `cloud/material_v2/test/trust_bundle.test.mjs`
- Create: `cloud/material_v2/package.json`
- Modify: `cloud/material_v2/store.mjs`
- Modify: `cloud/material_v2/service.mjs`

**Interfaces:**
- `createProductionService({pool, authorization, clock, keyProvider, anonymousPolicy}) -> {handleRuntimeRequest, handleAdminRequest, close}`.
- `authorization.authenticateRelayCredential(request) -> {issuer_id, subject_id, software_id, device_binding, valid_from_ms, valid_until_ms, scopes, request_hash}` using the existing service auth shape; `subject_id` is backend-derived only after parsing and policy-checking the request build, and `device_binding` is a fixed anonymous marker rather than caller `device_id`.
- PostgreSQL persists builds, private registrations, verifier sidecars, state, sessions, counters, generations, replay/idempotency claims, and exact cached responses. Unique constraints fence request identities, ephemeral claims, generation indexes, and stream counters.
- `authorization.authenticateRelayCredential(request) -> restricted anonymous grant`; the service principal maps to stable `anon:<build_id>` only after backend policy confirms the build. Grant scopes are limited to `session.control` and `material.issue`; shared callers remain indistinguishable.
- `registrationRepository.importBuild({publicManifest, privateRegistration, verifierSidecars, finalArtifactHash}, adminGrant)` validates via existing `registerBuild`/`enableBuild` logic and commits atomically.
- `createTrustBundleProvider({keyProvider, clock, buildRepository}) -> {getPublicTrustBundle(softwareId)}` returns only the bounded signed public trust-bundle bytes and current public bootstrap metadata; private key material is never serialized.
- Runtime request handlers invoke existing `handleSession` and `issueMaterial`; no new wire format or response signing implementation.

- [ ] **Step 1: Add the `pg` dependency and a versioned SQL migration runner; fail startup on missing or checksum-mismatched migrations.**
- [ ] **Step 2: Write failing database tests** for rollback, duplicate request races, concurrent generation allocation, revoke-vs-issue ordering, restart recovery, and bounded retry of serialization conflicts.
- [ ] **Step 3: Run focused tests against a disposable local PostgreSQL database and confirm the missing schema/adapter is the failure.**
- [ ] **Step 4: Implement tables and constraints** for builds, registrations, verifier sidecars, sessions, replay/idempotency claims, counters, generations, and exact cached responses; preserve binary data as `bytea`.
- [ ] **Step 5: Implement `pg_transaction.mjs`** with `SERIALIZABLE` transactions and bounded retry only for SQLSTATE `40001`; never retry validation, authorization, or uniqueness failures.
- [ ] **Step 6: Write and run failing production-start tests.** Missing PostgreSQL, migrations, trusted-time provider, key provider, relay/admin credentials, or anonymous policy must fail with `production_adapter_missing` before listening.
- [ ] **Step 7: Implement PostgreSQL-backed store/auth adapters** and prove every service mutation and cached response uses the transaction boundary.
- [ ] **Step 8: Implement relay authentication and build policy.** Default policy is deny. Derive `anon:<build_id>` only after backend lookup confirms build, region, mode, expiry, revocation, and request budget; reject caller subject/scopes/device/expiry as authority.
- [ ] **Step 9: Write and run failing admin import tests** for verifier and artifact hashes, public/private membership, wrong admin token, exact idempotent re-import, conflicting identity, concurrent import, revoke, and atomic rollback.
- [ ] **Step 10: Implement separate `XOVM_ADMIN_TOKEN` authentication and admin import/enable/revoke transactions.** Runtime credentials must fail every admin endpoint; compare tokens in constant time and never include them in errors.
- [ ] **Step 11: Add production capability self-check;** keep reference store/auth classes test-only and refuse production construction if any adapter is absent.
- [ ] **Step 12: Add trust-bundle tests** for root signature, key status, validity window, monotonic trust epoch, revocation, bootstrap metadata binding, and absence of private fields; implement public trust-bundle provider.
- [ ] **Step 13: Run `node --test cloud/material_v2/test/postgres_store.test.mjs cloud/material_v2/test/trust_bundle.test.mjs cloud/material_v2/test/production.test.mjs cloud/material_v2/test/admin.test.mjs cloud/material_v2/test/service.test.mjs` against disposable PostgreSQL.**

### Task 3: Implement the Self-Hosted HTTPS Backend

**Files:**
- Create: `cloud/material_v2/server.mjs`
- Create: `cloud/material_v2/config.mjs`
- Create: `cloud/material_v2/test/server.test.mjs`
- Create: `cloud/material_v2/test/config.test.mjs`
- Create: `cloud/material_v2/Dockerfile`
- Create: `cloud/material_v2/.dockerignore`
- Create: `cloud/material_v2/deploy/README.md`

**Interfaces:**
- `createServer({productionService, config, http}) -> {server, listen, close}`. Node binds to loopback behind a configured TLS reverse proxy and refuses non-loopback plaintext binding.
- Runtime endpoint is `POST /v2/relay`, accepts only the Task 1 envelope, and returns its response envelope with exact canonical v2 bytes.
- Admin endpoints are separate fixed paths and authenticate with an independent administrator credential/provider.
- Admin routes are `POST /v2/admin/builds/import`, `POST /v2/admin/builds/{build_id}/revoke`, and `POST /v2/admin/builds/{build_id}/enable`; import JSON is a closed envelope with canonical base64 fields `public_manifest_b64`, `private_registration_b64`, `verifier_sidecars_b64`, and lowercase `final_artifact_hash`.
- Public `GET /v2/trust/{software_id}` returns only signed public trust bytes and bootstrap metadata; it requires no relay/admin credential but has cache policy, bounded response size, and no private registration fields.
- Configuration is environment/provider injected using `DATABASE_URL`, `XOVM_RELAY_TOKEN`, `XOVM_ADMIN_TOKEN`, `XOVM_TRUSTED_TIME_PROVIDER`, `XOVM_SIGNING_KEY_PROVIDER`, `XOVM_ANONYMOUS_POLICY_PROVIDER`, and `XOVM_TRUST_ROOT_PROVIDER`; no secret defaults or embedded production keys.

- [ ] **Step 1: Write failing HTTPS handler tests** for method/path/content-type, relay authentication, response content type, CORS absence, no redirect, and generic external errors.
- [ ] **Step 2: Write failing streaming tests** for chunked bodies at/over limit, slow client timeout, aborted client, compressed input, oversized output, and concurrent requests.
- [ ] **Step 3: Verify red with `node --test cloud/material_v2/test/server.test.mjs`.**
- [ ] **Step 4: Write failing configuration tests** for missing/empty secrets, malformed backend IDs/origins, weak timeout/size bounds, unknown environment, and unsafe bind address; run `node --test cloud/material_v2/test/config.test.mjs`.
- [ ] **Step 5: Implement configuration parsing** for the exact documented variables, fixed loopback bind, hard byte/time bounds, and fail-closed missing values.
- [ ] **Step 6: Implement fixed-route HTTP server bound to loopback** with streaming limits, explicit timeouts, generic errors, and redacted structured logs. TLS terminates at the reverse proxy; forwarding headers never grant authorization.
- [ ] **Step 7: Add an ephemeral local TLS reverse-proxy fixture and test relay/admin credentials cannot cross scopes.**
- [ ] **Step 8: Add readiness that checks migrations and every production adapter; refuse listening when a required adapter is missing.**
- [ ] **Step 9: Add a non-root container image with read-only application files and no secrets in image layers; document reverse-proxy TLS, PostgreSQL, migrations, backups, health checks, and credential rotation in `deploy/README.md`.**
- [ ] **Step 10: Run server, config, production, admin, service, trust-bundle, and protocol Node suites.**

### Task 4: Add the Zeno HTTPS Relay Transport Helper

**Files:**
- Create: `cloud/material_v2/relay_client.js`
- Create: `cloud/material_v2/test/relay_client.test.js`
- Modify: `capability_v1.js` only after helper tests pass.

**Interfaces:**
- `forwardXovm2Request(requestBytes, config, transport = https) -> Promise<Buffer>`.
- `config` is server-owned `{backendOrigin, relayCredential, timeoutMs, maxRequestBytes, maxResponseBytes}`.
- Zeno secret-store names are `XOVM2_BACKEND_ORIGIN`, `XOVM2_RELAY_TOKEN`, `XOVM2_CONNECT_TIMEOUT_MS`, and `XOVM2_TOTAL_TIMEOUT_MS`; code bounds decoded size to 8192 request bytes and 16777216 response bytes regardless of configured lower limits, and separately enforces the derived JSON envelope byte caps.
- Only fixed route/method/content type/auth header are generated. `transport` is injected for tests; production uses Node built-in HTTPS.

- [ ] **Step 1: Write failing tests** for exact request bytes, fixed host/path/method, service credential header, response byte preservation, status validation, and content-type validation.
- [ ] **Step 2: Write failing SSRF/response tests** for caller URL/path/header injection, redirects, compressed responses, chunked oversize responses, invalid response base64, timeout, socket abort, and secret-free errors.
- [ ] **Step 3: Run `node --test cloud/material_v2/test/relay_client.test.js` and confirm failures are missing behavior.**
- [ ] **Step 4: Implement HTTPS-only fixed-origin transport with redirect rejection and separate raw/envelope streaming byte caps.** The client receives only decoded canonical response bytes, never arbitrary backend JSON or headers.
- [ ] **Step 5: Run relay client and HTTP contract suites.**

### Task 5: Add Protocol Routing to `capability_v1.js` Without Legacy Changes

**Files:**
- Modify: `capability_v1.js`
- Create or modify in existing test location: `test/capability_v1.test.js` (locate and extend the repository's current capability tests if they already exist).

**Interfaces:**
- Existing `buildCapabilityResponse(event, context)` remains the legacy implementation and keeps its output byte/schema behavior.
- Add a normalized top-level `protocol` discriminator for `capability_v1` or `xovm2_relay`; relay request payload is an encoded canonical v2 request.
- Export retains `capability_v1`, `buildCapabilityResponse`, `normalizeEvent`, canonical helpers, and `CODE_CONFIG`; add only the relay configuration/handler seams needed by tests.
- `exports.capability_v1` remains the selected Zeno entry point; do not introduce an undocumented alias.

- [ ] **Step 1: Snapshot valid and invalid legacy fixtures** from current tests and assert exact output string equality before editing implementation.
- [ ] **Step 2: Add failing route tests** proving legacy requests never call the injected relay and XOVM2 requests never call `buildCapabilityResponse`.
- [ ] **Step 3: Add failing closed-routing tests** for missing/unknown protocol, conflicting wrapped protocol fields, extra fields, malformed request encoding, and legacy-shaped payload attempting relay selection.
- [ ] **Step 4: Run the focused test file and confirm failures are expected.**
- [ ] **Step 5: Add a strict dispatch wrapper.** Keep existing legacy handler body intact; relay route validates only envelope-level closed fields and delegates request bytes to `forwardXovm2Request`.
- [ ] **Step 6: Add deployment config reads for backend origin and relay credential.** Fail closed when absent; do not use or print existing capability secrets as fallback.
- [ ] **Step 7: Run all legacy capability tests and relay routing tests; prove exact legacy output snapshots remain unchanged.**

### Task 6: Local End-to-End Relay Acceptance and Operator Handoff

**Files:**
- Create: `cloud/material_v2/test/relay_e2e.test.mjs`
- Modify: `cloud/material_v2/deploy/README.md` with redacted variable names and operator workflow.
- Modify: `docs/superpowers/specs/2026-10-22-cloud-material-relay-design.md` only for verified implementation decisions that preserve its invariants.

**Interfaces:**
- Test starts an ephemeral HTTPS backend with synthetic registration, test signing keys, fake trusted clock, durable-contract test adapter, and a test relay credential.
- Test routes a real Node-generated XOVM2 session-open and material-issue request through the Zeno relay handler into the backend; captured request/response are passed through the existing client authentication fixture.

- [ ] **Step 1: Write a failing E2E test** that builds synthetic registration, imports/enables it through the admin path, routes session-open and material-issue through relay, authenticates the returned envelope, and checks correct package binding.
- [ ] **Step 2: Add negative E2E cases** for anonymous policy disabled, wrong relay credential, revoked build, session closed, mismatched build/region, retry idempotency, response tamper, and backend down.
- [ ] **Step 3: Run the E2E test and confirm the expected initial failure.**
- [ ] **Step 4: Connect the already implemented server, service, and relay components through injected local HTTPS only.**
- [ ] **Step 5: Run all Node suites:** `node --test cloud/material_v2/test/*.test.mjs` and `node --test test/capability_v1.test.js`.
- [ ] **Step 6: Run cloud Python regressions:** `PYTHONDONTWRITEBYTECODE=1 XOLLVM_PROJECT_ROOT=/data/user/0/com.termux/files/home/xollvm-android python -m pytest -q utils/test_cloud_material_protocol.py utils/test_cloud_material_package.py utils/test_cloud_material_reencode.py utils/test_cloud_material_lease.py utils/test_cloud_material_lifecycle.py utils/test_zone_runtime_concurrency.py`.
- [ ] **Step 7: Verify `git diff --check`, inspect every changed file for secrets, confirm the user's existing `demo/jni/zone_runtime/capability_client.cpp` modification is untouched, and record that live deployment remains untested.**

### Task 7: User-Operated Deployment Validation (No Agent Deployment)

**Files:**
- No production credential or live cloud setting is changed by the implementation agent.
- Operator deploys backend and manually updates Zeno cloud-function code/configuration.

**Interfaces:**
- Operator supplies backend HTTPS origin and fixed route, Zeno environment/config mechanism and byte/timeout limits, PostgreSQL service, trusted-time and signing-key providers, admin credential setup, public trust bootstrap delivery path, and per-build anonymous policy.
- Operator confirms the Zeno Node.js/runtime version supports the selected built-in HTTPS APIs and supplies its maximum input/output size, execution timeout, event wrapper, and binary/base64 preservation behavior before relay integration is enabled.
- Runtime relay credential is separate from administrator credential and all XOVM2 signing keys.

- [ ] **Step 1: Operator deploys backend into a non-production/test policy and imports synthetic registration.**
- [ ] **Step 2: Operator deploys `capability_v1.js` and configures the fixed relay origin/credential in the approved secret store.**
- [ ] **Step 3: User explicitly requests live tests; run health, denied-unregistered-build, approved-test-build, response-authentication, timeout, and relay-credential-rotation tests without recording secrets.**
- [ ] **Step 4: Report online behavior separately from local E2E evidence; do not claim production adapter readiness if any production self-check is blocked.**
