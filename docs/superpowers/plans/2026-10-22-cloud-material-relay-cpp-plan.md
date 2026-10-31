# XOVM2 C++ Cloud Relay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the superseded Node production backend plan with a single-instance C++20 XOVM2 backend whose request path uses validated memory snapshots and memory-resident session state, with SQLite WAL for durable administrative records and a separate application WAL/checkpoint for mutable protocol state.

**Architecture:** Keep the existing Node XOVM2 service and reference store as protocol/test oracles only. The new C++ backend validates the exact existing canonical v2 protocol, loads enabled registrations into an immutable memory snapshot, handles session/replay/generation state in sharded memory, and records state transition plus exact idempotent response in a checksummed application WAL before success. SQLite is used for admin-managed build registration/policy and is never queried for registration/verifier data in the request path. HTTPS terminates at a trusted reverse proxy; the backend binds to loopback and enforces fixed routes and cloud-to-backend authentication.

**Tech Stack:** C++20 standalone CMake project, existing `runtime/cloud_material` canonical protocol/package code and fixtures, SQLite3 C API in WAL mode, OpenSSL/libcrypto, nlohmann JSON, a bounded HTTP server library selected from dependencies actually available on the target Linux host, GoogleTest, POSIX file locks/fsync/atomic rename, Node built-in HTTPS for the Zeno relay, and pytest.

**Spec:** `docs/superpowers/specs/2026-10-22-cloud-material-relay-design.md`; wire-format authority: `docs/superpowers/specs/2026-10-18-cloud-vm-protocol-design.md`.

## Global Constraints

- Preserve protocol version 2 and suite `X25519-Ed25519-HKDF-SHA256-AES256GCM` exactly.
- Canonical request maximum is 8192 decoded bytes; raw response maximum is 16777216 decoded bytes; enforce streaming and envelope expansion limits before full allocation.
- Request-time registration and verifier reads are memory-only; no SQLite reads in runtime session/material handling.
- Initial production topology is one C++ process on one server with exclusive ownership of one mutable state/WAL directory; multi-instance is unsupported.
- SQLite WAL is the durable source for admin build records/policy. The protocol session state has its own checksummed application WAL and checkpoint files.
- Return success only after the application WAL durably records both the state transition and exact idempotent response; default is fdatasync/fsync before success.
- Build snapshot update is durable-first, fully validated, then atomically published. Acknowledged revoke must not leave an older snapshot serving issuance.
- Private registration, verifier sidecars, WAL/checkpoint data, credentials, and private keys never enter source control, container image layers, logs, or relay responses.
- Runtime relay credential and administrator credential are distinct. Anonymous callers are not represented as authenticated users or devices.
- No production startup if SQLite schema, snapshot validation, WAL recovery, single-writer lock, trusted-time source, signing-key provider, relay credential, or deny-by-default anonymous policy is unavailable.
- No commit, stage, push, deployment, credential changes, or live tests unless separately requested.
- Configure and build the service independently with `cmake -S runtime/cloud_material_backend -B build/cloud_material_backend`; do not attach its production dependencies to LLVM's root configure or `Obfuscator` target.

## Review Focus

- WAL torn write versus interior corruption: Task 4 tests truncate only an incomplete final frame and fail closed on complete bad-checksum/interior frames.
- Crash around checkpoint rename/WAL retirement: Task 4 restarts at every boundary and must recover either old checkpoint+WAL or new checkpoint+remaining WAL without state loss.
- Snapshot revoke races with requests: Task 3 holds a snapshot generation through authorization/state commit and tests no successful issue after acknowledged revoke.
- Request retry after response loss: Task 3/4 proves the exact committed response is replayed after restart without reusing counters/generations.
- Malformed/oversized/ambiguous relay input and caller-selected host: Task 5/6 tests closed protocol, byte limits, fixed route, no redirects/compression, and legacy isolation.

---

### Task 1: Establish C++ Backend Build and Protocol-Compatible Request Parsing

**Files:**
- Create: `runtime/cloud_material_backend/CMakeLists.txt` as an independently configurable CMake project using CMake package discovery for SQLite3, OpenSSL, and nlohmann JSON; register a standalone C++ test executable with CTest, without an external test framework. Select and discover the bounded HTTP server dependency in Task 5 when implementing the server.
- Create: `runtime/cloud_material_backend/http_contract.h`
- Create: `runtime/cloud_material_backend/http_contract.cpp`
- Create: `runtime/cloud_material_backend/canonical_json.h`
- Create: `runtime/cloud_material_backend/canonical_json.cpp`
- Create: `utils/CloudMaterialBackendProtocolTest.cpp`
- Compile existing `runtime/cloud_material/material_protocol.cpp` and `runtime/cloud_material/material_package.cpp` into the backend library; do not copy or reimplement the client canonical scanner, hash, trust-bundle, or package-validation logic.
- Do not modify: root `CMakeLists.txt`; the backend CMake project is configured directly and must not require LLVM package discovery.

**Interfaces:**
- `parseRelayEnvelope(std::span<const std::byte> body) -> Expected<RelayRequest, BackendError>` returns the original canonical request byte vector and never reserializes it.
- `parseCanonicalRequest(std::span<const std::byte>) -> Expected<Request, BackendError>` calls the existing `xovm::material::decodeCanonical` for bounded canonical/duplicate-key validation, then validates exact closed fields and suite/type-specific fields under the existing 8192-byte limit.
- `xovm-cloud-material-backend-tests` is a standalone C++ executable registered with CTest; it uses named test functions and a small local assertion/reporting helper, consumes canonical protocol values from `runtime/cloud_material`, and does not require GoogleTest or another test framework.

- [ ] **Step 1: Add the standalone backend CMake test target and failing C++ tests** for valid session.open/material.issue requests, unknown/missing/duplicate fields, invalid UTF-8, noncanonical key order/whitespace/numbers/base64, unsupported suite, and 8193-byte input. Confirm SQLite, OpenSSL, and nlohmann JSON are available; HTTP server dependency selection belongs to Task 5.
- [ ] **Step 2: Configure, build, and run the focused test** with `cmake -S runtime/cloud_material_backend -B build/cloud_material_backend && cmake --build build/cloud_material_backend --target xovm-cloud-material-backend-tests && ctest --test-dir build/cloud_material_backend --output-on-failure`; confirm the tests fail on missing request parser behavior, while existing client parser/package sources compile independently of LLVM.
- [ ] **Step 3: Implement the bounded relay envelope parser** and call the existing `decodeCanonical` before DOM/schema access; cap the envelope/body before allocation and preserve, rather than reserialize, the canonical request bytes.
- [ ] **Step 4: Add request schema validation** for all four request types and keep the exact original bytes for request hashing/transcript binding.
- [ ] **Step 5: Run `ctest --test-dir build/cloud_material_backend --output-on-failure` and the existing material protocol/package pytest tests.**

### Task 2: Implement SQLite Admin Repository and Immutable Build Snapshot

**Files:**
- Create: `runtime/cloud_material_backend/admin_repository.h`
- Create: `runtime/cloud_material_backend/admin_repository.cpp`
- Create: `runtime/cloud_material_backend/build_snapshot.h`
- Create: `runtime/cloud_material_backend/build_snapshot.cpp`
- Create: `runtime/cloud_material_backend/migrations/001_build_registry.sql`
- Create: `utils/CloudMaterialSnapshotTest.cpp`
- Modify: `runtime/cloud_material_backend/CMakeLists.txt`

**Interfaces:**
- `SqliteBuildRepository::importBuild(ImportRecord, AdminPrincipal)`, `enableBuild(buildId, finalArtifactHash, AdminPrincipal)`, and `revokeBuild(buildId, AdminPrincipal)` are management-plane operations only.
- `BuildSnapshot::load(SqliteBuildRepository&, ValidationContext) -> Expected<std::shared_ptr<const BuildSnapshot>, Error>` loads/validates all enabled records and stores private registration/verifier bytes in immutable memory-owned objects.
- `SnapshotManager::acquire() -> SnapshotHandle` pins one snapshot generation for an entire request; `publish(nextSnapshot)` performs one atomic shared-pointer swap.

- [ ] **Step 1: Write failing SQLite tests** for exact import idempotency, identity conflict, invalid public/private membership, invalid sidecar/hash, unauthorized admin, failed transaction rollback, and enable/revoke state transitions.
- [ ] **Step 2: Write failing snapshot tests** proving no partially loaded build is published, duplicate identities are rejected, and a pinned old snapshot remains immutable during atomic publication.
- [ ] **Step 3: Run focused tests** against a temporary SQLite file; verify expected failures are missing repository/snapshot behavior.
- [ ] **Step 4: Create SQLite schema** with foreign keys, unique build/region identities, explicit pending/validated/enabled/revoked states, artifact binding, policy revision, and SQLite WAL mode plus `synchronous=FULL` for admin commits.
- [ ] **Step 5: Implement transaction-scoped import/enable/revoke** using prepared statements, `BEGIN IMMEDIATE`, bounded input parsing, verifier validation through existing C++ package/manifest verifiers, and explicit rollback on every failure.
- [ ] **Step 6: Implement immutable snapshot load and publish.** Query SQLite only during startup/admin refresh. Verify full registration membership and artifact pair before including a build.
- [ ] **Step 7: Test durable revoke ordering:** durably revoke in SQLite, immediately fail issuance for the revoked build while rebuilding/publishing the replacement snapshot, and acknowledge only after publication; if publication fails, set backend readiness false and prevent all runtime issuance until reconciliation.
- [ ] **Step 8: Run the standalone snapshot/admin CTest cases and existing material manifest/package pytest tests.**

### Task 3: Implement In-Memory Authorization, Session State, and XOVM2 Service

**Files:**
- Create: `runtime/cloud_material_backend/auth_policy.h`
- Create: `runtime/cloud_material_backend/auth_policy.cpp`
- Create: `runtime/cloud_material_backend/session_state.h`
- Create: `runtime/cloud_material_backend/session_state.cpp`
- Create: `runtime/cloud_material_backend/protocol_service.h`
- Create: `runtime/cloud_material_backend/protocol_service.cpp`
- Create: `utils/CloudMaterialBackendServiceTest.cpp`
- Modify: `runtime/cloud_material_backend/CMakeLists.txt`

**Interfaces:**
- `RelayAuthenticator::authenticate(credential, RequestFacts, trustedNow) -> Expected<AnonymousGrant, Error>` creates a backend-only principal bound to one build and request digest; scopes are only session.control/material.issue.
- `AnonymousPolicy::authorize(snapshot, RequestFacts, trustedNow, rateBudget) -> Expected<AnonymousGrant, Error>` defaults deny and checks build enabled/revision, software/build/artifact/region/mode, expiry, revocation, and budget before state mutation.
- `SessionState::transact(RequestFacts, grant, callback)` serializes mutations by stable shard/key, checks request/replay claims, and exposes bounded state operations; no network/database calls occur while a shard lock is held.
- `ProtocolService::handle(requestBytes, relayCredential) -> Expected<Bytes, Error>` dispatches to existing v2 request types and returns exact authenticated canonical response bytes.

- [ ] **Step 1: Write failing tests** for denied-by-default policy, wrong relay credential, caller-controlled subject/scopes/device/expiry, unregistered/revoked build, region/mode mismatch, and expired policy.
- [ ] **Step 2: Write failing state tests** for per-request idempotency, client/server nonce+ephemeral uniqueness, monotonic per-session/region generation, counter uniqueness, and session close/expiry behavior.
- [ ] **Step 3: Run focused tests** and confirm they fail on absent policy/service/state contracts.
- [ ] **Step 4: Implement fixed relay principal mapping** to a stable backend-derived anonymous subject per build; do not derive identity from client device/session fields.
- [ ] **Step 5: Implement sharded in-memory maps** with bounded record counts/bytes, explicit expiry handling, lock ordering, and held snapshot generation during each request.
- [ ] **Step 6: Implement server-side X25519 response sealing and Ed25519 transcript signature** using the exact existing protocol labels/fields and OpenSSL APIs; compare generated vectors against current Node/C++ client fixtures.
- [ ] **Step 7: Ensure session/material issuance never falls back from operation mode and never mutates generation/counter state before all schema/policy/replay preconditions pass.**
- [ ] **Step 8: Run focused service CTest cases plus existing `test_cloud_material_lease.py`, `test_cloud_material_lifecycle.py`, and native client protocol tests.**

### Task 4: Implement Checksummed Application WAL, Replay, and Checkpoints

**Files:**
- Create: `runtime/cloud_material_backend/state_wal.h`
- Create: `runtime/cloud_material_backend/state_wal.cpp`
- Create: `runtime/cloud_material_backend/checkpoint.h`
- Create: `runtime/cloud_material_backend/checkpoint.cpp`
- Create: `utils/CloudMaterialWalTest.cpp`
- Modify: `runtime/cloud_material_backend/session_state.{h,cpp}`

**Interfaces:**
- `StateWal::appendAndSync(sequence, StateDelta, exactResponse) -> Expected<CommitIndex, Error>` returns only after a complete checksummed record is durably flushed.
- `StateWal::recover(checkpoint) -> Expected<RecoveredState, Error>` applies monotonic records in sequence and returns state plus last committed sequence.
- `Checkpoint::writeAtomic(state, sequence)` uses private temp file, write-all, fsync, atomic rename, directory fsync, then WAL segment retirement covered by the checkpoint.
- Record format is versioned, length-prefixed, bounded, sequence-numbered, and checksummed; unknown versions and complete bad-checksum records are fatal.

- [ ] **Step 1: Write failing WAL tests** for exact replay, exact cached response recovery, sequence monotonicity, max-record limit, short write, fdatasync failure, duplicate sequence, and checksum mismatch.
- [ ] **Step 2: Write crash-boundary tests** for partial final header/body, complete corrupt final frame, interior corrupt frame, checkpoint temp write, rename, directory fsync, and WAL retirement ordering.
- [ ] **Step 3: Run focused WAL tests** and confirm expected failures.
- [ ] **Step 4: Implement record framing/checksum** with explicit endian encoding, fixed checksum algorithm, maximum record size, checked arithmetic, and no native struct serialization.
- [ ] **Step 5: Implement append+fdatasync** and ensure SessionState publishes the new in-memory state only after the WAL commit succeeds.
- [ ] **Step 6: Implement startup recovery:** replay complete valid frames; truncate only a final frame proven incomplete by EOF before declared size; fail closed on complete checksum mismatch, interior corruption, invalid epoch/sequence, or unknown record version.
- [ ] **Step 7: Implement atomic checkpoints** with directory fsync before deleting covered WAL files; test restart at each crash boundary.
- [ ] **Step 8: Add replay tests** that restart after committed request and prove exact response bytes return with no generation/counter reuse.
- [ ] **Step 9: Run WAL/service tests under sanitizers where supported and the complete backend native suite.**

### Task 5: Implement Backend Runtime Ownership, Config, and HTTP Routes

**Files:**
- Create: `runtime/cloud_material_backend/main.cpp`
- Create: `runtime/cloud_material_backend/config.h`
- Create: `runtime/cloud_material_backend/config.cpp`
- Create: `runtime/cloud_material_backend/http_server.h`
- Create: `runtime/cloud_material_backend/http_server.cpp`
- Create: `runtime/cloud_material_backend/process_lock.h`
- Create: `runtime/cloud_material_backend/process_lock.cpp`
- Create: `utils/CloudMaterialBackendHttpTest.cpp`
- Modify: `runtime/cloud_material_backend/CMakeLists.txt`
- Create: `runtime/cloud_material_backend/deploy/README.md`

**Interfaces:**
- `BackendConfig::fromEnvironment()` accepts explicit SQLite path, state/WAL directory, loopback port, relay/admin credentials, trusted-time provider, key provider, and hard request/timeout/concurrency caps; no defaults for security-sensitive secrets.
- `ProcessLock::acquire(stateDir)` obtains an exclusive nonblocking OS lock and records diagnostic PID/start identity; second owner fails before opening mutable WAL.
- `HttpServer` binds only `127.0.0.1`, accepts fixed `POST /v2/relay`, fixed admin routes, public trust-bundle GET, and health/readiness GET; TLS is terminated by the documented reverse proxy.
- Relay request contract is the closed `{protocol, request_b64}` JSON envelope; success contract is `{protocol, response_b64}` with exact original protocol bytes.

- [ ] **Step 1: Write failing config/ownership tests** for missing paths/secrets/providers, weak bounds, unsafe bind address, second-process lock, forked child, and stale-lock recovery.
- [ ] **Step 2: Write failing HTTP tests** for fixed methods/routes, duplicate/unknown fields, wrong content type, auth separation, oversized chunked input/output, slow input, disconnect, compression, no CORS, and generic errors.
- [ ] **Step 3: Run focused tests** and confirm missing server/config/lock implementations.
- [ ] **Step 4: Implement config validation and process lock**; ensure lock acquisition precedes SQLite mutable connection and WAL recovery.
- [ ] **Step 5: Implement bounded HTTP parser/listener** on loopback only. Reject non-identity content encoding, stop reading after cap, enforce header/body/idle/total timeouts and concurrency limits, and never trust forwarded headers for authorization.
- [ ] **Step 6: Implement runtime/admin/trust/health routes** with distinct credential paths and redacted structured error codes; admin input gets a separate bounded limit matching supported registration size.
- [ ] **Step 7: Implement startup readiness order:** config -> process lock -> SQLite schema check -> WAL/checkpoint recovery -> full build snapshot validation -> trusted time/key checks -> listener. Any failure exits without listening.
- [ ] **Step 8: Add local reverse-proxy HTTPS integration test** proving TLS validation at the proxy, fixed path forwarding, and independent relay/admin credentials.
- [ ] **Step 9: Add a non-root Linux deployment guide** at `runtime/cloud_material_backend/deploy/README.md`, covering application files read-only, separately permissioned SQLite/state directories, secrets supplied outside image layers, backups, recovery, checkpoint, and credential rotation. Do not add container, service-manager, or deployment packaging files unless explicitly approved.
- [ ] **Step 10: Run all backend HTTP, service, snapshot, WAL, and protocol tests.**

### Task 6: Integrate the Zeno Relay Without Changing `capability_v1`

**Files:**
- Modify: `/data/user/0/com.termux/files/home/xollvm-android/capability_v1.js`
- Modify: `/data/user/0/com.termux/files/home/xollvm-android/test/capability_v1.test.js` (confirmed existing Zeno test file).
- Test helper: `runtime/cloud_material_backend` local HTTPS fixture from Task 5.

**Interfaces:**
- Keep the existing `exports.capability_v1`, `buildCapabilityResponse`, normalization, canonicalization helpers, and legacy response generation unchanged.
- Dispatch explicit `capability_v1` to the original implementation; dispatch explicit `xovm2_relay` only to fixed HTTPS `/v2/relay` with `XOVM2_BACKEND_ORIGIN`, `XOVM2_RELAY_TOKEN`, and bounded timeout configuration.
- Relay helper forwards exact canonical request bytes, rejects redirects/compression/non-200/malformed response, and returns exact canonical response bytes without interpreting or signing them.

- [ ] **Step 1: Snapshot current valid and invalid legacy outputs byte-for-byte** before editing `capability_v1.js`.
- [ ] **Step 2: Add failing dispatch tests** to the existing `test/capability_v1.test.js`, proving legacy never calls relay, relay never calls legacy response logic, missing/unknown/ambiguous protocol fails closed, and legacy defaults remain unchanged.
- [ ] **Step 3: Write failing HTTPS transport tests** for exact request body, fixed origin/path, service credential, timeout, redirects, compression, caps, malformed response, and secret-free errors.
- [ ] **Step 4: Implement only the explicit dispatcher and fixed HTTPS transport** in the deployed function file; do not import code from the LLVM worktree at runtime.
- [ ] **Step 5: Run `node --test /data/user/0/com.termux/files/home/xollvm-android/test/capability_v1.test.js`, legacy snapshots, relay transport tests, and local HTTPS backend end-to-end request/response authentication fixture.**

### Task 7: Recovery, Performance, and User-Operated Deployment Acceptance

**Files:**
- Create: `utils/test_cloud_material_backend_acceptance.py` for process-restart acceptance and crash-boundary orchestration.
- Modify: `runtime/cloud_material_backend/deploy/README.md`.
- Modify: `docs/superpowers/specs/2026-10-22-cloud-material-relay-design.md` only for verified details consistent with approved architecture.

**Interfaces:**
- Acceptance harness launches backend with temporary SQLite/WAL directories and synthetic keys/registration, sends session-open/material requests through local HTTPS, stops/restarts process, and verifies authenticated exact retry response.
- Benchmark reports separate warm in-memory registration lookup, state transition+fdatasync, full relay round trip, and cold startup recovery; it does not claim performance without measurements on target hardware.

- [ ] **Step 1: Write failing process-restart acceptance tests** for committed response replay, counter/generation monotonicity, nonce replay fences, checkpoint recovery, and failed WAL sync response behavior.
- [ ] **Step 2: Add crash injection at append, sync, checkpoint write, rename, directory sync, and covered-WAL deletion boundaries.**
- [ ] **Step 3: Run tests and confirm the missing recovery behavior fails before implementation.**
- [ ] **Step 4: Implement only fixes required by the red recovery tests; rerun the full C++ backend suite after each fix.**
- [ ] **Step 5: Run Python material regressions:** `PYTHONDONTWRITEBYTECODE=1 XOLLVM_PROJECT_ROOT=/data/user/0/com.termux/files/home/xollvm-android python -m pytest -q utils/test_cloud_material_protocol.py utils/test_cloud_material_package.py utils/test_cloud_material_reencode.py utils/test_cloud_material_lease.py utils/test_cloud_material_lifecycle.py utils/test_zone_runtime_concurrency.py`.
- [ ] **Step 6: Run `ctest --test-dir build/cloud_material_backend --output-on-failure`, existing C++ material package tests, and `node --test /data/user/0/com.termux/files/home/xollvm-android/test/capability_v1.test.js`; inspect `git diff --check` and verify no user-modified files were reverted.**
- [ ] **Step 7: Document measured target-host latency/throughput, SQLite/state/WAL backup and restore, disk-full behavior, credential rotation, and one-instance limit.**
- [ ] **Step 8: Do not deploy or run live tests. User/operator deployment and explicit live-test request remain required.**

## Deferred Scope

- Multi-instance or multi-host shared session state, replication, consensus, and failover are out of scope. They require a separate architecture review because the single-writer WAL is authoritative.
- Database product migrations beyond SQLite, remote object storage, and online multi-writer administrative control are out of scope for initial single-instance deployment.
- Performance target numbers are intentionally not invented; measure on the selected target host before setting SLOs.
