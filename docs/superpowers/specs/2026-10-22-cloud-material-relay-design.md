# XOVM2 Cloud-Function Relay Design

Date: 2026-10-22
Status: Architecture revision for user review. The user confirmed a C++ backend with database-owned durable data loaded into C++ process memory for request-time access. The previous Node.js/PostgreSQL implementation plan is superseded and must not be executed as written.

## 1. Goal and Scope

Add an independently selectable XOVM2 relay mode to the existing Zeno cloud-algorithm entry point. Preserve `capability_v1` as a separate mode with its existing backend-controlled card-login policy. In relay mode, Zeno is configured to allow calls without card login; the cloud function forwards the XOVM2 request to an operator-hosted C++ backend, which owns material authorization policy, registration, protocol signing keys, trusted time, session state, and durable transaction state.

The cloud function is a narrow server-side proxy, not an authentication oracle. The relay mode does not claim Zeno card authorization, trusted device identity, hardware attestation, or resistance to a caller who can invoke the public cloud function repeatedly.

This design covers the end-to-end relay architecture and interfaces. It does not deploy the backend, configure a live endpoint, select production credentials, or claim production readiness before the operator supplies and deploys those components.

## 2. Two Independently Configured Modes

The deployed cloud function remains `node_js_code.processStringAndInt`. It normalizes the event once, validates a bounded request discriminator, and branches:

- `capability_v1`: execute the existing request validation, response generation, signature, and response shape unchanged. Existing Zeno settings continue to determine whether card login is required.
- `xovm2_relay`: forward only the closed XOVM2 request schema to the configured backend and return its bounded response bytes without interpreting or re-signing the protocol envelope.

Unknown protocol values, malformed events, unknown fields, and ambiguous wrappers fail closed. Relay mode never falls back to `capability_v1`, and `capability_v1` never forwards to the relay.

The cloud deployment configuration contains a fixed HTTPS backend base URL and a relay service credential. These are deployment secrets/configuration, not request fields. The relay code does not accept a caller-supplied destination URL, host, port, path, HTTP method, or header. Redirects are disabled. The existing `capability_v1` HMAC/signing keys are not reused as relay credentials or XOVM2 protocol keys.

## 3. Request Flow

1. The VM client creates a canonical XOVM2 session or material request using the existing v2 protocol.
2. The client invokes the configured Zeno cloud algorithm. In relay mode, Zeno may permit this call without card login, as selected by the operator.
3. `capability_v1.js` normalizes the supported event wrapper, validates the request discriminator and encoded request, applies a strict byte limit, then sends an HTTPS POST to one fixed backend route. It adds a cloud-to-backend service credential that is unavailable to the client.
4. The backend authenticates the relay credential, applies source/principal rate limits and request limits, then routes the request to the existing XOVM2 protocol service.
5. The backend returns the exact canonical v2 response bytes. The cloud function enforces the response limit and returns those bytes through the Zeno cloud-algorithm result without translating protocol fields.
6. The client performs its existing canonical parsing, signature, transcript, AEAD, package, identity, and timing checks. Cloud-function success alone never makes material executable.

Session establishment and `material.issue` are distinct v2 request types and both use the relay. Existing operation-mode refusal remains in force; the relay must not silently downgrade `operation` to `session` or `lease`.

The relay request never contains private registration or verifier-sidecar bytes. Runtime requests reference only a build/region identity. If a client requests session establishment, the backend creates the corresponding bounded anonymous principal/session using its own relay policy.

## 4. C++ Backend, Memory-Resident Data, and Persistence

The backend is a native C++ service. It must preserve the existing XOVM2 wire format and security rules. Request-time lookups use process memory, not a database query per request.

- The durable database is the source of truth for build registration, verifier sidecars, artifact identities, and administrative policy. The exact database product and schema are implementation-plan decisions; PostgreSQL is not a protocol requirement.
- On startup, the C++ process validates and loads all enabled build manifests, matching private registrations, verifier sidecars, active build/revocation state, and public trust metadata into a validated immutable snapshot in dynamic memory. Runtime issuance reads this snapshot directly.
- Administrative import, enable, or revoke writes durable state first, validates the complete resulting build set, then atomically publishes a new immutable in-memory snapshot. A failed write or validation must leave the old snapshot active; a failed snapshot publication must fail the admin operation and trigger reconciliation before further issuance.
- Production Ed25519 signing keys are held by a dedicated key provider, not by the database snapshot. X25519 ephemeral values use the existing cryptographic requirements. Trust bundles are signed and distributed through the existing client bootstrap contract.
- The C++ process owns mutable session state, counters, per-region generation allocation, request idempotency replies, and client/server nonce/key replay claims in sharded in-memory structures. A single-process, single-instance deployment is the initial supported topology.
- An append-only WAL persists state mutations before an operation is acknowledged as committed. WAL records are framed, versioned, checksummed, bounded, and replayed in order at startup; periodic checkpoints bound recovery time. WAL append/flush failure fails the state-changing request closed and does not return an apparently committed response.
- Checkpoint publication is atomic and crash-safe: write a new checkpoint to a private temporary file, fsync it, atomically rename it, fsync the containing directory, then retire only WAL segments fully covered by that checkpoint.
- Startup recovery validates checkpoint/WAL integrity and replays complete committed records in sequence. It may truncate only a final record that is provably incomplete because EOF occurs before its declared frame length; a complete frame with a bad checksum, interior corruption, invalid sequence/epoch transition, or unknown record version fails startup.
- Exactly one process may own the mutable state/WAL directory at a time, enforced by an exclusive OS lock and process identity. Concurrent writers and multi-instance deployment are unsupported in this design.
- Durable build registration is keyed by exact `build_id`, `region_id`, and final artifact identity.
- Trusted server time and rate/budget policy are required. Build and region authorization is checked against the in-memory immutable snapshot before mutable session state is changed.

### 4.1 Anonymous Policy

- Authentication of the cloud-function relay credential, strict HTTP method/path/content-type checks, no redirects, body/header/response limits, timeouts, and redacted errors.
- Per-build policy deciding whether anonymous session creation/material requests are enabled. Unregistered, disabled, revoked, incompatible, or expired builds fail closed.

Build registration and verifier sidecars are persisted by the backend and are not embedded in `capability_v1.js`. An administrator imports a public manifest plus its matching private registration and verifier sidecars through a separate authenticated administrative path. That path validates exact public/private membership, content hashes, canonical regions, verifier bytes, software/build/region identities, and final artifact identity before atomically enabling a build. Registration upload and build enablement are never exposed through the anonymous runtime relay credential.

Relay mode is intentionally usable without Zeno card login. Its backend grant is therefore an anonymous, policy-scoped grant, not a user-authenticated grant. It may be scoped to one build and its registered regions, has a short bounded lifetime, and must not claim a trusted device identity from request fields. Repeated access can be limited by relay credential, source network, build, and rate/budget policy, but a shared cloud-function credential does not distinguish individual callers. Strong per-user authorization requires a separate trusted identity source and is outside this anonymous mode.

The backend maps the authenticated relay service principal to a restricted anonymous authorization principal. Client-selected session IDs, nonces, device strings, and build/region fields remain protocol bindings and replay identifiers; they do not become user identity. Anonymous policy must explicitly decide which builds/regions may create anonymous sessions and issue session/lease material, the maximum lifetime and request rate, and how revocation disables new sessions/material. The backend must not accept client-supplied `subject_id`, scopes, or expiry as authority.

The prior Node `ReferenceMemoryStore` remains a protocol test fixture and is not a production C++ adapter. Production startup must fail closed until the durable database, immutable snapshot loader, WAL/checkpoint recovery, single-writer lock, trusted time, key provider, registration validation, relay authentication, and anonymous policy are all present and self-checked.

## 5. HTTP and Cloud-Function Boundary

The C++ backend exposes a single configured HTTPS base URL and versioned fixed route(s), not a generic URL proxy. The route contract carries a protocol discriminator and the canonical request bytes; response data carries the exact canonical v2 envelope bytes. The cloud function forwards neither arbitrary client headers nor cookies and does not log credentials, request secrets, plaintext packages, or private keys.

Both request and response are bounded before full allocation. The function uses explicit connect/total timeouts, verifies TLS, rejects redirects and compressed responses, checks response content type and status, and returns a stable generic error on transport failure. Error details remain in protected server logs with secrets and payload contents redacted.

The concrete runtime and administrator route names, deployment environment-variable names, Zeno event wrapper variants, and transport byte encoding are implementation-plan decisions to confirm against the operator's hosting environment before implementation. They must not weaken the closed protocol or permit URL selection by the caller. Runtime relay and registration administration use different credentials, routes, and authorization scopes.

## 6. Compatibility and Rollout

- Keep the deployed function name and `capability_v1` export/handler contract.
- Default protocol behavior remains the existing `capability_v1` path; relay requires an explicit XOVM2 discriminator.
- Do not change the old mode's card-login configuration or response schema.
- Introduce relay backend deployment and health/configuration independently. An unavailable or misconfigured relay returns failure and never falls back to the legacy protocol.
- Test the backend and relay with public test credentials, synthetic registrations, and local HTTPS fixtures before the operator deploys either service.
- Production testing occurs only after the user deploys the backend and updates the cloud-function endpoint/configuration, then explicitly requests live testing.

## 7. Security and Failure Behavior

- The cloud function's service credential prevents direct unauthenticated use of the backend route, but does not prevent abuse through the public cloud function. Rate limiting and anonymous-build policy are required.
- The backend's memory state is authoritative only for the lifetime of its exclusive process lock; a second process must not start against the same mutable WAL/state directory.
- A success response is returned only after its state transition and exact idempotent response are durably recorded under the configured WAL durability policy. Storage failure returns failure and does not advance externally visible state.
- Build-snapshot refresh uses durable revision/epoch checks and atomic publication. A process must not serve a revoked or older snapshot after acknowledging a successful revoke.
- WAL/checkpoint files and database registration data are sensitive: restrict filesystem/database permissions, exclude them from images and source control, and define backup encryption, retention, integrity verification, and restore drills.
- HTTPS protects the relay hop; the XOVM2 response signature and AEAD remain independently mandatory end-to-end.
- A leaked relay credential permits backend access within configured policy until rotated. Rotation and revocation must be supported operationally.
- Caller-supplied `software_id`, `build_id`, `region_id`, `session_id`, `device_id`, and client time are binding inputs only, not proof of authorization or device identity.
- Timeout, oversized body, non-success backend status, invalid response encoding, and backend unavailability fail closed. No retry may alter the original client's signed request, nonce, ephemeral key, or timing context. Identical transport retries are governed by v2 request idempotency.
- Logs and errors expose only bounded non-secret request identifiers/error codes; no full payload or credential is emitted.

## 8. Acceptance Criteria

- Existing `capability_v1` tests and canonical output remain unchanged for valid and invalid legacy requests.
- Protocol routing tests prove legacy requests never invoke the relay and XOVM2 requests never execute legacy response logic.
- Cloud relay tests cover wrapper normalization, exact body forwarding, fixed destination enforcement, service-auth header handling, timeout, redirect rejection, request/response caps, malformed responses, and secret-free errors/logging.
- C++ backend tests cover snapshot load and atomic swap, invalid/partial registration rejection, stale snapshot/revocation handling, single-writer lock exclusion, WAL append/flush failure, replay after restart, incomplete final WAL record recovery, interior corruption fail-closed, checkpoint crash boundaries, anonymous-policy allow/deny, idempotent retries, replay fences, generation monotonicity, and trust/key expiry.
- Performance acceptance measures warm in-memory lookup and end-to-end relay latency separately from cold startup recovery; request processing must not issue database queries for registration or verifier lookups.
- A restart test proves committed sessions/counters/replay claims and exact cached replies recover from WAL/checkpoint without reuse or duplicate issuance.
- End-to-end local tests pass a synthetic XOVM2 request through the cloud relay adapter to the backend and verify that the VM client accepts only the backend's authenticated response.
- Separate tests prove legacy behavior works with card-login gating configured on or off; relay behavior is independent of that setting and does not imply card authorization.
- Live deployment validation is a separate user-triggered step after the operator deploys and configures the backend.

## 9. Open Deployment Inputs

These are deployment values, not reasons to change the protocol design; capture them in the implementation plan and require them before live testing:

- Backend HTTPS origin and fixed route path(s).
- C++ server framework/TLS termination, supported Linux distribution/runtime, CPU and memory budget, backend hosting, and how secrets/environment variables are provisioned and rotated.
- Administrator identity/credential mechanism and approved process for importing registrations and enabling/revoking builds.
- Durable database product/transaction implementation for administrative records, WAL filesystem/device durability guarantees, checkpoint cadence/size limits, and trusted-time provider.
- Confirmation that initial deployment is one C++ process on one server with exclusive local state ownership; multi-instance support is explicitly out of scope unless separately designed.
- WAL acknowledgment durability target (default: `fdatasync`/equivalent durable flush of the state transition and exact idempotent response before returning success), storage-device guarantees, and checkpoint cadence/size limits.
- Public trust-bundle delivery and client bootstrap metadata path.
- Anonymous relay rate/budget policy and per-build enablement procedure.
- Zeno's exact maximum input/output sizes, timeout behavior, and whether a returned string preserves binary/base64 response content exactly.
