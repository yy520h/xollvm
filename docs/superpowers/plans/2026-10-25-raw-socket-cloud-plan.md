# Raw Socket Cloud Protocol Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the client-facing HTTP/TLS relay boundary with a minimal authenticated raw TCP protocol, using direct AArch64 socket syscalls on Android and a C++20 server exposing only announcement, update, algorithm material, remote variables, account login, and card login operations.

**Architecture:** Keep the existing X25519/Ed25519/HKDF/AEAD primitives and replay/generation/WAL state machine, but place them behind a length-delimited binary frame protocol. The client transport calls AArch64 Linux syscalls for `socket`, `connect`, `send`, `recv`, and `close`; it does not call libc network wrappers. The server remains a normal C++20 process using libc, SQLite, and a TCP listener. Existing v1 HTTP/package tests remain compatibility tests until the new protocol has equivalent coverage.

**Tech Stack:** C++20, Android AArch64 syscall ABI, TCP, X25519, Ed25519, HKDF-SHA256, AES-256-GCM or ChaCha20-Poly1305, SQLite/WAL, CMake, Python tests.

**Spec:** `docs/superpowers/specs/2026-10-25-dynamic-vm-window-ratchet-design.md`, sections 8.5 and 9.

## Global Constraints

- The client network hot path must not call libc `socket/connect/send/recv` wrappers.
- The client ELF is not required to be completely independent of `libc.so`; only the network syscall path is specialized.
- The first client transport binds a compile-time IP/port and does not implement DNS.
- TLS, HTTPS, HTTP, REST, GraphQL, redirects, and server-supplied trust roots are not part of the client protocol.
- Every encrypted frame binds its fixed header, transcript hash, direction, key version, and sequence as AEAD AAD.
- Production builds disable debug provider, fault injection, plaintext material logs, and local bypass paths.
- Account and card credentials are sent only inside an authenticated AEAD session; card secrets are never VM material keys.
- Existing `encoded_bc + decode_map` remains v1 compatibility data and is not expanded as the new algorithm API.
- Debug and production artifacts use different profiles, trust bundles, software/build identities, and protocol configuration.

## Review Focus

- Partial TCP writes/reads and sticky packets must reconstruct exactly one bounded frame; owned by Task 2 tests.
- Sequence rollback, duplicate request, wrong direction, wrong session, and oversized payload must fail before handler dispatch; owned by Task 3 tests.
- A fake server with a different Ed25519 key or transcript must be rejected; owned by Task 3 tests.
- A debug endpoint or debug trust bundle must not be accepted by a production client; owned by Task 4 tests.
- Missing production provider/key/config must prevent listener readiness rather than start in permissive mode; owned by Task 5 tests.

---

### Task 1: Freeze Raw Protocol Schema and Crypto Boundary

**Files:**
- Create: `runtime/cloud_material/raw_protocol.h`
- Create: `runtime/cloud_material/raw_protocol.cpp`
- Create: `runtime/cloud_material/raw_frame.h`
- Create: `runtime/cloud_material/raw_frame.cpp`
- Modify: `runtime/cloud_material/material_protocol.h`
- Modify: `runtime/cloud_material/material_protocol.cpp`
- Test: `utils/test_cloud_material_raw_protocol.py`
- Test: `cloud/material_v2/test/raw_protocol.test.mjs`

**Interfaces:**
- Produces `RawHello`, `RawServerHello`, `RawFrameHeader`, `RawFrameType`, `RawSessionTranscript`, canonical encode/decode functions, and maximum-size constants.
- Produces `encodeRawFrameHeader(const RawFrameHeader&, ByteSpan)` and `decodeRawFrameHeader(ByteSpan)` with strict length/version validation.
- Produces `deriveRawSessionKeys(const RawSessionTranscript&, ByteSpan shared_secret)` returning direction-separated `K_c2s`, `K_s2c`, `K_material`, and `K_control`.
- Consumes the existing X25519, Ed25519, HKDF, and AEAD primitives without changing v1 package parsing.

- [ ] **Step 1: Write failing schema tests** for canonical HELLO/SERVER_HELLO, fixed header widths, maximum payload, unknown frame type, duplicate fields, and transcript ordering.
- [ ] **Step 2: Run the focused tests** and verify failures identify the missing raw protocol types or validation.
- [ ] **Step 3: Implement the fixed binary schema** with explicit endian conversion, bounded lengths, no JSON, and no server-supplied endpoint/trust-root fields.
- [ ] **Step 4: Implement transcript hashing and direction-separated HKDF labels** using the existing crypto implementation; reject zero/invalid ephemeral keys and mismatched transcript fields.
- [ ] **Step 5: Add Node/C++ golden vectors** for the same transcript, derived keys, header bytes, and AEAD AAD bytes.
- [ ] **Step 6: Run `python3 utils/test_cloud_material_raw_protocol.py` and the focused Node test**; expect all vectors and malformed-input cases to pass.
- [ ] **Step 7: Commit the schema boundary** with `git add runtime/cloud_material/raw_protocol.h runtime/cloud_material/raw_protocol.cpp runtime/cloud_material/raw_frame.h runtime/cloud_material/raw_frame.cpp runtime/cloud_material/material_protocol.h runtime/cloud_material/material_protocol.cpp utils/test_cloud_material_raw_protocol.py cloud/material_v2/test/raw_protocol.test.mjs && git commit -m "feat: add raw socket protocol schema"`.

### Task 2: Add Direct AArch64 Syscall Client Transport

**Files:**
- Create: `runtime/cloud_material/raw_socket_syscall_aarch64.h`
- Create: `runtime/cloud_material/raw_socket_syscall_aarch64.cpp`
- Create: `runtime/cloud_material/raw_socket_transport.h`
- Create: `runtime/cloud_material/raw_socket_transport.cpp`
- Modify: `runtime/cloud_material/CMakeLists.txt`
- Test: `utils/test_cloud_material_raw_socket_transport.py`
- Test: `runtime/cloud_material/raw_socket_transport_test.cpp`

**Interfaces:**
- Produces `RawSocketFd::connectIpv4(uint32_t address, uint16_t port, Deadline)`, `sendAll(ByteSpan, Deadline)`, `recvExact(size_t, Deadline)`, `close()`, and `RawFrameTransport::roundTrip(...)`.
- The syscall wrapper returns negative errno values in a stable internal type and contains no calls to libc socket APIs.
- The transport handles partial I/O, `EINTR`, timeout, peer close, frame-size limits, and protocol shutdown.

- [ ] **Step 1: Write a failing symbol/behavior test** that links the client transport and checks exact-frame reconstruction over a local test socket while forcing short writes and short reads.
- [ ] **Step 2: Add an AArch64 syscall-number table** for Android Linux and compile-time architecture guards; fail the build for unsupported architectures instead of silently using libc wrappers.
- [ ] **Step 3: Implement syscall-only `socket/connect/send/recv/close`**. Use compile-time bound IPv4/IPv6 address structures; do not add DNS.
- [ ] **Step 4: Implement bounded frame send/receive** over the syscall layer, including `EINTR`, partial operations, maximum frame length, and deadline handling.
- [ ] **Step 5: Add a test-only injected syscall table** so unit tests can force partial I/O and errno paths without replacing production syscall instructions.
- [ ] **Step 6: Run the C++ transport test and Python integration test**; use `nm`/`objdump` on the client object to assert no unresolved `socket`, `connect`, `send`, `sendto`, `recv`, `recvfrom`, or `close` symbols exist in the transport object.
- [ ] **Step 7: Commit the transport** with `git add runtime/cloud_material/raw_socket_syscall_aarch64.h runtime/cloud_material/raw_socket_syscall_aarch64.cpp runtime/cloud_material/raw_socket_transport.h runtime/cloud_material/raw_socket_transport.cpp runtime/cloud_material/CMakeLists.txt utils/test_cloud_material_raw_socket_transport.py runtime/cloud_material/raw_socket_transport_test.cpp && git commit -m "feat: add syscall raw socket transport"`.

### Task 3: Implement C++ Session Handshake and Encrypted Frame Service

**Files:**
- Create: `runtime/cloud_material_backend/raw_server.h`
- Create: `runtime/cloud_material_backend/raw_server.cpp`
- Create: `runtime/cloud_material_backend/raw_session.h`
- Create: `runtime/cloud_material_backend/raw_session.cpp`
- Modify: `runtime/cloud_material_backend/protocol_service.h`
- Modify: `runtime/cloud_material_backend/protocol_service.cpp`
- Modify: `runtime/cloud_material_backend/CMakeLists.txt`
- Test: `utils/test_cloud_material_backend_raw_socket.py`
- Test: `runtime/cloud_material_backend/raw_session_test.cpp`

**Interfaces:**
- Produces a TCP listener that performs `HELLO -> SERVER_HELLO -> encrypted frame`.
- Produces `RawSession::acceptHello`, `deriveKeys`, `decryptFrame`, `encryptFrame`, `checkSequence`, and `close`.
- Routes only the six approved frame types; unknown/removed operations receive a bounded authenticated error and do not reach provider code.
- Reuses `ProtocolService` session/replay/generation state and existing WAL publication semantics.

- [ ] **Step 1: Write failing tests** for valid handshake, fake server signature, transcript mismatch, repeated sequence, sequence rollback, wrong direction, wrong session, bad tag, and oversized frame.
- [ ] **Step 2: Implement the TCP accept loop and bounded per-connection state**; reject readiness when signing/trust/provider dependencies are absent.
- [ ] **Step 3: Implement Ed25519 server signature verification material and X25519 ephemeral handshake** using the Task 1 transcript encoding.
- [ ] **Step 4: Implement AEAD frame decrypt/encrypt with direction-specific sequence and AAD binding**; reject before provider dispatch on any mismatch.
- [ ] **Step 5: Route `ANNOUNCEMENT`, `UPDATE`, `ALGORITHM_ACQUIRE`, `REMOTE_VARIABLES`, `LOGIN_ACCOUNT`, and `LOGIN_CARD`; remove HTTP-only assumptions from the new route while leaving v1 HTTP compatibility untouched.
- [ ] **Step 6: Run the focused C++ and Python process tests** and verify replay errors do not mutate WAL/session state.
- [ ] **Step 7: Commit the server boundary** with `git add runtime/cloud_material_backend/raw_server.h runtime/cloud_material_backend/raw_server.cpp runtime/cloud_material_backend/raw_session.h runtime/cloud_material_backend/raw_session.cpp runtime/cloud_material_backend/protocol_service.h runtime/cloud_material_backend/protocol_service.cpp runtime/cloud_material_backend/CMakeLists.txt utils/test_cloud_material_backend_raw_socket.py runtime/cloud_material_backend/raw_session_test.cpp && git commit -m "feat: add raw socket cloud session"`.

### Task 4: Add the Six Minimal Cloud APIs

**Files:**
- Create: `runtime/cloud_material_backend/cloud_api.h`
- Create: `runtime/cloud_material_backend/cloud_api.cpp`
- Modify: `runtime/cloud_material_backend/runtime_providers.h`
- Modify: `runtime/cloud_material_backend/runtime_providers.cpp`
- Modify: `runtime/cloud_material_backend/admin_repository.h`
- Modify: `runtime/cloud_material_backend/admin_repository.cpp`
- Test: `utils/test_cloud_material_backend_api.py`

**Interfaces:**
- Produces fixed-schema handlers for announcement, update metadata/chunks, algorithm `WindowGrant`, remote variables, account login/session refresh/logout, and card login/bind/unbind.
- Produces provider interfaces `AnnouncementProvider`, `UpdateProvider`, `WindowGrantProvider`, `RemoteVariableProvider`, `AccountAuthProvider`, and `CardAuthProvider`.
- Every response binds software/build/region/session/generation/version and has a size/type/expiry limit.

- [ ] **Step 1: Write failing provider-contract tests** for each of the six APIs, unknown fields, oversize content, expired announcement/update, wrong build, and card secret not being reused as material key.
- [ ] **Step 2: Implement closed canonical request/response schemas** with no arbitrary script/config execution and no full bytecode/decode_map response.
- [ ] **Step 3: Implement test providers backed by deterministic fixtures**; keep credentials, signing keys, and fixture secrets outside source-controlled production paths.
- [ ] **Step 4: Bind algorithm acquisition to the existing generation/counter/replay fence** and the new `WindowGrant` fields from the dynamic VM spec.
- [ ] **Step 5: Bind account/card login to an already authenticated AEAD session**; return a short session capability, never a VM root key.
- [ ] **Step 6: Run API tests and process-level restart/replay tests**; verify exact retry behavior and no WAL mutation on rejected requests.
- [ ] **Step 7: Commit the minimal API layer** with `git add runtime/cloud_material_backend/cloud_api.h runtime/cloud_material_backend/cloud_api.cpp runtime/cloud_material_backend/runtime_providers.h runtime/cloud_material_backend/runtime_providers.cpp runtime/cloud_material_backend/admin_repository.h runtime/cloud_material_backend/admin_repository.cpp utils/test_cloud_material_backend_api.py && git commit -m "feat: add minimal cloud api surface"`.

### Task 5: Separate Debug and Production C++ Profiles

**Files:**
- Modify: `runtime/cloud_material_backend/config.h`
- Modify: `runtime/cloud_material_backend/config.cpp`
- Modify: `runtime/cloud_material_backend/startup.cpp`
- Modify: `runtime/cloud_material_backend/main.cpp`
- Modify: `runtime/cloud_material_backend/CMakeLists.txt`
- Modify: `runtime/cloud_material_backend/deploy/README.md`
- Test: `utils/test_cloud_material_backend_startup.py`

**Interfaces:**
- Produces explicit `debug` and `production` profiles with distinct software/build identity, trust bundle, endpoint, provider set, and logging policy.
- Production startup fails closed when signing key, trust bundle, trusted time, CSPRNG, policy, or provider is missing.
- Debug mode binds loopback only and permits fake clock/fault injection only in test builds.

- [ ] **Step 1: Write failing startup tests** for missing production provider/key, debug provider accepted only by debug identity, production client rejecting debug trust identity, and endpoint override rejection.
- [ ] **Step 2: Implement profile parsing and identity binding**; do not use a runtime environment variable as a hidden production bypass.
- [ ] **Step 3: Remove new HTTP/TLS/reverse-proxy assumptions from the production raw listener documentation** while leaving legacy v1 status explicitly marked compatibility-only.
- [ ] **Step 4: Implement readiness checks and fail-closed startup** for all production dependencies.
- [ ] **Step 5: Run startup tests, CMake configure/build, Python suites, and `git diff --check`**.
- [ ] **Step 6: Commit profile separation** with `git add runtime/cloud_material_backend/config.h runtime/cloud_material_backend/config.cpp runtime/cloud_material_backend/startup.cpp runtime/cloud_material_backend/main.cpp runtime/cloud_material_backend/CMakeLists.txt runtime/cloud_material_backend/deploy/README.md utils/test_cloud_material_backend_startup.py && git commit -m "feat: separate cloud debug and production profiles"`.

## Plan Verification

- The spec's raw socket, application-layer authentication, six-function surface, C++ server, debug/production split, no-DNS first version, and libc network-wrapper constraint each map to a task above.
- Legacy HTTP/package code is deliberately not deleted in these tasks; it remains v1 compatibility until raw-socket process acceptance passes.
- No task treats direct syscalls as a root-proof boundary; tests report libc-wrapper avoidance, protocol security, and root/TTD limitations separately.
- No production secret, token, private key, or build artifact may be staged.
