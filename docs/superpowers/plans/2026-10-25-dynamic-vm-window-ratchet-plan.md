# Dynamic VM Window Ratchet Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the approved dynamic VM execution path: encrypted static artifact, authenticated small windows, 110/120-second lease rotation, Guardian/Worker handshake, continuation tails, short-lived W^X handler buffers, and side-effect-free chaff.

**Architecture:** The compiler/exporter produces an `EncryptedVmArtifact` containing encrypted bytecode blocks and handler shards but no plaintext execution package or global decode map. A C++ cloud provider issues small authenticated `WindowGrant` objects bound to session/generation/window state. A single protected ELF launches Guardian and Worker roles over controlled file descriptors; Worker consumes one window at a time and executes local continuation handlers in per-thread W^X buffers.

**Tech Stack:** LLVM C++20 pass/runtime, Android AArch64, C++20 cloud provider, X25519/Ed25519/HKDF/AEAD, `mmap/mprotect/__builtin___clear_cache`, socketpair/pidfd, CMake, native fixtures, Python/Node protocol tests.

**Spec:** `docs/superpowers/specs/2026-10-25-dynamic-vm-window-ratchet-design.md`, sections 1-7 and 9-11.

## Global Constraints

- No final ELF plaintext handler, full plaintext bytecode, full global decode map, static execution key, or session material.
- Do not expand `encoded_bc + decode_map`; keep it as v1 compatibility data.
- No global `opcode -> handler` table and no central semantic dispatch loop.
- Material absence before protected side effects is a synchronous fail-closed boundary.
- `renew_at = t0 + 110s`; `deadline = t0 + 120s`; pinned calls may finish, new calls need the new generation after deadline.
- Guardian/Worker are roles inside one protected delivery and must not rely on replaceable external helpers or `su` process injection.
- JIT memory is never RWX; plaintext handler cleanup is required after execution and on every supported exit path.
- Chaff has no business, external, persistent-log, floating-point, or exception side effects.
- This design does not claim to defeat a root-controlled TTD; tests must distinguish static extraction, cross-session replay, and current-run observation.

## Review Focus

- Artifact with missing or wrong window grant must produce zero protected business side effects; owned by Task 2 tests.
- Duplicate, skipped, expired, wrong-generation, and wrong-previous-state windows must be rejected; owned by Task 2 tests.
- Direct Worker launch, FD replacement, challenge replay, and Guardian death must fail before `main`; owned by Task 3 tests.
- W^X, instruction cache flush, nested handler buffers, and cleanup on normal return must be verified on Android AArch64; owned by Task 4 tests.
- Static audit must find no plaintext handler/full bytecode/global map and no central dispatch; owned by Task 5 tests.

---

### Task 1: Define Artifact, WindowGrant, and Continuation Schemas

**Files:**
- Create: `runtime/cloud_material/dynamic_vm_schema.h`
- Create: `runtime/cloud_material/dynamic_vm_schema.cpp`
- Create: `runtime/cloud_material/dynamic_vm_crypto.h`
- Create: `runtime/cloud_material/dynamic_vm_crypto.cpp`
- Modify: `runtime/cloud_material/material_abi.h`
- Modify: `runtime/cloud_material/material_store.h`
- Test: `utils/test_dynamic_vm_schema.py`

**Interfaces:**
- Produces `EncryptedVmArtifact`, `WindowGrant`, `ContinuationWindow`, `HandlerShardDescriptor`, and `GuardianChannelHello` structures with canonical encode/decode.
- Produces `validateWindowBinding`, `deriveWindowMaterial`, `advanceContinuation`, and secure cleanup helpers.
- Removes new-code dependence on `XovmMaterialView::decode_map`; v1 ABI remains available only to existing compatibility tests.

- [ ] **Step 1: Write failing tests** for canonical bytes, field limits, wrong build/region/session/generation/window, previous-state mismatch, expired grant, duplicate window, skipped window, and no decode-map field.
- [ ] **Step 2: Run the focused schema tests** and verify failures identify missing schema/validation rather than generic parser errors.
- [ ] **Step 3: Implement bounded binary schemas** with explicit field order, lengths, version, AAD preimage, and stable hash preimage.
- [ ] **Step 4: Implement HKDF domain separation** for window, permutation, decode, chaff, integrity, and JIT material bound to build/region/session/generation/window/previous-state.
- [ ] **Step 5: Implement a state machine that advances only from authenticated `previous_state_hash` to `next_state_hash`** and scrubs consumed material.
- [ ] **Step 6: Run the focused C++/Python tests and inspect `git diff --check`**.
- [ ] **Step 7: Commit the schemas** with `git add runtime/cloud_material/dynamic_vm_schema.h runtime/cloud_material/dynamic_vm_schema.cpp runtime/cloud_material/dynamic_vm_crypto.h runtime/cloud_material/dynamic_vm_crypto.cpp runtime/cloud_material/material_abi.h runtime/cloud_material/material_store.h utils/test_dynamic_vm_schema.py && git commit -m "feat: define dynamic vm window schema"`.

### Task 2: Build Encrypted Artifact and Window Provider

**Files:**
- Create: `runtime/cloud_material/dynamic_vm_artifact.h`
- Create: `runtime/cloud_material/dynamic_vm_artifact.cpp`
- Create: `runtime/cloud_material/dynamic_vm_window_provider.h`
- Create: `runtime/cloud_material/dynamic_vm_window_provider.cpp`
- Modify: `VMPass_Material.cpp`
- Modify: `runtime/cloud_material_backend/runtime_providers.h`
- Modify: `runtime/cloud_material_backend/runtime_providers.cpp`
- Modify: `runtime/cloud_material_backend/protocol_service.cpp`
- Test: `utils/test_dynamic_vm_artifact.py`
- Test: `utils/test_dynamic_vm_window_provider.py`

**Interfaces:**
- Produces `buildEncryptedVmArtifact(RegionRegistration, OutputPath)` and `issueWindowGrant(SessionState, WindowRequest)`.
- The artifact builder encrypts bytecode blocks and handler shards and records only public descriptors/commitments.
- The provider issues bounded windows and never returns full bytecode, full handler bundle, `decode_map`, or future window keys.

- [ ] **Step 1: Write failing artifact tests** that inspect output bytes and assert no plaintext canonical bytecode, handler marker, full map, or static session key remains.
- [ ] **Step 2: Implement artifact container and per-block authenticated encryption** with content hash, build/region identity, relocation descriptors, and versioned public ABI.
- [ ] **Step 3: Implement a deterministic debug provider** that uses test keys and fake time but emits the same production schema.
- [ ] **Step 4: Implement `issueWindowGrant` with generation/counter/replay/WAL binding** and previous/next state commitments.
- [ ] **Step 5: Add mismatch/expiry/replay tests and a process fixture** for valid grant, retry exact response, revoke, and restart recovery.
- [ ] **Step 6: Run artifact/provider tests and inspect output with `readelf`, `strings`, and a binary scanner**; expected result is no plaintext execution payload in the artifact/fixture ELF.
- [ ] **Step 7: Commit artifact/provider work** with `git add runtime/cloud_material/dynamic_vm_artifact.h runtime/cloud_material/dynamic_vm_artifact.cpp runtime/cloud_material/dynamic_vm_window_provider.h runtime/cloud_material/dynamic_vm_window_provider.cpp VMPass_Material.cpp runtime/cloud_material_backend/runtime_providers.h runtime/cloud_material_backend/runtime_providers.cpp runtime/cloud_material_backend/protocol_service.cpp utils/test_dynamic_vm_artifact.py utils/test_dynamic_vm_window_provider.py && git commit -m "feat: add encrypted vm artifact provider"`.

### Task 3: Add Launcher, Guardian, Worker, and Lease State Machine

**Files:**
- Create: `runtime/cloud_material/guardian_channel.h`
- Create: `runtime/cloud_material/guardian_channel.cpp`
- Create: `runtime/cloud_material/launcher.h`
- Create: `runtime/cloud_material/launcher.cpp`
- Modify: `runtime/cloud_material/material_runtime.cpp`
- Modify: `runtime/cloud_material/material_store.cpp`
- Test: `runtime/cloud_material/guardian_channel_test.cpp`
- Test: `utils/test_dynamic_vm_guardian.py`

**Interfaces:**
- Produces `Launcher::start`, `GuardianChannel::handshake`, `GuardianChannel::challenge`, `LeaseState::acquire`, `LeaseState::renewIfDue`, `LeaseState::pin`, and `LeaseState::release`.
- Uses `socketpair`, boot nonce, controlled inherited FD, process identity, challenge counter, generation, and state digest.
- Guardian handles session/renewal; Worker alone executes protected `main` and current window.

- [ ] **Step 1: Write failing tests** for direct Worker launch, missing FD, wrong boot nonce, FD replacement, Guardian death, challenge replay, generation rollback, and `t0+110s/t0+120s` behavior.
- [ ] **Step 2: Implement controlled launcher and role selection** without external helper binaries or `su` injection; direct Worker entry fails synchronously before protected side effects.
- [ ] **Step 3: Implement Guardian/Worker handshake and mutual challenge** with bounded messages and process-start identity checks.
- [ ] **Step 4: Implement lease state** using monotonic boot time: prefetch at 110 seconds, reject new old-generation acquire at 120 seconds, allow pinned calls to complete.
- [ ] **Step 5: Implement background renewal failure as a state mark**; only the next protected entry synchronously fails when no valid replacement grant exists.
- [ ] **Step 6: Run native and Python process tests**, including shutdown and fork/exec cleanup paths.
- [ ] **Step 7: Commit process/lease work** with `git add runtime/cloud_material/guardian_channel.h runtime/cloud_material/guardian_channel.cpp runtime/cloud_material/launcher.h runtime/cloud_material/launcher.cpp runtime/cloud_material/material_runtime.cpp runtime/cloud_material/material_store.cpp runtime/cloud_material/guardian_channel_test.cpp utils/test_dynamic_vm_guardian.py && git commit -m "feat: add dynamic vm guardian worker lease"`.

### Task 4: Implement AArch64 Handler Shards, W^X, and Continuation Tails

**Files:**
- Create: `runtime/cloud_material/jit_handler_buffer.h`
- Create: `runtime/cloud_material/jit_handler_buffer.cpp`
- Create: `runtime/cloud_material/continuation_executor.h`
- Create: `runtime/cloud_material/continuation_executor.cpp`
- Modify: `VMPass_Handlers.cpp`
- Modify: `VMPass_Dispatch.cpp`
- Modify: `VMPass_Impl.cpp`
- Test: `runtime/cloud_material/jit_handler_buffer_test.cpp`
- Test: `utils/test_dynamic_vm_continuation.py`

**Interfaces:**
- Produces `JitHandlerBuffer::allocateWritable`, `sealExecutable`, `flushInstructionCache`, `executeAndScrub`, and `ContinuationExecutor::runWindow`.
- Handler descriptors declare only approved AArch64 relocations and ABI references.
- No new code path may call a global opcode table, centralized semantic switch, or long-lived plaintext handler storage.

- [ ] **Step 1: Write failing Android AArch64 tests** for RWX rejection, RW-to-RX transition, cache flush, handler execution, cleanup, nested buffers, and unsupported relocation rejection.
- [ ] **Step 2: Implement page-granular buffer allocation and W^X transitions** using `mmap`, `mprotect`, and instruction-cache flush; never create RWX mappings.
- [ ] **Step 3: Implement authenticated handler shard decryption and relocation validation**; reject absolute/undeclared references before `RX`.
- [ ] **Step 4: Implement continuation tail execution** that obtains only the next local handler shard and does not materialize a global handler table or decode map.
- [ ] **Step 5: Remove the current cloud-material emission rejection only for the new schema-backed path**; keep unsupported legacy modes explicitly rejected.
- [ ] **Step 6: Run the native Android fixture on AArch64 and static source/ELF audits** for `switch(opcode)`, `global_handler_table`, `decode_map`, plaintext handler markers, RWX, and unresolved relocation symbols.
- [ ] **Step 7: Commit JIT/continuation work** with `git add runtime/cloud_material/jit_handler_buffer.h runtime/cloud_material/jit_handler_buffer.cpp runtime/cloud_material/continuation_executor.h runtime/cloud_material/continuation_executor.cpp VMPass_Handlers.cpp VMPass_Dispatch.cpp VMPass_Impl.cpp runtime/cloud_material/jit_handler_buffer_test.cpp utils/test_dynamic_vm_continuation.py && git commit -m "feat: add dynamic vm continuation execution"`.

### Task 5: Add Chaff, Integrity Coupling, and Final ELF Audit

**Files:**
- Create: `runtime/cloud_material/chaff_scheduler.h`
- Create: `runtime/cloud_material/chaff_scheduler.cpp`
- Create: `runtime/cloud_material/dynamic_vm_audit.cpp`
- Modify: `tools/xollvm-elf-hardener/MaterialManifest.cpp`
- Modify: `tools/xollvm-elf-hardener/xollvm-elf-hardener.cpp`
- Test: `utils/test_dynamic_vm_chaff.py`
- Test: `utils/test_dynamic_vm_final_audit.py`

**Interfaces:**
- Produces `ChaffScheduler::next` and `IntegrityState::advance` with fixed side-effect-neutral behavior.
- Produces an ELF audit that fails on plaintext handler/bytecode, full decode map, static secret, central dispatch, RWX, undeclared relocation, and missing material identity.

- [ ] **Step 1: Write failing chaff tests** for deterministic seed behavior, variant selection, no business-memory mutation, no external calls, no persistent output, no return/exception/FP changes, and return to true continuation.
- [ ] **Step 2: Implement bounded chaff variants** using only scratch state and authenticated window seed; keep chaff out of the authorization boundary.
- [ ] **Step 3: Implement integrity state as an input to the next continuation/window commitment** without introducing a single `if (valid) execute else fail` hot-path gate.
- [ ] **Step 4: Implement final ELF/material audit** and integrate it into `xollvm-elf-hardener materials`.
- [ ] **Step 5: Run all VM native/Python/Node suites, AArch64 fixture, `readelf`/scanner audit, and `git diff --check`**.
- [ ] **Step 6: Commit chaff/audit work** with `git add runtime/cloud_material/chaff_scheduler.h runtime/cloud_material/chaff_scheduler.cpp runtime/cloud_material/dynamic_vm_audit.cpp tools/xollvm-elf-hardener/MaterialManifest.cpp tools/xollvm-elf-hardener/xollvm-elf-hardener.cpp utils/test_dynamic_vm_chaff.py utils/test_dynamic_vm_final_audit.py && git commit -m "feat: add dynamic vm chaff and elf audit"`.

## Plan Verification

- Sections 1-7 of the approved spec map to Tasks 1-5; no task returns the old full package/decode-map execution model.
- The cloud provider dependency is expressed as `issueWindowGrant`; raw transport is handled by the separate raw-socket plan.
- Direct syscalls are not treated as a root-proof boundary, and Guardian/Worker is tested as a bypass-cost/fault-detection layer.
- Tests cover artifact secrecy, window replay, lease timing, process handshake, W^X, continuation absence of central dispatch, chaff neutrality, and final ELF audit.
- This plan does not introduce TEE, remote business operation authority, or production credentials.
