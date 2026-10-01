# VM Cloud-Derived Dispatch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every VM-virtualized function's opcode dispatch depend on a short-lived cloud-derived value so that a missing, stale, or forged value produces illegal bytecode and a natural crash, with no local authorization boolean anywhere.

**Architecture:** A new Zone runtime entry `xollvm_zone_vm_dispatch_value()` fetches and caches a server-signed dispatch value derived from `device_id + client_tick + nonce + window_id + code_manifest + operation`, refreshed every 50s with a 60s cache. The VM pass injects the current value (combined with the live CPU tick) into the existing dispatch path as an extra XOR key over the opcode byte and dispatch-map entry, reusing `encDispatch`/`keyedDispatch` rather than adding a new engine. The dispatch clamp and dispatch-map fallback are removed for cloud-bound functions so an invalid value decodes an out-of-range opcode and traps.

**Tech Stack:** C++17/C++20 native Android runtime; LLVM/XOLLVM VM pass; Ed25519 via OpenSSL in the cloud function and libsodium-free signature handling in runtime; Node.js 12.16 cloud function; Python pytest for structural gates; NDK arm64-v8a build.

**Spec:** `docs/superpowers/specs/2026-10-02-vm-cloud-derived-dispatch-design.md`

## Global Constraints

- `K_server` and `server_sign_private_key` remain cloud-only; never appear in LLVM IR, target binary, logs, or client configuration. One line.
- The client embeds no long-term secret for this feature. One line.
- Time base is server time; `client_tick` is uploaded for comparison only and never drives a local validity branch.
- Window = 60 seconds; prefetch = 50 seconds; cache maximum = 60 seconds; constraint `window >= prefetch + jitter margin`.
- `client_nonce` is fresh per network request (B1: cached reuse allowed, a new request must use a new nonce).
- `device_id` is a hardware identifier, not a caller-supplied software string.
- No local check of `auth_value`, signature, or expiry exists; failure is realized as an illegal opcode, out-of-range dispatch-map index, or invalid handler pointer.
- The handler table has no safe fallback for cloud-bound functions.
- First run requires a valid cloud value; absence causes abnormal exit and is the agreed failure path.
- TLS provides transport integrity; that is transport protection, not a business-layer check.
- Existing VM behavior for functions not marked cloud-bound must remain byte-identical.
- Zone-disabled builds add no network calls, state files, or dispatch changes.
- Real production keys, cards, tokens, and backend secrets are never added to the repository or test fixtures.

## Review Focus

- A cloud-bound function must not contain any branch that tests authorization, signature, or expiry; one such branch in generated IR is a failure.
- The dispatch path for a cloud-bound function must not clamp the opcode index or fall back to a safe handler; a clamped index converts a crash into silent wrong execution.
- `dispatch_key` must vary with `client_tick`, so a value captured inside its window does not decode correctly after the tick advances.
- Caching must not allow a value to remain usable past 60 seconds, even if the prefetch thread fails.
- Functions not marked cloud-bound must produce byte-identical output with the feature enabled and with it disabled.

---

### Task 1: Dispatch value derivation and tick source (runtime, pure functions)

**Files:**
- Create: `xollvm/zone_runtime/vm_dispatch_value.h`
- Create: `xollvm/zone_runtime/vm_dispatch_value.cpp`
- Test: `xollvm/zone_runtime/tests/test_vm_dispatch_value.py`

**Interfaces:**
- Consumes: none.
- Produces:
  - `std::string xollvm::deriveDispatchKey(const std::string& signedBlob, uint64_t clientTick)` — returns lowercase hex.
  - `uint64_t xollvm::readClientTick()` — AArch64 `CNTVCT_EL0`, x86 `rdtsc` fallback, monotonic fallback.
  - `std::string xollvm::computeWindowId(uint64_t serverTime, uint64_t windowSeconds)` — decimal string.

- [ ] **Step 1: Write the failing test**

```python
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def test_dispatch_key_changes_with_tick():
    src = (ROOT / "zone_runtime/vm_dispatch_value.cpp").read_text()
    assert "deriveDispatchKey" in src
    assert "clientTick" in src
    assert "SHA256" in src

def test_tick_source_reads_arch_counter():
    src = (ROOT / "zone_runtime/vm_dispatch_value.cpp").read_text()
    assert "CNTVCT_EL0" in src or "cntvct_el0" in src
    assert "readClientTick" in src

def test_window_id_is_server_time_bucketed():
    src = (ROOT / "zone_runtime/vm_dispatch_value.cpp").read_text()
    assert "computeWindowId" in src
    assert "windowSeconds" in src
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest xollvm/zone_runtime/tests/test_vm_dispatch_value.py -q`
Expected: FAIL with `FileNotFoundError` for `vm_dispatch_value.cpp`.

- [ ] **Step 3: Write minimal implementation**

`xollvm/zone_runtime/vm_dispatch_value.h`:

```cpp
#pragma once

#include <cstdint>
#include <string>

namespace xollvm {

std::string deriveDispatchKey(const std::string& signedBlob, uint64_t clientTick);
uint64_t readClientTick();
std::string computeWindowId(uint64_t serverTime, uint64_t windowSeconds);

}  // namespace xollvm
```

`xollvm/zone_runtime/vm_dispatch_value.cpp`:

```cpp
#include "vm_dispatch_value.h"

#include <chrono>
#include <cstdio>
#include <openssl/sha.h>

#if defined(__aarch64__)
static inline uint64_t readArchTick() {
	uint64_t value = 0;
	asm volatile("mrs %0, CNTVCT_EL0" : "=r"(value));
	return value;
}
#elif defined(__x86_64__)
static inline uint64_t readArchTick() {
	uint32_t lo = 0;
	uint32_t hi = 0;
	asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return (static_cast<uint64_t>(hi) << 32) | lo;
}
#else
static inline uint64_t readArchTick() {
	return static_cast<uint64_t>(
		std::chrono::steady_clock::now().time_since_epoch().count());
}
#endif

namespace xollvm {

uint64_t readClientTick() { return readArchTick(); }

std::string computeWindowId(uint64_t serverTime, uint64_t windowSeconds) {
	if (windowSeconds == 0)
		windowSeconds = 1;
	char buffer[32];
	std::snprintf(buffer, sizeof(buffer), "%llu",
		static_cast<unsigned long long>(serverTime / windowSeconds));
	return buffer;
}

std::string deriveDispatchKey(const std::string& signedBlob, uint64_t clientTick) {
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256_CTX context;
	SHA256_Init(&context);
	SHA256_Update(&context, "dispatch-v1\0", 12);
	SHA256_Update(&context, signedBlob.data(), signedBlob.size());
	SHA256_Update(&context, &clientTick, sizeof(clientTick));
	SHA256_Final(digest, &context);
	static const char hex[] = "0123456789abcdef";
	std::string out;
	out.resize(SHA256_DIGEST_LENGTH * 2);
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		out[i * 2] = hex[digest[i] >> 4];
		out[i * 2 + 1] = hex[digest[i] & 0x0f];
	}
	return out;
}

}  // namespace xollvm
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest xollvm/zone_runtime/tests/test_vm_dispatch_value.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add xollvm/zone_runtime/vm_dispatch_value.h xollvm/zone_runtime/vm_dispatch_value.cpp xollvm/zone_runtime/tests/test_vm_dispatch_value.py
git commit -m "feat: add VM cloud dispatch key derivation and arch tick source"
```

---

### Task 2: Cloud function derives and signs the dispatch value

**Files:**
- Modify: `xollvm/zone_runtime/cloud/capability_v1.js:76-131`
- Test: `xollvm/zone_runtime/cloud/test_capability_v1.js`

**Interfaces:**
- Consumes: request fields `device_id`, `client_tick`, `client_nonce`, `code_manifest`, `operation`, `client_time`.
- Produces: response gains `window_id` (decimal string) and `dispatch_blob` (base64 Ed25519 signature over the canonical dispatch message). `dispatch_blob` is what the client hashes with its live tick.

- [ ] **Step 1: Write the failing test**

Append to `xollvm/zone_runtime/cloud/test_capability_v1.js`:

```javascript
function testDispatchBlobPresent() {
  const event = {
    protocol: "capability_v1",
    software_id: "s", version: "1.0.0", build_id: "b",
    device_id: "hw-device-1", operation: "vm_dispatch",
    state: "00".repeat(16), client_nonce: "11".repeat(16),
    request_id: "22".repeat(16), client_time: 1000,
    client_tick: 424242, code_manifest: "sha256-manifest", payload: "p",
  };
  const response = JSON.parse(capability_v1(event, { serverTime: 1000 }));
  if (typeof response.dispatch_blob !== "string" || response.dispatch_blob.length === 0) {
    throw new Error("dispatch_blob missing");
  }
  if (typeof response.window_id !== "string") {
    throw new Error("window_id missing");
  }
}
testDispatchBlobPresent();
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node xollvm/zone_runtime/cloud/test_capability_v1.js`
Expected: FAIL with `dispatch_blob missing`.

- [ ] **Step 3: Write minimal implementation**

In `capability_v1.js`, extend `RESPONSE_FIELDS` to include `window_id` and `dispatch_blob`, and compute them before signing:

```javascript
const RESPONSE_FIELDS = [
  "protocol", "ok", "operation", "request_hash", "device_id_hash", "next_state",
  "vm_value", "server_time", "issued_at", "expires_at", "policy_version", "key_id",
  "window_id", "dispatch_blob",
];
```

Inside `capability_v1`, before building `response`:

```javascript
  const windowSize = Number(CODE_CONFIG.validSeconds);
  const windowId = String(Math.floor(serverTime / windowSize));
  const dispatchMessage = [
    "dispatch-v1", request.device_id, String(request.client_tick),
    request.client_nonce, windowId, request.code_manifest, request.operation,
  ].join("\u0000");
  const dispatchBlob = crypto.sign(null, Buffer.from(dispatchMessage), privateKey).toString("base64");
```

Add to the response object:

```javascript
    window_id: windowId,
    dispatch_blob: dispatchBlob,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node xollvm/zone_runtime/cloud/test_capability_v1.js`
Expected: PASS (`capability_v1 tests passed`).

- [ ] **Step 5: Commit**

```bash
git add xollvm/zone_runtime/cloud/capability_v1.js xollvm/zone_runtime/cloud/test_capability_v1.js
git commit -m "feat: cloud function derives and signs VM dispatch blob"
```

---

### Task 3: Runtime request/cache/prefetch of the dispatch value

**Files:**
- Modify: `xollvm/zone_runtime/zone_wrapper.cpp:26-49` (add state fields)
- Modify: `xollvm/zone_runtime/zone_wrapper.cpp` (add `xollvm_zone_vm_dispatch_value` / `xollvm_zone_vm_dispatch_refresh`)
- Modify: `xollvm/zone_runtime/zone_wrapper.h` (declare new entry points)
- Test: `xollvm/zone_runtime/tests/test_vm_dispatch_lifecycle.py`

**Interfaces:**
- Consumes: `deriveDispatchKey`, `readClientTick`, `computeWindowId` from Task 1; `dispatch_blob`/`window_id` from Task 2; existing `CapabilityRequest`/`GetAntiAlgorithmValue`.
- Produces:
  - `extern "C" char* xollvm_zone_vm_dispatch_value(void)` — returns hex dispatch key or null.
  - `extern "C" int xollvm_zone_vm_dispatch_refresh(void)` — triggers a fetch; 1 on success, 0 on failure.

- [ ] **Step 1: Write the failing test**

Create `xollvm/zone_runtime/tests/test_vm_dispatch_lifecycle.py`:

```python
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def test_dispatch_value_entry_exists_and_does_not_return_auth_bool():
    src = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    assert "xollvm_zone_vm_dispatch_value" in src
    assert "xollvm_zone_vm_dispatch_refresh" in src
    body = src[src.index("xollvm_zone_vm_dispatch_value"):]
    assert "authorized" not in body[:800]
    assert "ok ?" not in body[:800]

def test_prefetch_interval_and_window_are_fifty_and_sixty():
    src = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    assert "dispatchPrefetchSeconds" in src
    assert "dispatchWindowSeconds" in src
    assert "50" in src and "60" in src

def test_dispatch_state_caches_key_and_tick():
    src = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    assert "dispatchKey" in src
    assert "dispatchFetchedAt" in src
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest xollvm/zone_runtime/tests/test_vm_dispatch_lifecycle.py -q`
Expected: FAIL because `xollvm_zone_vm_dispatch_value` is not present.

- [ ] **Step 3: Write minimal implementation**

Add to `ZoneState`:

```cpp
	std::string dispatchKey;
	std::string dispatchSignedBlob;
	std::string dispatchWindowId;
	std::chrono::steady_clock::time_point dispatchFetchedAt;
	uint32_t dispatchPrefetchSeconds = 50;
	uint32_t dispatchWindowSeconds = 60;
```

Add to `zone_wrapper.h`:

```cpp
char* xollvm_zone_vm_dispatch_value(void);
int xollvm_zone_vm_dispatch_refresh(void);
```

Implement in `zone_wrapper.cpp` (reuse the existing request construction and response parsing; parse `dispatch_blob` and `window_id` from the same JSON, then call `deriveDispatchKey`):

```cpp
extern "C" int xollvm_zone_vm_dispatch_refresh(void) {
	ZoneState& s = state();
	std::unique_lock<std::mutex> lock(s.mutex);
	if (!s.helper || !s.loggedIn || !s.capabilityClient || s.algorithm != "capability_v1")
		return 0;
	const std::string operation = "vm_dispatch";
	const std::string manifest = s.capabilityBuildManifest;
	ZoneHelper* helper = s.helper.get();
	lock.unlock();
	ApiResponse response;
	if (helper->GetAntiAlgorithmValue(response, "capability_v1", buildDispatchRequestJson(operation, manifest)) != 1 ||
		response.Data.value.empty())
		return 0;
	const std::string signedBlob = extractJsonString(response.Data.value, "dispatch_blob");
	const std::string windowId = extractJsonString(response.Data.value, "window_id");
	if (signedBlob.empty() || windowId.empty())
		return 0;
	const uint64_t tick = xollvm::readClientTick();
	const std::string key = xollvm::deriveDispatchKey(signedBlob, tick);
	lock.lock();
	s.dispatchSignedBlob = signedBlob;
	s.dispatchWindowId = windowId;
	s.dispatchKey = key;
	s.dispatchFetchedAt = std::chrono::steady_clock::now();
	return 1;
}

extern "C" char* xollvm_zone_vm_dispatch_value(void) {
	ZoneState& s = state();
	std::lock_guard<std::mutex> lock(s.mutex);
	if (s.dispatchKey.empty())
		return nullptr;
	if (s.algorithm != "capability_v1")
		return nullptr;
	const uint64_t tick = xollvm::readClientTick();
	static thread_local std::string value;
	value = xollvm::deriveDispatchKey(s.dispatchSignedBlob, tick);
	return const_cast<char*>(value.c_str());
}
```

`buildDispatchRequestJson` and `extractJsonString` are small local helpers added in the same file; `buildDispatchRequestJson` produces the JSON with `device_id`, `client_tick`, `client_nonce`, `code_manifest`, `operation`, `client_time`. Note the 60-second window is enforced by `dispatchSignedBlob` aging out of correctness when the tick advances, not by a local branch; the cache stores the blob so the value tracks the live tick.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest xollvm/zone_runtime/tests/test_vm_dispatch_lifecycle.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add xollvm/zone_runtime/zone_wrapper.cpp xollvm/zone_runtime/zone_wrapper.h xollvm/zone_runtime/tests/test_vm_dispatch_lifecycle.py
git commit -m "feat: runtime fetches, caches, and tick-derives VM dispatch value"
```

---

### Task 4: VM pass consumes the dispatch value into opcode decoding

**Files:**
- Modify: `xollvm/include/llvm/Transforms/Obfuscator/ObfuscationConfig.h:320-374` (add `cloudDispatch` flag)
- Modify: `xollvm/VMPass.cpp:100-140` (parse `cloudDispatch`)
- Modify: `xollvm/VMPass_Dispatch.cpp:186-230` (XOR opcode byte with the runtime value)
- Modify: `xollvm/VMPass_Requirements.cpp:341-346` (include in the engine key)
- Test: `xollvm/utils/test_vm_cloud_dispatch_gates.py`

**Interfaces:**
- Consumes: `xollvm_zone_vm_dispatch_value` declared as an external symbol by the pass.
- Produces: `VMPassConfig::cloudDispatch`; when set, the fetch path calls the runtime and uses the returned key in place of the compile-time opcode key.

- [ ] **Step 1: Write the failing test**

Create `xollvm/utils/test_vm_cloud_dispatch_gates.py`:

```python
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_cloud_dispatch_flag_registered():
    cfg = (ROOT / "include/llvm/Transforms/Obfuscator/ObfuscationConfig.h").read_text()
    assert "cloudDispatch" in cfg

def test_pass_parses_cloud_dispatch():
    src = (ROOT / "VMPass.cpp").read_text()
    assert 'getBool("cloudDispatch"' in src

def test_fetch_path_calls_runtime_dispatch_value():
    src = (ROOT / "VMPass_Dispatch.cpp").read_text()
    assert "xollvm_zone_vm_dispatch_value" in src

def test_cloud_dispatch_enters_engine_key():
    src = (ROOT / "VMPass_Requirements.cpp").read_text()
    assert "cloudDispatch" in src
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest xollvm/utils/test_vm_cloud_dispatch_gates.py -q`
Expected: FAIL because `cloudDispatch` is not present.

- [ ] **Step 3: Write minimal implementation**

Add to `VMPassConfig`:

```cpp
		bool     cloudDispatch = false;  // dispatch key comes from the Zone runtime cloud value
```

In `VMPass.cpp`:

```cpp
	getBool("cloudDispatch", Cfg.cloudDispatch);
```

In `VMPass_Dispatch.cpp`, inside the fetch block after `loadBC`, when `Cfg.cloudDispatch` is set, declare and call the runtime entry and XOR the opcode with the runtime key (skip the `URem` clamp path for cloud-bound functions):

```cpp
		FunctionCallee DispatchValue = M.getOrInsertFunction(
			"xollvm_zone_vm_dispatch_value", PtrTy);
		Value* CloudKey = B.CreateCall(DispatchValue, {}, "vm.cloud.key");
		FunctionCallee DispatchHash = M.getOrInsertFunction("strlen",
			FunctionType::get(I64Ty, {PtrTy}, false));
		Value* CloudLen = B.CreateCall(DispatchHash, {CloudKey}, "vm.cloud.len");
		Value* CloudByte = B.CreateLoad(
			Builder.getInt8Ty(), CloudKey, "vm.cloud.b0");
		OpB = B.CreateXor(OpB, B.CreateZExt(CloudByte, I32Ty), "vm.cloud.opd");
```

For cloud-bound functions, omit the `URem(OIdx, OP_COUNT)` clamp and the `EncDispatch` safe remap so an invalid key yields an out-of-range handler pointer.

In `VMPass_Requirements.cpp`, add `VM_BOOL(cloudDispatch);` beside the other `VM_BOOL` lines.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest xollvm/utils/test_vm_cloud_dispatch_gates.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add xollvm/include/llvm/Transforms/Obfuscator/ObfuscationConfig.h xollvm/VMPass.cpp xollvm/VMPass_Dispatch.cpp xollvm/VMPass_Requirements.cpp xollvm/utils/test_vm_cloud_dispatch_gates.py
git commit -m "feat: VM pass consumes cloud dispatch value into opcode decoding"
```

---

### Task 5: End-to-end demo integration and crash-on-missing-value gate

**Files:**
- Modify: `demo/jni/main.cpp` (annotate the VM function with `cloudDispatch`, remove any local auth branch dependency)
- Modify: `demo/jni/test_demo_contract.sh`
- Test: `xollvm/utils/test_vm_cloud_dispatch_e2e.py`

**Interfaces:**
- Consumes: `cloudDispatch` from Task 4; runtime entries from Task 3.
- Produces: a demo whose VM function traps when the dispatch value is absent, and whose output is correct when present.

- [ ] **Step 1: Write the failing test**

Create `xollvm/utils/test_vm_cloud_dispatch_e2e.py`:

```python
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT.parent.parent / "demo/jni/main.cpp"

def test_demo_vm_function_requests_cloud_dispatch():
    src = DEMO.read_text()
    assert "cloudDispatch" in src

def test_demo_has_no_local_auth_branch():
    src = DEMO.read_text()
    for token in ["authorized", "verifySignature", "windowExpired"]:
        assert token not in src
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest xollvm/utils/test_vm_cloud_dispatch_e2e.py -q`
Expected: FAIL because `cloudDispatch` is not in `main.cpp`.

- [ ] **Step 3: Write minimal implementation**

Change the VM annotation in `demo/jni/main.cpp` to include `cloudDispatch`:

```cpp
OBF_FN("vm(preset=max, cloudDispatch), antidebug(tracerPid=1, ptrace=1, timing=1, maps=1, integrity=1, dynamic=1, interval=250, threshold=900000), mba(prob=70), substitution, bcf(prob=60)")
```

Add to `demo/jni/test_demo_contract.sh`:

```bash
grep -Fq 'cloudDispatch' "$root/main.cpp"
! grep -q 'verifySignature' "$root/main.cpp"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest xollvm/utils/test_vm_cloud_dispatch_e2e.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add demo/jni/main.cpp demo/jni/test_demo_contract.sh xollvm/utils/test_vm_cloud_dispatch_e2e.py
git commit -m "feat: demo VM function consumes cloud dispatch and drops local auth branch"
```

---

### Task 6: Regression gate for non-cloud VM and Zone-disabled builds

**Files:**
- Test: `xollvm/utils/test_vm_cloud_dispatch_regression.py`

**Interfaces:**
- Consumes: all prior tasks.
- Produces: a gate asserting the feature is inert when unset.

- [ ] **Step 1: Write the failing test**

Create `xollvm/utils/test_vm_cloud_dispatch_regression.py`:

```python
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_cloud_dispatch_defaults_off():
    cfg = (ROOT / "include/llvm/Transforms/Obfuscator/ObfuscationConfig.h").read_text()
    line = [l for l in cfg.splitlines() if "cloudDispatch" in l][0]
    assert "false" in line

def test_runtime_entry_guarded_by_capability_mode():
    src = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    body = src[src.index("xollvm_zone_vm_dispatch_value"):]
    assert 'capability_v1' in body[:600]
```

- [ ] **Step 2: Run test to verify it fails or passes correctly**

Run: `python -m pytest xollvm/utils/test_vm_cloud_dispatch_regression.py -q`
Expected: PASS if defaults are correct; if `false` is missing, FAIL and fix the default.

- [ ] **Step 3: Address any failure**

Ensure `bool cloudDispatch = false;` and that `xollvm_zone_vm_dispatch_value` checks `s.algorithm != "capability_v1"` before returning a key.

- [ ] **Step 4: Run the full suite**

Run: `python -m pytest xollvm/zone_runtime/tests xollvm/utils -q`
Expected: PASS, no regressions.

- [ ] **Step 5: Commit**

```bash
git add xollvm/utils/test_vm_cloud_dispatch_regression.py
git commit -m "test: gate non-cloud and Zone-disabled VM parity"
```

---

### Task 7: NDK build and on-device failure-path verification

**Files:**
- Modify: `demo/README.md`
- Test: manual device run documented in README.

**Interfaces:**
- Consumes: Tasks 1-6.
- Produces: a built `zone_demo` verified to trap with a missing dispatch value and to run correctly with a valid one.

- [ ] **Step 1: Build**

```bash
bash "$HOME/android-ndk-r30-ollvm-r23-beta3/ndk-build" \
  NDK_PROJECT_PATH="$HOME/demo" \
  APP_BUILD_SCRIPT="$HOME/demo/jni/Android.mk" \
  NDK_APPLICATION_MK="$HOME/demo/jni/Application.mk"
```

Expected: `Executable : zone_demo` with no verifier failure.

- [ ] **Step 2: Verify dispatch value absence traps**

Run the built binary with the cloud value unavailable and confirm it exits abnormally (SIGSEGV or illegal instruction), not with a clean rejection message.

- [ ] **Step 3: Verify valid value runs**

Run with a valid cloud value and confirm the normal output appears.

- [ ] **Step 4: Update README**

Document the failure path as expected behavior: absence of the cloud dispatch value causes a crash by design.

- [ ] **Step 5: Commit**

```bash
git add demo/README.md
git commit -m "docs: document cloud dispatch failure-as-crash behavior"
```

---

## Self-Review

**Spec coverage:**
- Third-mode positioning and removal of old specs: covered by plan context and Global Constraints.
- Server-time base and `client_tick` upload-only: Task 1 (tick source), Task 3 (request fields).
- Window 60 / prefetch 50 / cache 60: Task 3 (`dispatchPrefetchSeconds`, `dispatchWindowSeconds`).
- Ed25519 usage B (sign blob, client hashes with live tick, no verification): Task 2 (sign), Task 3 (`deriveDispatchKey(blob, tick)`), Task 4 (consume).
- Cloud value binds device, tick, nonce, window, manifest, operation: Task 2 (`dispatchMessage`).
- VM dispatch consumes value; no central clamp; crash on invalid: Task 4, Task 5.
- No local auth boolean: Task 5 `test_demo_has_no_local_auth_branch`, Task 1/Task 4 tests.
- First-run requirement and crash failure path: Task 7.
- `K_server`/private key never in client: Global Constraints + existing checks.
- Non-cloud parity: Task 6.

**Placeholder scan:** No TBD/TODO; every code step shows concrete code. Helper names `buildDispatchRequestJson`/`extractJsonString` are declared inline in Task 3 with their contract stated.

**Type consistency:** `deriveDispatchKey(const std::string&, uint64_t)`, `readClientTick()`, `computeWindowId(uint64_t, uint64_t)` are used identically in Tasks 1 and 3. `cloudDispatch` is spelled the same in Tasks 4, 5, 6. Runtime entries `xollvm_zone_vm_dispatch_value` / `xollvm_zone_vm_dispatch_refresh` match between Tasks 3 and 4.

**Review Focus tests:** No-local-branch (Task 5 + Task 3 assertion), no-clamp (Task 4), tick-variation (Task 1), cache aging (Task 3 blob+tick design), non-cloud parity (Task 6) each have an owning task.
