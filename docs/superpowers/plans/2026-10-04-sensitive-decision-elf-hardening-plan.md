# Sensitive Decision and ELF Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a generic strict sensitive-decision protection boundary to XOLLVM, integrate Zone as the first consumer, and reject or detect exploitable final-ELF layouts and mutations.

**Architecture:** A `sensitive` annotation is parsed as policy metadata and validated before VM preparation. VM gains a shared return area so early/multiple returns are safe, and strict candidates must successfully commit or compilation fails. A separate LLVM Object-based post-link tool audits final `PF_X PT_LOAD` ranges, patches a compiler-emitted manifest, and the generated runtime checker binds manifest verification to VM state rather than exposing a patchable success boolean.

**Tech Stack:** C++20, LLVM 23 new pass manager and LLVM Object APIs, AArch64 ELF, Clang/LLD, Python 3/pytest for structural attack gates, Android NDK/ndk-build.

**Spec:** `docs/superpowers/specs/2026-10-04-sensitive-decision-elf-hardening-design.md`

## Global Constraints

- Do not hardcode Zone, OpenSSL, `EVP_DigestVerify`, `strcmp`, or `SSL_connect` names in XOLLVM.
- Do not restore compiler-bundled Zone runtime or the removed `zoneauth` pass.
- `sensitive(strict=1)` must fail compilation if validation, VM preparation, VM commit, or post-validation cannot prove protection.
- Runtime executability is determined by `PT_LOAD.p_flags & ELF::PF_X`, not section flags.
- Any non-allowlisted zero run of at least 512 bytes in a file-backed executable load is a link failure.
- Same seed must reproduce output; different seeds must produce at least two wrapper structure families.
- Build only as the Termux user and keep `-static-libstdc++` for Android executables delivered to MT terminals.
- Do not stage `build/`, `obj/`, generated OpenSSL archives, credentials, cards, tokens, or unrelated existing worktree changes.

## Review Focus

- A sensitive function with two early value returns must virtualize and return the correct value on both paths; Task 2 adds unit and runtime coverage.
- A raw external call result or its arithmetic/dataflow derivative returned to an unprotected caller must be rejected under `strict=1`; a constant status selected only after the protected region commits its internal authorization state remains allowed. Task 4 adds both fixtures.
- A sensitive call result stored to memory or passed to an unknown function must be diagnosed as an escape; Task 3 adds def-use tests.
- A 512-byte zero run inside `.rodata` mapped by `PF_X` must fail even without `SHF_EXECINSTR`; Task 7 adds synthetic ELF boundary fixtures.
- A dynamic relocation whose target lies inside an executable load must make sealing fail, so seal-time and runtime hashes always observe identical executable bytes; Task 8 adds relocation-policy fixtures.

---

### Task 1: Freeze The Five Attack Baselines

**Files:**
- Create: `utils/attack_gates/elf_model.py`
- Create: `utils/attack_gates/test_sensitive_attack_baseline.py`
- Create: `utils/fixtures/sensitive_decision_fixture.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `llvm-readelf`, `llvm-objdump`, and an AArch64 compiler supplied through `XOLLVM_TEST_CLANG`.
- Produces: `parse_load_segments(path: Path) -> list[LoadSegment]`, `find_zero_runs(data: bytes, minimum: int) -> list[ZeroRun]`, and five pytest attack-gate cases reused by Tasks 6, 7, and 10.

- [ ] **Step 1: Write the ELF model tests before implementation**

Add dataclasses and expected tests with these exact fields:

```python
@dataclass(frozen=True)
class LoadSegment:
    offset: int
    file_size: int
    virtual_address: int
    flags: int

@dataclass(frozen=True)
class ZeroRun:
    offset: int
    size: int

def test_zero_run_threshold_is_inclusive():
    blob = b"A" + b"\0" * 511 + b"B" + b"\0" * 512 + b"C"
    assert find_zero_runs(blob, 512) == [ZeroRun(513, 512)]
```

- [ ] **Step 2: Run the model test and verify RED**

Run:

```bash
python -m pytest utils/attack_gates/test_sensitive_attack_baseline.py -q
```

Expected: collection/import failure because `elf_model.py` does not yet define the interfaces.

- [ ] **Step 3: Implement the minimal read-only ELF parser used by tests**

Use `struct.unpack_from` for ELF64 little-endian headers only, validate `ELFCLASS64`, `ELFDATA2LSB`, program-header bounds, and `p_offset + p_filesz <= len(data)`. Reject malformed inputs with `ElfFormatError`; do not mutate files in this helper.

- [ ] **Step 4: Add the baseline fixture and five observations**

The fixture must contain one annotated decision consumer with an external fixed-signature verifier, one `strcmp`-style comparison, one transport helper, success/failure actions, and an explicit 1,024-byte zero array in read-only data. Tests record, rather than hide, these current baseline findings:

```python
assert direct_call_to("fixture_verify", disassembly)
assert conditional_failure_edge_after("fixture_compare", disassembly)
assert xrefs_to("fixture_transport", disassembly)
assert any(run.size >= 512 for run in executable_zero_runs(binary))
```

- [ ] **Step 5: Run the attack baseline suite**

Run:

```bash
XOLLVM_TEST_CLANG=/data/user/0/com.termux/files/home/xollvm-android/build/bin/clang \
python -m pytest utils/attack_gates/test_sensitive_attack_baseline.py -q
```

Expected: PASS, with the baseline explicitly proving at least paths 1, 2, 3, and 5 are detectable. Path 4 is represented by the transport xref, not by hardcoding `SSL_connect`.

- [ ] **Step 6: Review checkpoint**

Inspect only the files listed in this task with `git diff --check` and `git diff -- <files>`. Do not commit unless the user explicitly requests it.

### Task 2: Make VM Multiple Returns Correct

**Files:**
- Modify: `include/llvm/Transforms/Obfuscator/VMPass_Impl.h`
- Modify: `VMPass_Wrapper.cpp`
- Modify: `VMPass_Handlers.cpp`
- Modify: `VMPass_Requirements.cpp`
- Modify: `utils/VMRequirementsTest.cpp`
- Modify: `utils/obf_runtime_tests.py`

**Interfaces:**
- Consumes: existing `OP_RET_VOID`, `OP_RET_INT`, `OP_RET_PTR`, and `OP_RET_F` bytecode instructions.
- Produces: engine parameters `kParamRetStorage` and `kParamRetKind`, enum `VMReturnKind`, and one wrapper-owned return storage object independent of source return-register slots.

- [ ] **Step 1: Add failing eligibility and runtime tests**

Add an LLVM IR unit fixture with two `ret i32` blocks and assert:

```cpp
EXPECT_TRUE(VMImpl::isVMEligibleForTest(*F, FOC, Config, &Reason));
EXPECT_TRUE(Reason.empty());
```

Add runtime cases for `i1`, `i32`, `i64`, pointer, `float`, and `double`, each with at least two value-return blocks. Assert both branches match an unobfuscated reference build.

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
cmake --build /data/user/0/com.termux/files/home/xollvm-android/build --parallel 4 --target VMRequirementsTests
/data/user/0/com.termux/files/home/xollvm-android/build/tools/Obfuscator/VMRequirementsTests \
  --gtest_filter='VMEligibility.*MultipleReturn*'
```

Expected: FAIL with `multi-value-return`.

- [ ] **Step 3: Define a stable return-storage ABI**

Add:

```cpp
enum class VMReturnKind : uint32_t { Void = 0, I32 = 1, I64 = 2, Ptr = 3, F64 = 4 };
static constexpr unsigned kParamRetStorage = 18;
static constexpr unsigned kParamRetKind = 19;
```

Use a wrapper `alloca [16 x i8]` aligned to 8. The engine receives `ptr ret_storage` and `i32 ret_kind`. Keep lazy context after these fixed parameters so every engine key has deterministic parameter indices.

- [ ] **Step 4: Change every shared-engine return handler to write the result**

Implement exact behavior:

```cpp
// OP_RET_INT i32 path
Value *Value32 = ldVR(B, Src);
B.CreateStore(Value32, B.CreateBitCast(RetStorage, PointerType::getUnqual(I32Ty)));
B.CreateRetVoid();
```

Use i64, pointer, and f64 stores for the other kinds. `OP_RET_VOID` only returns. Preserve register decryption by reading through existing `ldVR`/`ldVR64`/`ldFR` helpers.

- [ ] **Step 5: Replace `computeReturnInfo()` slot discovery**

Derive only one return kind from `F.getReturnType()`. Delete `WrapRetSlot`; the wrapper always reads the dedicated storage after the engine call and converts i32 back to narrow integer or f64 back to float as needed.

- [ ] **Step 6: Remove the multi-value-return eligibility rejection**

Keep rejection for inconsistent/unsupported return types, EH, `musttail`, `callbr`, and existing `indirectbr`. Remove only the block at `VMPass_Impl.h` that counts value-returning `ReturnInst`s.

- [ ] **Step 7: Run unit and differential runtime tests**

Run:

```bash
cmake --build /data/user/0/com.termux/files/home/xollvm-android/build --parallel 4 --target VMRequirementsTests obj.Obfuscator
/data/user/0/com.termux/files/home/xollvm-android/build/tools/Obfuscator/VMRequirementsTests
python utils/obf_runtime_tests.py --case vm-multiple-returns
```

Expected: all return kinds and all early-return paths pass.

- [ ] **Step 8: Review checkpoint**

Run `git diff --check` for Task 2 files and inspect that no old fixed return-slot load remains.

### Task 3: Parse And Validate Sensitive Decision Boundaries

**Files:**
- Create: `include/llvm/Transforms/Obfuscator/SensitiveDecision.h`
- Create: `SensitiveDecision.cpp`
- Modify: `include/llvm/Transforms/Obfuscator/ObfuscationConfig.h`
- Modify: `ObfuscationConfig.cpp`
- Modify: `ObfuscationPipeline.cpp`
- Modify: `CMakeLists.txt`
- Modify: `utils/VMRequirementsTest.cpp`

**Interfaces:**
- Consumes: annotation `sensitive(region=<identifier>,strict=<bool>)` and existing function analysis manager.
- Produces: `SensitiveDecisionConfig`, `SensitiveDecisionAnalysisResult`, and function metadata `!obf.sensitive.validated` containing region and strict flag.

- [ ] **Step 1: Add parser tests**

Add tests for:

```cpp
auto C = AnnotationParser::parseAnnotationString(
    "obf: sensitive(region=auth,strict=1), vm(preset=max)");
auto S = SensitiveDecisionConfig::fromPassConfig(*C.getPassConfig("sensitive"));
EXPECT_TRUE(S.enable);
EXPECT_TRUE(S.strict);
EXPECT_EQ(S.region, "auth");
```

Also reject empty region, unknown parameters, and `sensitive` without enabled `vm`.

- [ ] **Step 2: Run parser tests and verify RED**

Expected: compile failure because `SensitiveDecisionConfig` is undefined.

- [ ] **Step 3: Implement configuration parsing and pipeline ordering**

Define:

```cpp
struct SensitiveDecisionConfig {
    bool enable = false;
    bool strict = true;
    std::string region;
    static SensitiveDecisionConfig fromPassConfig(const PassConfig &PC);
    bool validate(std::string *Reason = nullptr) const;
};
```

Add ordering rule `sensitive -> vm`; do not add it as an ordinary mutating function pass after VM.

- [ ] **Step 4: Add failing def-use validation tests**

Parse IR fixtures and assert these diagnostics:

```text
sensitive result escapes through return
sensitive result escapes through store
sensitive result escapes to unknown call
sensitive decision has no in-region success/failure branch
```

The valid fixture calls an external declaration, compares its integer result, and terminates both branch regions locally.

- [ ] **Step 5: Implement conservative sensitivity propagation**

Seed taint from non-void calls to declaration-only, non-intrinsic functions inside a sensitive function. Propagate through casts, `icmp`, `select`, PHI, integer arithmetic, and loads/stores only when the alloca is provably function-local and non-escaping. Reject a tainted return value, non-local store, unknown call argument, and inline assembly use under strict mode. Do not add implicit control-dependence taint to branch-local constants: a function may commit protected state on success and then return literal `1`/`0`, but returning the external result, comparison value, or a dataflow-derived status is forbidden.

- [ ] **Step 6: Mark validated functions**

Attach metadata only after validation succeeds:

```llvm
!obf.sensitive.validated = !{!"auth", i1 true}
```

Do not rewrite external call names and do not create library-specific rules.

- [ ] **Step 7: Run unit tests and build the plugin**

Run:

```bash
cmake --build /data/user/0/com.termux/files/home/xollvm-android/build --parallel 4 --target VMRequirementsTests obj.Obfuscator
/data/user/0/com.termux/files/home/xollvm-android/build/tools/Obfuscator/VMRequirementsTests \
  --gtest_filter='SensitiveDecision*'
```

Expected: parser, valid region, and all escape diagnostics pass.

- [ ] **Step 8: Review checkpoint**

Confirm `SensitiveDecision.cpp` contains no Zone/OpenSSL/API-name matching.

### Task 4: Enforce Strict VM Preparation And Commit

**Files:**
- Modify: `include/llvm/Transforms/Obfuscator/VMPass_Plan.h`
- Modify: `VMPass_Plan.cpp`
- Modify: `VMPass.cpp`
- Modify: `include/llvm/Transforms/Obfuscator.h`
- Modify: `ObfReport.cpp`
- Modify: `utils/VMRequirementsTest.cpp`
- Create: `utils/attack_gates/test_sensitive_strict.py`

**Interfaces:**
- Consumes: `!obf.sensitive.validated` metadata from Task 3.
- Produces: `VMPreparedCandidate::Required`, `VMPreparedCandidate::Region`, `VMPlanCoordinator::verifyRequiredCandidates()`, and fatal diagnostics prefixed `obfuscator: sensitive region`.

- [ ] **Step 1: Add strict failure tests**

Compile fixtures for EH/invoke, `callbr`, unsupported operand, missing `vm`, oversized block count, a raw tainted return, a branch-local constant status return, and successful multi-return. Example assertion:

```python
proc = compile_fixture("sensitive_invoke.ll")
assert proc.returncode != 0
assert "obfuscator: sensitive region 'auth'" in proc.stderr
assert "EH/invoke" in proc.stderr
```

- [ ] **Step 2: Run strict tests and verify RED**

Run:

```bash
python -m pytest utils/attack_gates/test_sensitive_strict.py -q
```

Expected: strict fixtures currently compile or fail without the required diagnostic.

- [ ] **Step 3: Record every required candidate before eligibility checks**

Extend coordinator registration so a required function is represented even when preparation fails:

```cpp
VMPreparedCandidate *addRequired(Function &Fn, StringRef Region,
                                 bool Strict, StringRef InitialReason);
```

Set `Accepted=true` only after successful prepare. Preserve exact skip reason from `isVMEligible` or emitter verification. Store the pre-transform declaration callees from `SensitiveDecisionAnalysisResult` on the candidate as `SmallVector<Function *, 4> SensitiveCallees`; Task 5 uses that captured provenance after the original body is replaced.

- [ ] **Step 4: Make module completion verify required candidates**

After function pipeline execution and before `freeze()`, call `verifyRequiredCandidates()`. For strict failures use `report_fatal_error` with region, function, and reason. For non-strict failures append an explicit report entry.

- [ ] **Step 5: Add post-commit proof metadata**

On successful `VMImpl::commit()`, attach:

```llvm
!obf.sensitive.committed = !{!"auth"}
```

Coordinator post-validation requires both `obf.vm.caller` and matching sensitive committed metadata.

- [ ] **Step 6: Run strict tests and all VM unit tests**

Expected: every unsupported strict fixture fails loudly, valid multi-return succeeds, and ordinary non-sensitive VM skip behavior remains unchanged.

- [ ] **Step 7: Review checkpoint**

Confirm no strict candidate can disappear because of probability, budget, `maxBlocks`, or candidate list filtering without a diagnostic.

### Task 5: Add Sensitive Decision Post-VM Structural Gates

**Files:**
- Modify: `SensitiveDecision.cpp`
- Modify: `include/llvm/Transforms/Obfuscator/SensitiveDecision.h`
- Modify: `include/llvm/Transforms/Obfuscator.h`
- Create: `utils/attack_gates/test_sensitive_codegen.py`
- Modify: `utils/fixtures/sensitive_decision_fixture.cpp`

**Interfaces:**
- Consumes: committed sensitive metadata and final module after `VMPlanCoordinator::commit()`.
- Produces: `verifyCommittedSensitiveRegions(Module &, raw_ostream &) -> bool` and AArch64 codegen gates.

- [ ] **Step 1: Add failing post-commit tests**

Build a protected fixture and assert the final sensitive wrapper has `obf.vm.caller`, no original external call instruction, and no native conditional branch controlled by the original result. Add a deliberately uncommitted metadata fixture that must fail strict post-validation.

- [ ] **Step 2: Run tests and verify RED**

Expected: no post-commit verifier exists.

- [ ] **Step 3: Implement module-level post-validation**

For each validated strict region:

- require matching committed metadata;
- require the original body to be replaced by the VM wrapper;
- require all original declaration callees to appear only in private VM callee tables for that region, not as calls in the wrapper;
- require no tainted native branch remains in preserved helper code.

- [ ] **Step 4: Add AArch64 disassembly gates**

Use `llvm-objdump -d --no-show-raw-insn`. Resolve symbol/relocation provenance without searching for OpenSSL names. Fail when a direct call to the fixture verifier and a dependent native conditional branch both occur in the protected symbol.

- [ ] **Step 5: Run structural tests over three seeds**

Run seeds `1`, `20260930`, and `4294967295`. Expected: no sensitive direct-call/branch chain in any output and byte-identical output for repeated builds with the same seed.

- [ ] **Step 6: Review checkpoint**

Keep tests semantic: fixture symbol names are allowed in test code, but production compiler code remains name-agnostic.

### Task 6: Integrate Zone As The First Sensitive Consumer

**Files:**
- Modify: `/data/user/0/com.termux/files/home/xollvm-android/demo/jni/zone_runtime/capability_client.cpp`
- Modify: `/data/user/0/com.termux/files/home/xollvm-android/demo/jni/zone_runtime/capability_client.h`
- Modify: `/data/user/0/com.termux/files/home/xollvm-android/demo/jni/zone_runtime/zone_wrapper.cpp`
- Modify: `/data/user/0/com.termux/files/home/xollvm-android/demo/jni/test_demo_contract.sh`
- Create: `utils/attack_gates/test_zone_sensitive_boundary.py`

**Interfaces:**
- Consumes: `OBF_FN("sensitive(region=zone-capability,strict=1), vm(preset=max,...)")` supported by Tasks 3-5.
- Produces: one compact `CapabilityClient::acceptVerifiedResponse(...)` decision boundary that owns signature, binding, time, state update, and reject behavior. It may return literal status values after local state commit, but no raw verifier result leaves the boundary.

- [ ] **Step 1: Add contract and attack tests first**

Require exactly one Zone capability sensitive region, require `strict=1`, and compile the demo runtime to verify that `EVP_DigestVerify` cannot be followed to a native accept/reject branch in that region.

- [ ] **Step 2: Run tests and verify RED**

Expected: current `acceptResponse()` is only generic `OBF_ZONE_FN` and the result crosses an ordinary native branch.

- [ ] **Step 3: Refactor only the final decision boundary**

Keep network and JSON parsing outside VM. Pass a fully parsed response and expected hashes into a compact function that performs signature verification, field comparisons, time checks, and in-memory state update before returning literal success/failure status values. A success return is advisory: `xollvm_zone_require()` must independently require the committed in-memory capability state. Do not virtualize curl, JSON parsing, or the entire SDK.

- [ ] **Step 4: Apply the sensitive annotation**

Use the generic annotation and `preset=max`; do not add function names to XOLLVM. Ensure failure cannot populate `state_` or `response_`, and success updates both only after every check passes.

- [ ] **Step 5: Run Zone behavioral and structural tests**

Run valid signature, invalid signature, wrong request hash, wrong device hash, expired response, future-issued response, wrong operation, and wrong key ID. Then run the existing demo contract and valid-card e2e command.

- [ ] **Step 6: Review checkpoint**

Confirm card/configuration values are not added to tests or logs and capability remains memory-only.

### Task 7: Build The Final-ELF Cave Auditor

**Files:**
- Create: `tools/xollvm-elf-hardener/CMakeLists.txt`
- Create: `tools/xollvm-elf-hardener/xollvm-elf-hardener.cpp`
- Modify: `CMakeLists.txt`
- Create: `utils/elf_hardener_test.py`
- Create: `utils/fixtures/elf_caves/elf_caves.yaml`

**Interfaces:**
- Consumes: `xollvm-elf-hardener audit --input <elf> --zero-threshold 512 [--allow-section <name>]`.
- Produces: exit 0 for a valid ELF; exit 2 for malformed ELF; exit 3 for policy violation; deterministic diagnostics containing segment index, file offset, virtual address, size, section owner, and permissions.

- [ ] **Step 1: Write 511/512/513-byte fixture tests**

Generate ELF fixtures with LLD linker scripts for zero runs outside loads, unowned inside `PF_X`, `.rodata` inside `PF_X`, and inside RW loads. Explicitly strip section headers for one fixture.

- [ ] **Step 2: Run tests and verify RED**

Expected: tool target and executable do not exist.

- [ ] **Step 3: Add an LLVM Object-based executable target**

Link LLVM `Object`, `BinaryFormat`, and `Support`. Parse `ELF64LEObjectFile`; reject non-ELF64LE in the first release with a precise diagnostic.

- [ ] **Step 4: Implement segment and zero-run classification**

Scan only `[p_offset, p_offset + p_filesz)` for each `PT_LOAD`. Determine executable status from `PF_X`. Use sections only to report ownership; audit must still work when section headers are absent.

- [ ] **Step 5: Implement policy and allowlists**

Default threshold is 512 inclusive. `--allow-section` accepts exact section names only and never raw offsets. A zero run spanning owners is not allowlisted unless every covered byte belongs to the same allowed section.

- [ ] **Step 6: Run fixture and real-demo audits**

The synthetic boundaries must behave exactly as specified. The current demo must initially fail on the known executable-mapped `.rodata` run, proving the auditor catches path 5.

- [ ] **Step 7: Review checkpoint**

Fuzz malformed header sizes, overflowed offsets, overlapping loads, absent sections, and duplicate section names; all must fail without out-of-bounds reads.

### Task 8: Emit And Patch The ELF Integrity Manifest

**Files:**
- Create: `include/llvm/Transforms/Obfuscator/ElfIntegrity.h`
- Create: `ElfIntegrity.cpp`
- Create: `integrity_stub/CMakeLists.txt`
- Create: `integrity_stub/integrity_sha256.c`
- Modify: `include/llvm/Transforms/Obfuscator.h`
- Modify: `CMakeLists.txt`
- Modify: `tools/xollvm-elf-hardener/xollvm-elf-hardener.cpp`
- Create: `utils/elf_integrity_test.py`

**Interfaces:**
- Consumes: any module containing at least one strict sensitive region.
- Produces: retained section `.xollvm.integrity` with magic `XOLINT01`, version 1, SHA-256 digest, up to eight executable ranges, and a runtime constructor that poisons `__obf_elf_integrity_state` on mismatch.

- [ ] **Step 1: Add manifest layout tests**

Define a packed, endian-stable manifest schema in the header and assert exact offsets/sizes in C++:

```cpp
struct ElfIntegrityManifestV1 {
    uint8_t Magic[8];
    uint32_t Version;
    uint32_t RangeCount;
    uint64_t ManifestVirtualAddress;
    ElfIntegrityRange Ranges[8];
    uint8_t Digest[32];
};
static_assert(sizeof(ElfIntegrityManifestV1) == 184);
```

`ElfIntegrityRange` contains `uint64_t VirtualAddress` and `uint64_t FileSize`. Runtime computes the module base as `&manifest - ManifestVirtualAddress`; it must not scan memory for an ELF header.

- [ ] **Step 2: Run tests and verify RED**

Expected: manifest symbol and patch command do not exist.

- [ ] **Step 3: Emit placeholder and runtime state**

The module pass emits one linkonce/COMDAT placeholder, retains it through `llvm.compiler.used`, and emits hidden writable `__obf_elf_integrity_state`. The placeholder digest and ranges are zero before post-link patching. Build `integrity_sha256.c` to embedded LLVM bitcode using the same pattern as `aes_stub`; link only the internal `__xollvm_integrity_sha256(const uint8_t *, size_t, uint8_t[32])` helper into modules that contain strict sensitive regions. The helper is freestanding and has no libc or OpenSSL calls.

- [ ] **Step 4: Implement canonical post-link hashing**

Add:

```text
xollvm-elf-hardener seal --input <elf> --output <elf>
xollvm-elf-hardener verify --input <elf>
```

Hash each file-backed `PF_X PT_LOAD` range plus canonical program-header fields with LLVM's `SHA256` implementation. Treat the manifest bytes as zero while hashing. Before hashing, enumerate `RELA`, `REL`, RELR, and Android packed dynamic relocation targets. If any target virtual address lies in a `PF_X PT_LOAD`, reject sealing with the relocation table, type, target address, and owning segment. This first version never canonicalizes or silently omits executable relocation bytes.

- [ ] **Step 5: Generate the runtime checker**

Use the embedded freestanding SHA-256 helper without libc/OpenSSL dependencies. Compute the module base exactly as `&manifest - ManifestVirtualAddress`, validate the ELF magic and program-header bounds at that base, hash the same manifest-zeroed ranges and canonical program-header fields, constant-time compare the digest, and mix failure into `__obf_elf_integrity_state`. Do not scan memory for an ELF header, branch to a standalone failure block, or return a public boolean API.

- [ ] **Step 6: Bind integrity state into strict VM wrappers**

For strict sensitive wrappers, mix `__obf_elf_integrity_state` into the effective VM salt/callee mask. Valid state is neutral; invalid state deterministically corrupts bytecode/dispatch behavior before the sensitive decision can succeed.

- [ ] **Step 7: Add mutation tests**

Mutate `.text`, executable `.rodata`, executable padding, VM bytecode, a program header, and manifest bytes. `verify` must reject all. Add one ELF with a dynamic relocation target inside `PF_X` and require `seal` to reject it; add a control ELF whose relocations target only RW loads and require sealing to succeed. Add file-tail data and assert runtime manifest scope does not claim to cover it; a separate full-file/package test owns that case.

- [ ] **Step 8: Run tool, unit, and Android runtime tests**

Expected: unmodified sealed fixture runs, each covered mutation fails closed, and the tool produces identical manifests for identical input.

- [ ] **Step 9: Review checkpoint**

Compare seal-time and runtime byte ordering, manifest-zeroing, range ordering, and program-header serialization against shared golden vectors. Confirm executable relocation targets are rejected before either hash path runs.

### Task 9: Integrate The Hardener Into The Final Link Wrapper

**Files:**
- Modify: `/data/user/0/com.termux/files/home/xollvm-android/demo/jni/ndk-linker-wrapper/clang++`
- Modify: `/data/user/0/com.termux/files/home/xollvm-android/demo/jni/Android.mk`
- Modify: `.github/workflows/build-android.yml`
- Modify: `docs/项目功能与命令总览.md`
- Modify: `docs/obf_annotations.h`
- Modify: `/data/user/0/com.termux/files/home/xollvm-android/demo/README.md`
- Modify: `/data/user/0/com.termux/files/home/xollvm-android/demo/jni/test_demo_contract.sh`

**Interfaces:**
- Consumes: `XOLLVM_ELF_HARDENER`, `XOLLVM_ELF_ZERO_THRESHOLD`, and final linker `-o <path>`.
- Produces: a sealed final ELF or a failed link with no stale output accepted as success.

- [ ] **Step 1: Add wrapper integration tests**

Test `-o file`, `-ofile`, response-file arguments, compile-only invocations, failed underlying links, missing hardener, malformed ELF, and a policy-violating ELF. Compile-only commands must never invoke the hardener.

- [ ] **Step 2: Run tests and verify RED**

Expected: current wrapper delegates link and never audits/seals output.

- [ ] **Step 3: Implement robust output discovery and temporary linking**

On link commands, rewrite output to `<output>.xollvm-unsealed`, run real NDK clang, run `audit` then `seal`, atomically rename to the requested output, and remove only the temporary file on failure. Never delete a pre-existing requested output unless replacement succeeds.

- [ ] **Step 4: Wire tool location into ndk-build and cloud artifacts**

Set `XOLLVM_ELF_HARDENER` explicitly in `Android.mk`. Package the hardener beside clang/opt in the Android workflow. Keep `-static-libstdc++` on the final Android executable.

- [ ] **Step 5: Fix the demo RX layout**

Use supported LLD flags or a linker script to separate ordinary `.rodata` into a non-executable read-only load. Do not whitelist the current 1,031-byte `.rodata` zero run and do not random-fill it. Re-run `readelf -lW` and the auditor until no unallowlisted executable run remains.

- [ ] **Step 6: Update user documentation**

Document annotation syntax, strict behavior, hardener environment variables, error exit meanings, manifest scope, package-signing boundary, and the fact that dynamic symbols may remain globally visible.

- [ ] **Step 7: Run wrapper and demo contract tests**

Expected: a valid link seals automatically; a 512-byte executable cave fails the link; compile-only commands remain unchanged.

- [ ] **Step 8: Review checkpoint**

Inspect wrapper quoting with paths containing spaces and verify no command uses shell `eval`.

### Task 10: Diversify VM Wrappers And Run End-To-End Attack Regression

**Files:**
- Modify: `include/llvm/Transforms/Obfuscator/ObfuscationConfig.h`
- Modify: `ObfuscationConfig.cpp`
- Modify: `VMPass.cpp`
- Modify: `VMPass_Wrapper.cpp`
- Create: `utils/attack_gates/test_wrapper_families.py`
- Modify: `utils/attack_gates/test_sensitive_attack_baseline.py`
- Modify: `/data/user/0/com.termux/files/home/xollvm-android/demo/jni/test_demo_contract.sh`

**Interfaces:**
- Consumes: VM config `wrapperFamily=auto|split|arena|outlined` and module seed.
- Produces: at least two structurally distinct wrapper families with deterministic family choice for a given function and seed.

- [ ] **Step 1: Add wrapper-family parser and structural tests**

Build 20 seeds. Normalize AArch64 prologues into opcode classes, frame size, spill order, and distance to first indirect call. Require at least two distinct classes and exact repeatability for the same seed.

- [ ] **Step 2: Run tests and verify RED**

Expected: existing shuffled allocas still normalize to one wrapper family.

- [ ] **Step 3: Implement `split` and `arena` families**

`split` preserves current separate arrays. `arena` allocates one aligned byte arena, computes randomized non-overlapping offsets for i32/i64/f64/pointer files, and passes typed GEPs to the same engine ABI. Validate alignment and total-size overflow before emission.

- [ ] **Step 4: Implement `outlined` preload family**

Create a private seed-named helper that initializes argument/constant slots and is called indirectly through a private table. Exclude unsupported allocas and fall back only when `wrapperFamily=auto`; explicit `outlined` under strict sensitive mode must fail rather than silently change family.

- [ ] **Step 5: Run all five attack regressions**

For the sealed Zone demo, assert:

```text
1. relocation/PLT mapping does not identify a direct sensitive decision callsite
2. verifier provenance does not lead to a native result branch/prologue chain
3. compare provenance does not lead to a native cbz/cbnz failure target
4. transport xrefs do not identify the final authorization decision function
5. no unallowlisted PF_X zero run is >= 512 bytes
```

- [ ] **Step 6: Run full verification**

Run:

```bash
cmake --build /data/user/0/com.termux/files/home/xollvm-android/build --parallel 4 --target obj.Obfuscator VMRequirementsTests xollvm-elf-hardener
/data/user/0/com.termux/files/home/xollvm-android/build/tools/Obfuscator/VMRequirementsTests
python -m pytest utils/attack_gates utils/elf_hardener_test.py utils/elf_integrity_test.py -q
cd /data/user/0/com.termux/files/home/xollvm-android/demo && ndk-build clean && ndk-build -j2
bash /data/user/0/com.termux/files/home/xollvm-android/demo/jni/test_demo_contract.sh
```

Then run the valid-card Android e2e without logging the card and run invalid-card, invalid-capability, expired-response, and binary-mutation cases.

- [ ] **Step 7: Inspect final binary properties**

Run `llvm-readelf -lW -r -Ws`, `llvm-objdump -d`, `xollvm-elf-hardener verify`, and the five attack scripts. Record command output in the test report, not in source comments.

- [ ] **Step 8: Final review checkpoint**

Run `git diff --check`, inspect all files changed by this plan, verify no secrets or build products are tracked, and request a full code review before any commit or push.
