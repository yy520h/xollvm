# 混淆后真实图报告实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 将 `-obf-graph-dir` 从直接调用图升级为由最终 LLVM Module 和 VM witness 共同驱动的混淆后结构图，并保持报告关闭时零行为变化。

**Architecture:** 在现有 `ObfReport.cpp` 中增加统一的稳定节点/边事实模型。最终 Module 扫描负责函数、基本块、直接/间接调用、`indirectbr`、`blockaddress` 和 Zone gate；`FunctionReport::VM` 负责补充 VM engine、handler、variant、decoy 和 nested dependency 事实。fragment 继续使用现有 C++ 文件锁聚合，JSON 和 SVG 均从合并后的事实模型输出。

**Tech Stack:** LLVM C++ IR API、LLVM `json`、LLVM `raw_fd_ostream`、内置 SVG、现有 Python 契约测试和 LLVM/NDK 构建。

**Spec:** `docs/superpowers/specs/2026-10-01-obfuscated-graph-report-design.md`

## Global Constraints

- 核心总图和逐函数 SVG 由 XOLLVM 内置 C++ 生成。
- 不调用 Python、Graphviz、Termux、Node.js 或其他外部程序生成核心图。
- 静态无法唯一解析的 VM dispatch、函数指针和间接跳转必须标记为非确定关系。
- 不改变 `-obf-graph-dir` 关闭时的编译行为。
- 不回退工作树中与本任务无关的已有修改。
- 交付到 MT/NDK 的编译器产物继续按项目要求静态链接 C++ runtime。

## Review Focus

- VM handler table 只有 witness 数据、没有可直接映射到 LLVM Function 的目标时，报告必须仍输出可追踪的逻辑 handler 节点，而不是丢失 VM 结构。测试：VM witness-only graph fixture。
- 函数指针调用和 `indirectbr` 不能被误报为确定 direct edge。测试：含间接调用和多目标 `indirectbr` 的 IR fixture。
- 同一 module fragment 重写后不能遗留旧节点。测试：两次写入同 module key 的聚合测试。
- 函数名、opcode 名和 XML 特殊字符不能破坏 JSON/SVG。测试：转义 fixture。
- 没有 VM 或没有可识别调用的空/普通 Module 仍必须输出有效图。测试：empty/direct fixture。

---

### Task 1: 添加模式选项和统一图模型

**Files:**
- Modify: `ObfuscationOptions.cpp:140-144`
- Modify: `include/llvm/Transforms/Obfuscator/ObfuscationOptions.h:58-63`
- Modify: `include/llvm/Transforms/Obfuscator/ObfReport.h:17-150`
- Test: `utils/test_graph_report.py`

**Interfaces:**
- Produces `ObfGraphMode` and `getGraphReportMode()` returning `StringRef`/normalized mode data used by `writeGraphReport`.
- Produces `GraphNode`, `GraphEdge`, `GraphModel` structures owned by `ObfReport` with stable string IDs and JSON/SVG-neutral fields.

- [ ] **Step 1: Write the failing test**

Add a test invoking the tool with `-mllvm -obf-graph-mode=obfuscated` and assert the generated JSON contains `graph_mode: obfuscated`, `nodes`, and `edges`; invoke `direct` and assert `graph_mode: direct`.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest utils/test_graph_report.py -q`

Expected: FAIL because the option and JSON graph mode do not exist.

- [ ] **Step 3: Write minimal implementation**

Add the string command-line option with default `obfuscated`, reject values other than `obfuscated` and `direct` in `getGraphReportMode()`, and add the model structs plus stable ID helpers. Keep existing direct fragment fields source-compatible until Task 3 switches the writer.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest utils/test_graph_report.py -q`

Expected: PASS for option parsing and the model contract.

- [ ] **Step 5: Commit**

```bash
git add ObfuscationOptions.cpp include/llvm/Transforms/Obfuscator/ObfuscationOptions.h include/llvm/Transforms/Obfuscator/ObfReport.h utils/test_graph_report.py
git commit -m "feat: add obfuscated graph model"
```

### Task 2: Scan final IR for calls and control-flow relations

**Files:**
- Modify: `ObfReport.cpp:394-497`
- Modify: `include/llvm/Transforms/Obfuscator/ObfReport.h:94-150`
- Test: `utils/test_graph_report.py`

**Interfaces:**
- Consumes `GraphModel` from Task 1.
- Produces `collectFinalIRGraph(const Module&, GraphModel&)`.

- [ ] **Step 1: Write the failing test**

Add a textual IR fixture with one direct call, one indirect function-pointer call, one `indirectbr`, and a `blockaddress` global. Assert JSON contains `direct_call`, `indirect_call`, `indirect_branch`, and `blockaddress_ref`, and that only the direct edge has `static_exact: true`.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest utils/test_graph_report.py -q`

Expected: FAIL because current graph fragments only contain direct named calls and no edge typing.

- [ ] **Step 3: Write minimal implementation**

Walk final non-declaration functions. Create stable function nodes, classify direct `CallBase` targets, emit `unknown_indirect` for unresolved indirect calls, inspect `IndirectBrInst` destinations, and scan `BlockAddress` constants recursively enough to emit references. Mark generated functions using the existing obfuscator marker API/metadata where available.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest utils/test_graph_report.py -q`

Expected: PASS with all edge types and exactness flags.

- [ ] **Step 5: Commit**

```bash
git add ObfReport.cpp include/llvm/Transforms/Obfuscator/ObfReport.h utils/test_graph_report.py
git commit -m "feat: collect obfuscated IR graph edges"
```

### Task 3: Add VM witness and Zone graph facts

**Files:**
- Modify: `ObfReport.cpp:394-497, 674-750`
- Modify: `include/llvm/Transforms/Obfuscator/ObfReport.h:68-104`
- Test: `utils/test_graph_report.py`, `utils/test_vm_witness.py`

**Interfaces:**
- Consumes `FunctionReport::VM` and `VMEngineWitness` from the existing report sink.
- Produces `appendVMWitnessGraph(const FunctionReport&, GraphModel&)` and `appendZoneGateEdges(const Function&, GraphModel&)`.

- [ ] **Step 1: Write the failing test**

Build a report fixture containing an engine ID, real handlers, two handler variants, decoys, dependencies, and a Zone gate call. Assert JSON has `vm_engine`, `vm_dispatcher`, `vm_handler`, `vm_handler_variant`, `handler_table`, `vm_dispatch`, `generated_dependency`, and `zone_gate` facts.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest utils/test_graph_report.py utils/test_vm_witness.py -q`

Expected: FAIL because witness data is currently serialized only under per-function report JSON and is not part of the graph.

- [ ] **Step 3: Write minimal implementation**

Use the existing witness engine ID and handler arrays to create stable logical nodes. Represent opcode and variant relationships as non-exact VM edges. Add decoy nodes/count metadata and witness dependency edges. Detect `xollvm_zone_require` by direct callee name and emit a `zone_gate` node/edge without recursively expanding the runtime.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest utils/test_graph_report.py utils/test_vm_witness.py -q`

Expected: PASS and witness counts match the existing JSON witness values.

- [ ] **Step 5: Commit**

```bash
git add ObfReport.cpp include/llvm/Transforms/Obfuscator/ObfReport.h utils/test_graph_report.py utils/test_vm_witness.py
git commit -m "feat: include VM and Zone graph facts"
```

### Task 4: Emit JSON, SVG, CFGs, and aggregated fragments from GraphModel

**Files:**
- Modify: `ObfReport.cpp:401-540, 674-750`
- Modify: `include/llvm/Transforms/Obfuscator/ObfReport.h:132-150`
- Test: `utils/test_graph_report.py`

**Interfaces:**
- Consumes complete `GraphModel` from Tasks 1-3.
- Produces `obfuscated_callgraph.json`, `obfuscated_callgraph.svg`, `.graph` fragments, and final per-function SVGs; keeps `program_callgraph.svg` only for explicit `direct` mode compatibility.

- [ ] **Step 1: Write the failing test**

Assert `obfuscated_callgraph.svg` and `.json` exist, are valid UTF-8/XML/JSON, include typed nodes/edges, and that `direct` mode still writes the legacy `program_callgraph.svg`.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest utils/test_graph_report.py -q`

Expected: FAIL because current output has no typed aggregate JSON and uses only the legacy filename.

- [ ] **Step 3: Write minimal implementation**

Replace direct-only fragment serialization with deterministic GraphModel serialization, merge nodes/edges by stable ID under the existing lock, emit typed JSON and self-contained SVG with legend/colors, and preserve the direct writer path. Escape JSON through LLVM JSON APIs and SVG text/attributes through one local XML escape helper.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest utils/test_graph_report.py -q`

Expected: PASS including duplicate-fragment replacement and special-character fixtures.

- [ ] **Step 5: Commit**

```bash
git add ObfReport.cpp include/llvm/Transforms/Obfuscator/ObfReport.h utils/test_graph_report.py
git commit -m "feat: render typed obfuscated graph reports"
```

### Task 5: Build, integrate, and verify NDK/demo behavior

**Files:**
- Modify: `utils/test_graph_report.py` only if integration assertions need exact tool arguments.
- Modify: `/data/user/0/com.termux/files/home/demo/jni/Android.mk` only if the new mode is not already passed by the existing graph configuration.
- Test: `utils/test_graph_report.py`, `zone_runtime/tests`, `/data/user/0/com.termux/files/home/demo/jni/test_demo_contract.sh`

**Interfaces:**
- Consumes the completed compiler implementation.
- Produces rebuilt `clang`/`opt` and demo graph artifacts without external graph tools.

- [ ] **Step 1: Write the failing integration assertion**

Extend the graph contract to require `obfuscated_callgraph.json`, at least one VM node when the VM demo is enabled, and no Python/Graphviz command invocation in the compiler path.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest utils/test_graph_report.py -q`

Expected: FAIL before rebuilding the modified compiler.

- [ ] **Step 3: Build and run the implementation**

Run:

```bash
cmake --build /data/user/0/com.termux/files/home/xollvm-android/build --parallel 6 --target opt clang
```

Then run the existing demo clean build and graph contract from the demo directory using its established commands. Do not build as root.

- [ ] **Step 4: Run all verification**

Run:

```bash
python -m pytest -q
python -m pytest utils/test_graph_report.py zone_runtime/tests -q
bash /data/user/0/com.termux/files/home/demo/jni/test_demo_contract.sh
git diff --check
```

Expected: all tests pass, demo runtime still passes Zone login/algorithm/logout checks, and graph output contains typed VM structure.

- [ ] **Step 5: Commit**

```bash
git add ObfReport.cpp ObfuscationOptions.cpp include/llvm/Transforms/Obfuscator/ObfReport.h include/llvm/Transforms/Obfuscator/ObfuscationOptions.h utils/test_graph_report.py docs/superpowers/plans/2026-10-01-obfuscated-graph-report.md
git commit -m "feat: report obfuscated VM graph structure"
```
