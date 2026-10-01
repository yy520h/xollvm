# 混淆后真实调用图报告第二阶段设计

## 目标

将现有的直接函数调用图升级为“混淆后结构图”。报告必须反映 XOLLVM 完成 VM、flattening、BCF、ADec、function merging、Zone gate 等模块级和函数级变换后的 LLVM Module 结构，而不是只根据原始 `CallBase -> Function` 关系生成一张干净的业务调用图。

报告的主要用途是检查混淆效果：使用者能够看到混淆器生成的 wrapper、VM engine、dispatcher、handler、handler variant、间接跳转和授权门等结构，并能区分直接关系与静态无法唯一解析的动态关系。

## 非目标

- 不声称静态 LLVM 图等同于 IDA 对最终机器码的完整运行时视图。
- 不猜测 VM 在某次输入下唯一的动态执行路径；动态 opcode 和间接跳转使用集合边表示。
- 不在目标程序运行时生成图，也不把图形报告代码链接进交付的 Android 程序。
- 不依赖目标机器上的 Python、Graphviz、Termux、Node.js 或其他外部程序。
- 不默认生成每个混淆 pass 的图片；pass 快照仍由现有 `-obf-report-dir` 的 DOT 报告控制。

## 用户接口

保留现有选项：

```text
-mllvm -obf-graph-dir=<directory>
```

增加图模式：

```text
-mllvm -obf-graph-mode=obfuscated
```

允许值：

- `obfuscated`：默认模式，生成混淆后结构图。
- `direct`：兼容当前简单直接调用图，适合和混淆后图对照。

`obfuscated` 模式只在 `-obf-graph-dir` 非空时启用。未知模式必须在 LLVM 命令行解析阶段报错，不静默降级。

## 输出

```text
<graph-dir>/
├── obfuscated_callgraph.svg
├── obfuscated_callgraph.json
├── modules/
│   └── <module-key>.graph
└── functions/
    ├── <function>.svg
    └── ...
```

`obfuscated_callgraph.svg` 是自包含 SVG，可以直接由浏览器打开，不包含外部字体、脚本、图片或 CSS 文件。

`obfuscated_callgraph.json` 是稳定的机器可读图模型，至少包含：

- schema 和 schema version；
- module identifier；
- nodes：稳定 ID、显示名、节点类型、来源函数、是否由 obfuscator 生成；
- edges：稳定 ID、from、to、边类型、是否静态确定、可选 opcode/handler 信息；
- VM engines：engine ID、配置摘要、真实 handler、variant 数、decoy 数、handler table 大小；
- generation limitations：间接调用、动态 opcode、外部声明、未解析跳转等说明。

每个非声明的最终函数生成一张 CFG SVG。CFG 必须从变换完成后的函数读取，至少支持：

- 普通基本块边；
- `indirectbr` 的多目标边；
- `blockaddress` 引用；
- dispatcher 和 handler 基本块；
- back edge 和自循环；
- obfuscator 标记的基本块。

## 图模型

### 节点类型

至少支持以下类型：

- `source_function`：用户原始函数的最终 wrapper 或剩余函数；
- `generated_function`：混淆器生成的函数；
- `vm_engine`：`__vm_engine` 或 nested engine；
- `vm_handler`：opcode handler；
- `vm_handler_variant`：handler variant；
- `vm_dispatcher`：VM fetch/dispatch 结构；
- `indirect_target_set`：无法静态唯一解析的目标集合；
- `external_declaration`：外部声明，仅当被图边引用时加入；
- `zone_gate`：`xollvm_zone_require` 授权门调用；
- `unknown_indirect`：存在间接调用但没有足够静态信息解析时的占位节点。

### 边类型

- `direct_call`：LLVM 能直接解析到目标函数的调用；
- `indirect_call`：函数指针或间接调用，目标为集合或未知节点；
- `vm_wrapper`：原函数 wrapper 到 VM engine 的关系；
- `vm_dispatch`：engine/dispatcher 到 handler 集合；
- `handler_table`：handler table 到 handler variant 的引用；
- `handler_variant`：opcode 到具体 variant 的关系；
- `indirect_branch`：`indirectbr` 到可能基本块目标；
- `blockaddress_ref`：全局表或常量对基本块地址的引用；
- `generated_dependency`：生成函数之间的依赖；
- `zone_gate`：业务函数到授权门的关系。

每条边必须携带 `static_exact` 布尔字段。VM dispatch、加密 dispatch、函数指针和无法唯一解析的关系必须标记为 `false`，不能伪装成确定调用。

## VM 关系采集

VM 生成器在创建结构时向模块级图采集器发布事实，而不是由报告器猜测名称。采集点包括：

1. `VMImpl::commit()` 创建 wrapper、bytecode、callee 表和 handler table 时，记录原函数、engine ID 和 wrapper 关系。
2. `populateVMEngine()` 创建 engine 和 dispatcher 时，记录 engine 节点及其 dispatcher 节点。
3. `buildHandlerTable()` 创建 opcode、variant、decoy 和 engine pointer slot 时，记录 handler table 边。
4. nested VM 创建 helper/inner engine 时，记录 engine dependency 和 nested handler 关系。
5. wrapper 中的间接 engine call、`indirectbr`、`blockaddress` 和 handler table load 记录为动态或非唯一边。
6. `VMEngineWitness` 与图节点使用同一 engine ID、配置 key、真实 handler 和 variant 数，避免报告出现两套不一致的数据。

采集器必须使用稳定的逻辑 ID，不使用临时 LLVM 指针地址。节点 ID 至少绑定 module seed、engine ID、函数名和 handler/opcode 信息，并在同一 seed 下可复现。

## 非 VM 混淆结构

- BCF 和 flattening 的最终基本块及其边直接从最终 LLVM CFG 读取。
- ADec 生成的 `indirectbr`、blockaddress 和 trampoline 使用专门边类型写入 JSON/SVG。
- function merging 的 super-function、selector dispatch 和 thunk 使用最终 Module 中的函数及调用/跳转关系表示。
- Zone gate 根据注入的 `xollvm_zone_require` 调用和 capability 字符串标记为 `zone_gate`，不把网络 runtime 的所有内部函数展开到默认业务图中。
- 外部 SDK 和 C++ 标准库默认显示为 `external_declaration`，但不把其内部实现当作当前 Module 的混淆效果。

## 编译器内置实现

所有报告生成逻辑编译进 XOLLVM 的 `clang`/`opt`：

- C++ 图采集器位于 Obfuscator 静态扩展内；
- C++ 直接写 JSON 和 SVG；
- 不调用 Python 子进程；
- 不调用 Graphviz；
- NDK 交付只需同步带该选项和实现的 `clang`/`opt`；
- 输出 SVG 使用固定内置样式和布局，不读取外部模板；
- 文件锁和 module fragment 聚合继续由 LLVM C++ 文件系统 API 完成。

编译器仍可以保留 Python HTML 报告工具作为开发者的可选增强，但核心总图和逐函数 SVG 不得依赖该工具才能生成。

## 多源文件构建

每个 LLVM Module 写入一个 fragment。fragment 至少包含节点和边事实，不直接把单个 Module 的图当作最终总图。写入共享目录时使用 LLVM 文件锁：

1. 获取图目录锁；
2. 原子写入当前 module fragment；
3. 读取全部 fragment 并按稳定 ID 合并节点和边；
4. 写入新的 `obfuscated_callgraph.json` 和 `obfuscated_callgraph.svg`；
5. 释放锁。

同一个 module key 的旧 fragment 必须被覆盖，避免增量构建残留。不同输出目录之间不得共享状态。

## 错误和限制

- 无法解析的间接调用必须生成 `unknown_indirect` 节点或明确的 unresolved edge，不能静默丢失。
- SVG 写出失败必须通过 LLVM diagnostic 报告路径和系统错误，但不能破坏未启用图报告时的普通构建。
- 图报告失败时，默认不改变目标程序生成；`-obf-graph-strict` 可选地将报告错误升级为构建失败。
- 图过大时使用稳定的分层/分区布局，并在 JSON 中记录节点和边数量；不通过截断关系制造假图。
- 递归边、自循环和多个平行边必须保持可辨识；JSON 中可以去重，SVG 中可以使用曲线或偏移。

## 测试

必须增加以下测试：

- `direct` 模式保留直接调用图行为；
- `obfuscated` 模式输出不同于 direct 模式的 VM/生成结构；
- 含 VM 的 fixture 包含 engine、dispatcher、handler 或 handler table 节点；
- handler variant、decoy、encrypted dispatch 和 nested VM 的计数与 `VMEngineWitness` 一致；
- `indirectbr` 和函数指针调用不会被错误地写成确定 direct edge；
- Zone gate 节点和边存在且 capability 可追踪；
- 多 Module 并行写 fragment 后总图包含全部节点和边；
- 重复构建覆盖同 module fragment，不保留过期节点；
- 无 Python、Graphviz 和 Termux 环境时，直接执行 `opt` 仍能生成有效 SVG/JSON；
- SVG/XML 转义、超长函数名、递归边、空 Module 和只有外部声明的 Module；
- 未开启 `-obf-graph-dir` 时无新增文件、无图报告行为回归；
- 现有 Zone、VM 和完整 Python 测试继续通过。

## 完成标准

1. `-obf-graph-mode=obfuscated` 生成的总图反映最终 Module 的混淆后结构，而不是只显示原始直接调用关系。
2. VM engine、dispatcher、handler、variant、decoy、nested dependency 和间接关系在 JSON 中可追踪，在 SVG 中可视化。
3. 每个最终非声明函数都有对应 CFG SVG，且能表示 `indirectbr`、blockaddress 和 dispatcher 结构。
4. 总图和逐函数 SVG/JSON 由内置 C++ 实现生成，不依赖目标机器外部运行时工具。
5. 多源文件并行构建的 fragment 聚合稳定、可复现且不会被最后一个 Module 覆盖。
6. 图报告关闭时现有编译产物和性能行为保持不变，图报告开启时新增耗时主要来自报告扫描和 SVG 写出，而不是混淆流水线本身。

## 明确边界

该报告是“混淆后 LLVM Module 和 XOLLVM 生成结构图”，不是运行时动态 trace，也不是最终机器码的完整反汇编数据库。它必须诚实标注静态无法唯一解析的关系；如果将来需要最终 ELF 地址布局或运行时路径，应作为独立的 binary/post-link 报告阶段实现。
