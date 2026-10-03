# XOLLVM 项目分析与风险评估

> 分析时间：2026-10-03
> 分析方式：静态源码分析（只读，未修改任何源码，未运行构建/测试）
> 项目 HEAD：`5f4f4f1 docs: 移除已归档的 superpowers 计划与规范文档`

## 1. 项目定位

`xollvm-android/xollvm` 是一个基于 **LLVM New Pass Manager** 的 Android/AArch64 混淆工具链扩展。它不是单一的控制流混淆 Pass，而是由三层组成：

1. **LLVM 混淆 Pass 集合**：在 LLVM IR 层做控制流、数据流、调用关系、常量/字符串保护。
2. **VM 虚拟化引擎**：把选定函数转换为自定义字节码，并生成解释执行的 engine、handler 和 wrapper。
3. **Zone 授权运行时**：负责卡密授权、心跳、capability 校验、云值 dispatch 和最终目标链接依赖。

支持两种使用方式：

- 直接集成进 `clang`/`opt`（LLVM in-tree extension）。
- 构建独立插件 `Obfuscator.so`，通过 `-fpass-plugin` 或 `-load-pass-plugin` 加载。

主构建入口为 `CMakeLists.txt`。

## 2. 目录与模块结构

| 分类 | 主要文件 | 作用 |
| --- | --- | --- |
| 基础运算混淆 | `MBAObfuscation.cpp`、`Substitution.cpp` | 改写算术、逻辑与指令序列 |
| 控制流混淆 | `BogusControlFlow.cpp`、`SplitBasicBlock.cpp`、`Flattening.cpp` | 伪控制流、基本块切分、CFG 扁平化 |
| 数据保护 | `ConstantEncryption.cpp`、`StringEncryption.cpp`、`SemanticDiffusion.cpp` | 常量/字符串加密、语义扩散 |
| 调用关系保护 | `VirtualCall.cpp`、`FunctionMerging.cpp` | 隐藏直接调用、函数合并与共享分发 |
| 反反编译 | `AntiDecompiler.cpp`、`ADec/` | 干扰反汇编/反编译的结构注入 |
| 反调试 | `AntiDebug.cpp`、`VMPass_AntiDebug.cpp` | tracerPid、ptrace、时序、maps、完整性、动态监控 |
| 后续优化防护 | `AntiOptimizationShield.cpp` | 降低后续 `-O2/-O3` 还原混淆结构的概率 |
| VM 虚拟化 | `VMPass*.cpp`、`VMPass*.h` | 字节码编译、engine、dispatch、wrapper |
| 报告与诊断 | `ObfReport.cpp`、`ObfMetrics.cpp`、`ObfDebug.cpp` | CFG/JSON 报告、指标、跳过原因 |
| 授权运行时 | （已移除） | Zone 登录、心跳、capability、cloud dispatch（已分离到 demo 项目） |
| 加密 stub | `aes_stub/` | AES-CTR / ChaCha 运行时解密 stub |

## 3. Pass 注册与配置流程

Pass 注册入口是 `registration/PluginEntry.cpp`，通过 LLVM PassBuilder 回调注册：

- 模块管线名 `obfuscation`
- 函数管线名 `obfuscation-fn`
- `-enable-obfuscation` 编译器扩展点
- 模块分析与函数分析

业务代码通过注解头文件 `docs/obf_annotations.h` 使用：

```cpp
#include "obf_annotations.h"

OBF("vm(hardened=1), mba, bcf")
int secret_check(const char *value) {
    return value != nullptr;
}
```

注解解析链路（`ObfuscationConfig.cpp`）：

```text
obf: 注解字符串
  -> AnnotationParser::parseAnnotationString
  -> 按顶层逗号切分 pass spec（跳过括号内逗号）
  -> parsePassConfig（pass 名 + key=val 参数表）
  -> 标准化 pass ID、校验是否已知
  -> ObfuscationConfig（passes + budget）
```

全局命令行选项集中在 `ObfuscationOptions.cpp`，主要包括 `-obf-seed`、`-obf-deterministic`、`-obf-verify`、`-obf-max-function-insts`、`-obf-ir-budget-multiplier`、`-obf-pipeline-ordering`、`-obf-report-*`。（`-obf-zone-*` 已随 zoneauth 移除）

## 4. 混淆管线顺序

执行顺序由 `ObfuscationPipeline.cpp` 按依赖规则拓扑排序，不是照搬注解书写顺序。典型顺序：

```text
fmerge / constenc
  -> mba / substitution
  -> split / sdiff
  -> bcf
  -> vm 或 flattening（二者冲突）
  -> vcall
  -> shield
  -> strenc（module pass，实际在函数管线之前运行）
  -> adec（最后）
```

关键约束：

- `constenc` 尽早执行，避免后续算术改写破坏其目标。
- `mba`、`substitution` 先于 CFG 重构类 Pass。
- `flattening` 先于 `vcall`：flattening 默认不接受已有间接调用，而 vcall 会引入间接调用。
- `vm` 先于 `vcall`：VM 需要把可静态识别的 callee 放入常量表。
- `vm` 与 `flattening` 冲突：二者都重构整个函数 CFG，同时启用会 `report_fatal_error`。
- `vm` 先于独立 `antidebug`：独立 AntiDebugPass 注入的多值返回 guard 会让 `isVMEligible` 拒绝该函数。
- `adec` 最后执行。

模块级编排（`include/llvm/Transforms/Obfuscator.h` 中的 `ObfuscationModulePass::run`）：

```text
ObfVerify(pre) → FunctionMergingPass
  → ObfVerify → StringEncryptionPass → ObfVerify
  → ObfuscationFunctionDriverPass（逐函数按注解驱动各 Pass，含预算事务）
  → ObfVerify(final)
  → VMPlanCoordinator.freeze() + commit()（VM engine 统一生成）
  → 报告输出
```

（`ZoneAuthModulePass` 已随 zoneauth 功能移除）

每个函数的 Pass 循环带事务化预算保护：单 Pass 超预算时回滚到执行前快照并记录 skip，而不是被下一个 Pass 才发现。

## 5. VM 虚拟化执行流程

VM 主入口在 `VMPass.cpp` 的 `VMPass::run`。整体流程：

```text
函数注解
  -> VMPassConfig::fromPassConfig
  -> isVMEligible 资格判断
  -> 克隆模块、PHI demote、intrinsic 降级
  -> BytecodeEmitter 生成字节码
  -> verifyBytecode 结构校验
  -> VMPlanCoordinator 按 EngineConfigKey 分组
  -> freeze() 分配 engine ID
  -> commit() 构建共享/独立 __vm_engine、handler、dispatch
  -> 原函数体替换为 wrapper，间接调用 __vm_engine
```

### 5.1 配置

`VMPassConfig` 支持 `preset=medium|high|max` 及显式开关：`hardened`、`encBytecode`、`encDispatch`、`threadedDispatch`、`keyedDispatch`、`nestedVM`、`superOps`、`randISA`、`handlerVariants`、`handlerDecoys`、`perFnEngine`、`metamorphicEngines`、`cloudDispatch`、`lazyDecrypt`、`constInStream`、`rollingRegKey` 等。

配置依赖约束（`fromPassConfig` 内强制）：

- `lazyDecrypt`、`hardened`、`constInStream` 依赖 `encBytecode`。
- `hardened` 隐含 `regEncrypt`。
- `bindAntiDebug` 依赖 `hardened && antiDebug`。
- `metamorphicEngines` 需要 `enginePoolSize >= 2` 或 `perFnEngine`。
- `handlerVariants` 限幅 `[1, kMaxHandlerVariants]`，`handlerDecoys <= 3`。

### 5.2 资格检查（isVMEligible）

`include/llvm/Transforms/Obfuscator/VMPass_Impl.h` 中的 `isVMEligible` 会拒绝：

- 含 EH pad / invoke / callbr / 已有 indirectbr / naked 属性的函数。
- 基本块数超出 `[minBlocks, maxBlocks]` 的函数。
- **多值返回函数**：返回值返回的 `ret` 多于 1 个时直接 bail（`multi-value-return`）。这是对 `computeReturnInfo` 只记录第一个返回槽这一已知限制的保守缓解，见 §8.1。

### 5.3 Engine 分组

`VMPass_Plan.cpp` 的 `VMPlanCoordinator` 收集各函数 prepare 结果，按 `EngineConfigKey`（含 randISA、cloudDispatch 等配置）分组：

- 兼容配置共享 engine 和 handler 域（demand pruning）。
- 不同配置发生碰撞时按 key hash 重新分配 engine pool ID，保证物理隔离。
- `nestedVM` 组暂时保留完整 handler 域。

### 5.4 Wrapper

`VMPass_Wrapper.cpp` 的 `buildWrapper()` 负责：

- 先重建原始 entry block 的 alloca（保持栈布局稳定）。
- 分配 i32/i64/指针/浮点虚拟寄存器文件（hardened 下乱序分配并清零）。
- 写入参数、常量、per-slot XOR key。
- 初始化 `vm.ip`、salt。
- 间接调用 `__vm_engine`（engine 指针来自 handler 表，打断静态调用图）。
- 从寄存器文件提取返回值返回。

hardened 模式额外做常量 blind（opaque 表达式）、寄存器加密、结构扰动，并可对 wrapper 自身再做 switch 分发式扁平化。

### 5.5 Dispatch

中央 dispatch（`buildDispatch`）与 threaded dispatch（`emitThreadedTail`）逻辑镜像：

```text
读取 vm.ip → 边界检查（越界 -> vm.exit）
  -> loadBC 取 opcode（encBytecode 时解密）
  -> keyedDispatch：按 IP 的 key 反 XOR
  -> ip++
  -> opcode 域检查：>= OP_COUNT -> InvalidBB（llvm.trap + unreachable）
  -> encDispatch：经 dmap 解密得到排列后的槽位
  -> handlerVariants：按 (ip, salt) 选择变体 v，槽位 = P*K + v
  -> cloudDispatch：TableSlot += __zone_get_dispatch_offset()
  -> GEP handler 表 -> indirectbr
```

非法 opcode 走显式 trap，不再用 `urem` 折回合法操作码。`cloudDispatch` 的 offset 叠加没有任何本地校验分支，合法云值 offset 为 0，非法/过期值直接把索引推离有效区域。

## 6. Cloud dispatch 与 Zone 运行时链路

### 6.1 编译期注入

`cloudDispatch=1` 时，中央 dispatch（`VMPass_Dispatch.cpp` buildDispatch）和 threaded dispatch（emitThreadedTail）各注入一次 `__zone_get_dispatch_offset()` 调用。`cloudDispatch=0` 时完全不引用运行时符号。

### 6.2 客户端运行时

`zone_runtime/cloud_value_manager.cpp`：

```text
首次进入 dispatch
  -> 惰性启动后台预取线程
  -> 若尚无 V（fetch_time == 0），同步拉取一次
  -> 读取当前 window_id（按 60s 窗口 + 时间偏移）
  -> HMAC-SHA256(dispatch_v, little_endian window_id)
  -> 取低 12 bit（0xFFF）作为 offset
```

后台线程按 50s 预取间隔刷新，失败最多重试 3 次，失败时继续用旧 V（窗口推进后 offset 自然偏移）。`xollvm_zone_vm_dispatch_refresh()` / `xollvm_zone_vm_dispatch_copy_v()` 由 `zone_wrapper.cpp` 提供，弱符号引用使独立单测可缺省。

### 6.3 云端参考实现

`zone_runtime/cloud/capability_v1.js`：对每个 window 搜索 32 字节 `dispatch_v`，使 `HMAC(V, window) & 0xFFF == 0`，随 Ed25519 签名的响应下发 `dispatch_v`/`window_id`/`dispatch_blob`。

### 6.4 Zone 授权主流程（已移除）

`ZoneAuth.cpp` 已从编译器移除，zone_runtime 已分离到 demo 项目独立维护。
编译器不再注入 Zone 授权调用。如需 Zone 授权，请在最终项目中自行集成
zone_runtime 源码。

## 7. 构建、交付与平台约束

### 7.1 构建模式

- **in-tree 静态扩展**：`-DLLVM_EXTERNAL_PROJECTS=Obfuscator -DLLVM_EXTERNAL_OBFUSCATOR_SOURCE_DIR=<本目录> -DLLVM_OBFUSCATOR_LINK_INTO_TOOLS=ON`，编译进 clang/opt。
- **standalone 插件**：`find_package(LLVM)` 后构建 `Obfuscator.so`。

两种模式共享 `add_llvm_pass_plugin(Obfuscator ...)`。AES stub 由外部 clang 编成 bitcode 再转为 C 数组头文件编译进 Obfuscator；`Obfuscator`/`obj.Obfuscator` 都依赖 `aes_stub_inc` 生成目标。

### 7.2 单元测试目标

`LLVM_INCLUDE_TESTS` 且 in-tree 时构建 `VMRequirementsTests`（`utils/VMRequirementsTest.cpp` + VM requirements/emitter/verifier）。

### 7.3 Android/Termux 约束

- Android 构建目标 `aarch64-linux-android`、`arm64-v8a`、API 24，并加 `-static-libstdc++`，使产物可在没有 Termux C++ runtime 的 MT 终端运行。
- 构建必须用 Termux 普通用户身份；root 构建会污染中间产物属主。
- MT 终端执行脚本需显式 `bash xxx.sh`（无 `/usr/bin/env`）。

### 7.4 交付边界

LLVM 工具链与最终项目自行集成的 Zone runtime 是两个交付面：

- `clang`/`opt`/插件属于编译工具链。
- Zone runtime 源码、curl/zlib/OpenSSL 源码及其构建规则属于最终项目，不再由 XOLLVM 提供。
- XOLLVM 不再打包 Zone archive，也不再提供 `zoneauth` 编译器参数或自动链接包装器。
- `cloudDispatch` 需要的 `__zone_get_dispatch_offset()` 外部符号由最终项目自行集成的 runtime 提供。

## 8. 已发现问题与风险

> 说明：以下问题来自静态分析。其中「多返回错误值」因 §5.2 的资格检查已被**缓解**（该形状函数被跳过不做 VM），其余多数为未缓解或部分缓解。

### 8.1 VM 正确性

| # | 问题 | 位置 | 等级 | 状态 |
| --- | --- | --- | --- | --- |
| 1 | 多返回函数 wrapper 固定读第一个返回槽 | `VMPass_Wrapper.cpp computeReturnInfo()` | 高（设计上） | **已被 isVMEligible 的 multi-value-return bail 缓解**；属已知限制而非未修复 bug。长期可统一 return slot 后放开限制 |
| 2 | CALL handler 用 PtrTy/DoubleTy 统一重建调用签名，未保留真实 ABI（float 被当 double 调） | `VMPass_Handlers.cpp buildCall2()` | 高 | **已修复**：float 参数用真实 float 类型调用，不再升 double；同步修复 `ensureCallFTyCases()` |
| 3 | CALL 按固定 MaxArgs 预读参数槽字节，与 `nargs` 无关，可能越界读取字节码 | `VMPass_Handlers.cpp buildCall2()` | 高 | **已修复**：只按真实形参数预读参数字节，超过 NArgs 的槽位不读取 |
| 4 | `FCMP_TRUE`（谓词 15）verifier 接受但 handler 默认返回 0 | `VMPass_Verifier.cpp` / `VMPass_Handlers.cpp` | 高 | **已修复**：handler 与 nested helper 均添加 FCMP_TRUE case，返回 i32 1 |
| 5 | intrinsic 降级非严格等价：`fabs`(-0)、`fma` 融合舍入、`minnum/maxnum`(NaN)、`copysign`(NaN/-0)、`memset`(size 0 -> 0 位整数类型) | `VMPass_Impl.cpp prepare()` | 中高 | **已修复**：fabs/fma/minnum/maxnum/copysign 不再降级，保留原样由 isize() 标记 unsupported；memset 跳过 size==0 的 0 位整数类型 |
| 6 | AES stub 缺失时 `buildEncryptCtor()` 仅记录错误返回，提交继续，生成无法解密字节码的坏产物 | `VMPass_Crypto.cpp` | 高 | **已修复**：AES stub 缺失/链接失败时 `report_fatal_error` 中止编译 |

### 8.2 Cloud / Zone 安全

| # | 问题 | 位置 | 等级 | 状态 |
| --- | --- | --- | --- | --- |
| 7 | `xollvm_zone_vm_dispatch_refresh` 不走 `acceptResponse()`，dispatch_v 未经签名/request/device/有效期/window 绑定校验即写入全局状态 | `zone_wrapper.cpp` | 高 | **已修复**：新增 `verifyDispatchResponse()` 复用验签/request/device/有效期绑定校验，通过后才写入 dispatch_v |
| 8 | 云端源码内置 `kServer` 与 `signingPrivateKey` | `zone_runtime/cloud/capability_v1.js` | 高 | 跳过（用户要求不修改） |
| 9 | `CloudValue.m_V.data` 32 字节数组跨线程 memcpy，无互斥/双缓冲/版本校验，可能读到撕裂 V | `cloud_value_manager.cpp` | 中高 | **已修复**：`CloudValue` 增加 `std::mutex`，`data` 读写均在锁保护下进行 |
| 10 | `fetchVFromCloud(windowId, ...)` 忽略 windowId，窗口翻转期间可能装错窗口的 V | `cloud_value_manager.cpp` | 中高 | **已修复**：`CloudValue` 记录 `window_id`，`computeDispatchOffset` 使用 V 对应的 window_id 而非当前 window 计算 HMAC |
| 11 | 12-bit mask 失效是概率性的：错误 V 有约 1/4096 概率仍得 offset 0 | 设计取舍 | 中 | **已修复**：文档 `项目功能与命令总览.md` 已补充概率失效说明 |
| 12 | capability 状态文件只恢复 state，不恢复 response，重启后离线恢复实际失败 | `capability_client.cpp` | 中 | **已修复**：`writeState`/`loadState` 持久化完整 response 字段（vm_value/issued_at/expires_at/key_id/policy_version），重启后离线 `require()` 可用 |

### 8.3 构建与跨平台

| # | 问题 | 位置 | 等级 | 状态 |
| --- | --- | --- | --- | --- |
| 13 | ZoneAuth 失败路径硬编码 AArch64 svc 退出，普通 workflow 同时构建 x86_64/Windows，ZoneAuth 实为 Android/AArch64 特化 | `ZoneAuth.cpp injectStartup()` | 中高 | **已移除**：zoneauth 功能已从编译器移除 |
| 14 | `zone_archive_audit.py` 接收 target_triple 但不验证 archive 架构 | `zone_runtime/zone_archive_audit.py` | 中 | **已移除**：zone_runtime 已分离到 demo 项目 |
| 15 | 符号前缀化排除 `_Z` 开头 C++ mangled 符号，bundled SDK 的 C++ 符号隔离不充分 | `zone_runtime/zone_prefix_archive.py` | 中 | **已移除**：zone_runtime 已分离到 demo 项目 |
| 16 | 配置项 `-obf-zone-capability-valid-seconds` 声明后未接入实际逻辑（有效期由云端决定） | `ObfuscationOptions.cpp` | 低 | **已移除**：`-obf-zone-*` 参数已随 zoneauth 移除 |
| 17 | `injectStartup` 中 `SetShutdownMode` 被调用两次、`ObfZoneShutdownMode` 校验重复 | `ZoneAuth.cpp` | 低 | **已移除**：zoneauth 功能已从编译器移除 |

### 8.4 其他观察

- `VMPass_Dispatch.cpp` 的共享 engine 状态下 CALL 变体被固定到最后一个变体（注释说明原因：CALL 的 FTy switch 只挂在最后构建的变体上），这是已知折中，不是缺陷。
- Zone 登录传 `NULL` 卡密时走 stdin 交互读取；无 stdin/后台服务/Android JNI 场景会阻塞，属接口适用性限制。

## 9. 测试现状

### 9.1 已覆盖

- `utils/VMRequirementsTest.cpp`：VM 配置、requirement 合并、engine 分组、randISA 等单元测试。
- `utils/test_vm_cloud_dispatch_gates.py`：cloudDispatch 注入的结构 gate（两处注入、关闭时不引用符号）。

（`zone_runtime/` 相关测试已随 zoneauth 功能移除，zone_runtime 已分离到 demo 项目）

### 9.2 主要缺口

- 大量测试是「源码中存在某字符串/片段」的结构 gate，不是真实行为回归。
- Python/Node/Zone CTest 未全部接入主 CI；根 CMake 只注册 `VMRequirementsTests`。
- `utils/test_vm_cloud_dispatch_e2e.py` 依赖仓库外固定 demo 路径（`/data/user/0/.../demo/jni/main.cpp`），干净环境不可复现。
- Android workflow 只检查 ELF，未在 Termux/bionic 环境真正执行 clang/opt 与 Zone 链接。
- 缺 AES/ChaCha known-answer 测试。
- 缺运行时行为回归：CALL ABI 组合、浮点边界（NaN/-0/Infinity/fma）、错误签名 dispatch_v、并发刷新、window 翻转竞态、进程重启恢复。

## 10. 修复优先级建议

### P0 — 阻止错误产物与敏感泄露

1. 移除/轮换云端源码中的真实密钥材料，改为平台 secret 注入。
2. 修复 `vm_dispatch_refresh` 的完整签名、request、device、有效期与 window 绑定校验。
3. AES stub 缺失时强制失败（终止该函数转换或编译失败），禁止产出半可用产物。

### P1 — VM 语义正确性

1. CALL handler 使用完整 `FunctionType` 重建调用，补 AArch64 ABI 回归测试。
2. CALL 按 `nargs` 读取参数槽，emitter/verifier/handler 三处统一指令长度。
3. 修复 `FCMP_TRUE` 及全部浮点谓词映射。
4. 对无法保持精确语义的 intrinsic（fma/fabs/copysign/minnum/maxnum/memset0）改为拒绝虚拟化或按 LLVM 语义精确实现。
5.（可选增强）统一多返回函数的 return slot，放开 multi-value-return 限制。

### P2 — 运行时并发与跨平台

1. cloud value 用互斥/双缓冲/版本号保证快照一致。
2. 刷新结果校验当前 window。
3. 明确 capability state 恢复语义（完整恢复或文档改口）。
4.（已移除）ZoneAuth 增加 target triple 门控。
5.（已移除）完善 archive 架构审计与 C++ 符号隔离。

### P3 — 测试与 CI

1. 补多返回、CALL ABI、浮点边界、intrinsic、AES 缺失等行为回归。
2. 补错误签名/篡改 dispatch_v、过期 window、并发刷新测试。
3. Python/Node/Zone CTest 接入 CI。
4. cloud dispatch e2e fixture 移入仓库，去除外部固定路径。
5. 增加 Android/Termux 实际运行验证。

## 11. 建议的最小验证矩阵

| 类别 | 场景 | 期望 |
| --- | --- | --- |
| VM 返回值 | 单返回、void、指针、i64、float、double | 与未混淆程序一致 |
| CALL ABI | 不同参数宽度、浮点、指针 | 参数与返回值不损坏 |
| Dispatch | central、threaded、encrypted、keyed、cloud | 合法正常、非法 opcode trap |
| VM 加密 | AES stub 存在/缺失 | 存在可运行，缺失明确失败 |
| 浮点 | NaN、-0、Infinity、fma | 与 LLVM 基线一致 |
| Cloud | 有效/错误/过期 V、window 翻转 | 验签正确、状态一致、无撕裂 |
| Zone | 登录失败、心跳失败、退出、重启 | 符合 fail-closed |
| 平台 | Termux、MT、Android AArch64 | 运行时依赖与 C++ ABI 正确 |

## 12. 最终评价

XOLLVM 已从传统 LLVM 混淆 Pass 演进为「编译期 VM + 多级 IR 混淆 + 授权运行时 + 云值门控」的完整工具链。Pass 注册、注解解析、管线拓扑排序、事务化预算保护、engine 分组与 Android 构建路径整体结构清晰；VM 的 dispatch 域检查、demand pruning、engine 配置隔离等设计也体现了对鲁棒性的考虑。

当前最值得投入的方向不是继续堆叠混淆选项，而是先收敛四个基础面：

- **VM 语义正确性**（CALL ABI、浮点谓词、intrinsic 等价性、AES 失败路径）。
- **cloud dispatch 的可验证链路**（完整验签、window 绑定、并发一致性）。
- **授权运行时的生命周期与平台边界**（state 恢复、AArch64 特化门控）。（zoneauth 已移除，由 demo 项目独立维护）
- **测试从结构 gate 走向真实行为回归**。

这些基础稳定后，再叠加 handler polymorphism、nested VM、更复杂的云值策略与反反编译技术，才不会持续放大调试与交付风险。
