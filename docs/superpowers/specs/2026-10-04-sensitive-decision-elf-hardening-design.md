# XOLLVM 敏感决策与 ELF 加固设计

## 1. 目标

为 XOLLVM 增加通用的敏感决策保护和最终 ELF 加固能力，并以 Zone runtime 作为首个集成与回归样例。设计针对以下静态破解路径提高自动分析成本：

1. 解析 `.rela.plt` 和 `.plt`，建立桩地址到符号名映射。
2. 从 `EVP_DigestVerify` 调用点向前回溯验签函数边界。
3. 从 `strcmp` 等比较调用追踪紧邻的条件分支和失败目标。
4. 从 `SSL_connect` 交叉引用定位授权函数。
5. 搜索 `PT_LOAD` 中不小于 512 字节的可执行零填充区并植入代码。

本设计不承诺阻止拥有 root、动态调试或完整运行时控制能力的攻击者。验收目标是破坏上述稳定静态定位链、避免关键保护静默跳过，并检测最终 ELF 的非预期可执行空洞和受保护范围篡改。

## 2. 非目标

- 不在编译器中硬编码 Zone、OpenSSL、`EVP_DigestVerify`、`strcmp` 或 `SSL_connect` 名称。
- 不把隐藏动态符号作为默认强制目标。同一符号可能仍被未保护代码使用并保留在 `.dynsym`。
- 不用随机填充替代完整性校验。
- 不修改 LLD 源码，除非标准链接脚本和后链接工具无法表达所需布局策略。
- 不恢复已经移除的编译器内置 Zone runtime 或 `zoneauth` Pass。

## 3. 威胁模型和成功标准

### 3.1 攻击者能力

假设攻击者可以获得最终 AArch64 ELF，并能使用 `readelf`、`objdump`、反编译器和自定义脚本分析动态符号、重定位、调用图、控制流和程序头，也能修改文件后重新运行。

### 3.2 自动验收标准

- 受保护区域中不存在到目标敏感 API 的直接 `BL`/PLT 调用。
- 敏感调用结果不流入普通原生 `cbz`、`cbnz` 或等价直接失败分支。
- 保护区域必须覆盖敏感调用、结果归一化、成功路径和失败动作；敏感结果不得越过保护边界后再判断。
- 关键区域无法完成要求的 VM 转换时，`strict=1` 必须导致编译失败并报告原因。
- `PF_X PT_LOAD` 中出现非白名单且不小于 512 字节的连续零区时，最终链接失败。
- 修改受保护的可执行范围、VM bytecode 或完整性 manifest 后，运行时必须 fail-closed。
- 五条攻击路径必须作为自动化回归测试，而不是依赖人工反汇编判断。

## 4. 总体架构

实现分为两个独立但组合使用的层次：

1. 编译期敏感决策保护：新增 `SensitiveDecision` 分析与规范化步骤，并扩展 VM 对多返回和严格覆盖的支持。
2. 最终链接后 ELF 加固：扩展链接包装器，在最终 ELF 上执行空洞审计、生成完整性 manifest 并校验布局策略。

Zone runtime 仅通过注解和清晰的函数边界接入通用机制，不向 XOLLVM 注入业务配置或 SDK 实现。

## 5. 用户接口

新增通用注解：

```cpp
OBF_FN("sensitive(region=auth, strict=1), vm(preset=max)")
bool verifyAndAuthorize(...);
```

也可由文档头提供语义等价的宏：

```cpp
XOLLVM_SENSITIVE_DECISION("auth")
bool verifyAndAuthorize(...);
```

参数语义：

- `region`：诊断和报告使用的稳定区域标识，不参与安全判断。
- `strict=1`：保护条件不满足、结果泄漏、VM 跳过或后端不支持时编译失败。
- `strict=0`：允许降级，但必须在 obfuscation report 中记录明确原因。

`sensitive` 不根据被调函数名称猜测语义。开发者必须把完整决策放入注解函数，或者使用后续可扩展的 metadata 显式标记结果源和决策消费者。

## 6. SensitiveDecision Pass

### 6.1 运行位置

该步骤运行在 VM 准备和提交之前、普通控制流混淆之前。它负责验证边界和规范化数据流，不直接承担最终虚拟化。

建议顺序：

```text
annotation analysis
  -> sensitive decision validation/lowering
  -> VM planning and commit
  -> supported supplemental passes
  -> strict post-validation
```

### 6.2 数据流规则

Pass 对敏感区域中的候选结果执行 def-use 分析：

- 支持 `i1` 验证结果。
- 支持整数状态码与常量比较。
- 支持 `strcmp`、`strncmp`、`memcmp` 风格的零/非零语义，但通过显式 metadata 或调用结果使用形态描述，不硬编码库名称。
- 将结果规范化为编码 decision token。
- token 只能被区域内 VM 控制流、返回值封装或显式允许的无副作用组合使用。
- token 不能存入外部可见全局、逃逸到未知调用、跨越未保护函数边界，或在 VM 外驱动原生条件分支。

### 6.3 决策边界

有效区域必须同时包含：

- 敏感调用或验证计算；
- 结果归一化；
- 成功动作或成功返回；
- 失败动作或失败返回。

仅保护返回 `bool` 的验签函数、却在未保护调用者中执行 `if (!verified)`，属于边界错误。`strict=1` 必须拒绝这种配置。

### 6.4 编译后验证

VM 提交后执行严格验证：

- 原始敏感调用和条件分支不得残留在原函数体。
- 必须存在预期的 VM bytecode、callee table 和受保护 wrapper。
- 所有敏感 token 的消费者必须已进入 VM 边界。
- 任一检查失败时，报告 region、函数、IR 指令和跳过原因。

## 7. VM 扩展

### 7.1 多返回支持

移除当前对多个值返回块的限制：

- VM context 增加统一返回值区域和返回种类字段。
- 每个 `OP_RET_*` 将值写入统一区域并终止解释执行。
- wrapper 从统一返回区读取结果，不再依赖第一个 `ReturnInst` 推导返回槽。
- 支持多个提前失败路径和多个正常返回路径。

void、整数、指针和现有支持的浮点返回类型必须保持 ABI 正确。EH、`musttail`、`callbr` 等现有不支持情况继续明确拒绝。

### 7.2 严格覆盖

为 VM planning 增加敏感候选标记：

- 普通 VM 候选可按现有策略跳过。
- 敏感候选在 `strict=1` 下不得因预算、概率、函数大小或非致命启发式静默跳过。
- 真正不支持的 IR 必须生成可操作的诊断。

### 7.3 调用保护

敏感区域内的外部调用通过 VM callee table 和通用 call handler 执行，使原生 wrapper 不保留目标 API 的直接 `BL`。

该设计不宣称删除全局动态符号。若其他代码仍调用同一 API，符号可能继续存在，但不能从重定位直接建立到敏感决策区域的稳定调用链。

动态名称解析作为后续可选增强，不纳入第一阶段默认实现，避免引入 Android linker namespace、符号版本和 `dlsym` 新定位点。

### 7.4 Wrapper 结构变体

当前 wrapper 的寄存器区和 engine context 形态较稳定。至少增加以下可按 seed 选择的结构族：

- 分离寄存器数组与单一随机布局 byte arena。
- wrapper 内联预装载与私有 helper 预装载。
- 多种 engine context 字段顺序或调用 ABI 布局。

同 seed 必须确定性复现，不同 seed 应改变结构族、入口指令类别和到首次间接调用的距离。

## 8. Zone Runtime 接入

Zone 侧将以下逻辑收拢成完整敏感决策区域：

- capability 响应解析后的签名验证；
- `request_hash`、`device_id_hash`、`key_id`、operation、policy 和时间窗口绑定；
- nonce 或状态链比较；
- 最终 accept/reject 动作。

原则：

- 不只给 `verifySignature()` 加保护；必须保护消费其结果并决定授权的函数。
- capability 校验失败时不能产生可供业务使用的 VM dispatch 输入。
- `SSL_connect` 所在网络函数不是授权真值来源。即使攻击者由 TLS 调用定位网络层，也不能直接得到最终授权决策边界。
- Zone 配置、卡密和服务端密钥不进入编译器代码。

## 9. 后链接 ELF 加固

### 9.1 链接流程

最终链接包装器执行：

1. 调用原始 NDK clang/lld 生成 ELF。
2. 解析 ELF program headers 和必要的 section headers。
3. 分类所有连续零区。
4. 执行 `PF_X` 空洞策略。
5. 计算受保护范围和 program header 元数据摘要。
6. 将摘要和范围描述写入专用 manifest。
7. 重新读取并验证最终文件。

后链接工具失败时不得保留看似成功的最终产物。

### 9.2 零区分类

每个不小于阈值的零区分类为：

- 不属于任何 `PT_LOAD`；
- 位于 `PF_X PT_LOAD` 但不属于任何文件支持的 section；
- 位于 `PF_X PT_LOAD` 的某个 section 内；
- 位于非执行 `PT_LOAD`。

运行时可执行性以 `PT_LOAD.p_flags & PF_X` 为准，不能仅依据 section 的 `SHF_EXECINSTR`。当前 demo 中 `.rodata` 的约 1031 字节零区位于可执行 `PT_LOAD`，必须被检测。

### 9.3 默认策略

- 非白名单 `PF_X` 零区长度不小于 512 字节时构建失败。
- section 所属零区和无 section 归属零区分别报告。
- 白名单只允许显式命名、用途明确的保留 section，不接受任意偏移白名单。
- 优先调整链接布局，使普通只读数据进入非执行段；不以随机填充掩盖布局问题。

### 9.4 完整性 Manifest

manifest 至少绑定：

- `PF_X PT_LOAD` 的文件支持字节范围；
- 相关 program header 字段；
- VM bytecode 所在范围；
- manifest 版本、哈希算法和范围数量。

manifest 自身使用规范化零值参与摘要，随后由后链接工具回填。运行时根据加载基址验证映射范围，失败时不返回可利用的布尔值，而是破坏 VM 执行所需状态并 fail-closed。

文件尾追加数据和所有非 `PT_LOAD` 字节不属于内存自校验范围，应由 APK/包签名或单独的全文件验证负责。

## 10. 工具与边界

新增独立 ELF 工具，优先使用 LLVM Object/ELF API，而不是手写不完整解析器。该工具负责审计和 patch，不直接修改 LLD。

IR Pass 只负责：

- 产生 runtime checker 和 manifest 占位符；
- 标记需要保留的 section；
- 提供受保护对象 metadata。

后链接工具负责：

- 最终文件偏移和虚拟地址映射；
- `PT_LOAD` 权限判断；
- 空洞审计；
- 摘要计算和 manifest 回填。

## 11. 测试设计

### 11.1 编译期测试

添加 AArch64 fixture：

- `strcmp(nonce, expected) != 0`，覆盖相等、首字节错误、末字节错误、空值和长值。
- 验签函数返回 `i1`，覆盖成功、失败和畸形输入。
- 单返回与多个提前返回版本。
- 敏感结果在未保护调用者中判断的错误版本。

检查：

- `strict=1` 对边界错误和不支持 IR 报错。
- 成功产物中敏感区域没有目标 API 的直接 `BL`。
- 原生 wrapper 中没有由敏感结果驱动的直接条件失败分支。
- 同 seed 可复现，不同 seed 产生多个 wrapper 结构族。

### 11.2 ELF 测试

构造 511、512、513 字节零区，分别覆盖：

- `PT_LOAD` 外；
- `PF_X PT_LOAD` 无 section 归属区域；
- `PF_X PT_LOAD` 内 `.rodata`；
- 非执行 `PT_LOAD`。

同时覆盖无 section headers 的 stripped ELF、PIE、共享库和不同的 `p_vaddr - p_offset`。

### 11.3 篡改测试

分别修改：

- `.text`；
- `PF_X` padding；
- 可执行映射的 `.rodata`；
- VM bytecode；
- program header；
- manifest；
- 文件尾追加数据。

测试必须明确由 runtime integrity 或包级完整性中的哪一层检测，不能把未覆盖区域报告为已保护。

### 11.4 五条攻击路径回归

提供独立攻击脚本，以失败条件衡量加固效果：

1. PLT/rela 映射不能直接给出敏感决策调用点。
2. 从验签 API 不能恢复原生结果分支和稳定函数序言链。
3. 比较调用后不存在直接连接授权失败块的 `cbnz` 模式。
4. TLS 建连函数交叉引用不能直接确定最终授权决策函数。
5. `PF_X PT_LOAD` 中不存在未允许的 512 字节以上零洞。

## 12. 实施阶段

建议按以下阶段交付，每阶段独立构建和测试：

1. 建立攻击基线脚本，证明当前产物五条路径的实际命中情况。
2. 修复 VM 多返回并增加 strict candidate 语义。
3. 实现 SensitiveDecision 验证、规范化和提交后检查。
4. 在 Zone runtime 收拢敏感决策边界并接入注解。
5. 实现 ELF audit/manifest 工具和最终链接包装器集成。
6. 增加 wrapper 结构族与跨 seed 测试。
7. 运行 demo 端到端授权、篡改和攻击回归测试。

## 13. 风险与约束

- VM、LTO、CFI、BTI/PAC、sanitizer 和异常处理可能存在兼容性边界，strict 诊断必须准确。
- 将大范围网络或 JSON 代码整体 VM 化会造成显著体积和性能成本；Zone 应提取紧凑的最终决策函数，而非虚拟化整个 SDK。
- ELF 自校验代码本身可被补丁绕过，因此校验结果应参与 VM 状态和云值派生，避免形成单一 `if (integrity_failed)` 补丁点。
- 动态符号存在不等于敏感调用点暴露。测试必须分析符号到决策区域的数据流，而不是简单要求全局无符号。
- 完整性 manifest 在签名之前生成；APK 打包、压缩或签名流程不得再次修改 ELF 内容。
