# xollvm max VM 架构加固设计

日期：2026-10-13

## 1. 已确认的目标

用户要求加固 xollvm 编译器自身：扩充现有 56 个逻辑 opcode，降低 handler 表和 engine 地址的静态定位线索，以白盒 AES 替换 VM 的扩展密钥与 XOR mask 存储，并补齐 CALL 多态、嵌套 VM、ISA 随机化和有效配置报告。

用户已选择：新增重型保护集中进入 `preset=max`，强度优先，接受明显的体积、编译时间和运行开销增加。本设计尚须用户审阅，之后才编写实施计划和修改产品代码。

交付对象是 xollvm 工具链。使用独立无凭据 fixture 验证；demo 不是本阶段的实现目标。现有未提交的 AES 辅助函数局部化修复和测试必须保留。

## 2. 当前源码依据

- `VMPass_ISA.h`：`OP_COUNT=0x38`，逻辑 opcode 为 56 个；物理 opcode 使用单字节编码。存在 4 个复合 opcode 和最多 32 个诱饵。
- `VMPass_Emitter.cpp`：两阶段计算大小与发射；融合结果、跳转偏移、需求收集和 verifier 必须保持一致。
- `VMPass_Dispatch.cpp`：静态表含原始 block address 和 engine 指针；加密 dispatch map 只保护索引映射，不保护表中的目标地址。
- `VMPass_Wrapper.cpp`：从表中固定的 engine 槽加载入口；lazy context 含完整 176 字节 AES 扩展密钥。
- `VMPass_Crypto.cpp`：masked round key 和 mask 同在模块中，运行时还原扩展密钥。
- `SharedState::CallSW` 每个返回类别只有一份状态。后续 CALL 变体覆盖前一份，因此当前所有 CALL 变体槽被固定到最后一个变体。
- `ensureCallFTyCases()` 后续扩展类型时使用独立简化 byte loader，明确拒绝 StrongBC，且不支持 lazy AES 路径。统一解码上下文是 CALL 修复的前置工作。
- `VMPass_Nested.cpp`：按模块共享 helper，内层强制 `hardened=false`；`nestedVMHardened` 未实际实现。
- `VMPass.cpp`：max 设置 bindAntiDebug，但 VM antiDebug 默认关闭，归一化后绑定失效。cloudDispatch 和 wrapperFamily=auto 不由 max 自动开启。

## 3. 方案选择

### 3.1 opcode 扩展

选择增加有明确输入输出语义、真实发射路径的指令。拒绝仅扩展枚举或添加未执行的同义编号作为达标方式。

### 3.2 目标地址保护

有三种可行方向：

1. 运行时初始化明文地址表后加密：实现简单，但原始地址引用和初始化路径仍在最终文件中，不满足本次静态表加固目标。
2. 无表分发：可能被 LLVM/AArch64 后端再次生成跳转表，且改变 threaded dispatch 和变体组织；本阶段不选择。
3. 链接后编码相对地址：先让 LLVM/LLD 正常解析 block address，最终文件由 hardener 改写为编码的相对目标；目标平台可验证、可与 ELF seal 共用。选择此方向。

第三种方案意味着新 max 产物需要匹配的链接后 hardener。工具链必须提供正式链接入口和可机器识别的待处理标记；不能宣称仅运行 LLVM pass 就已完成最终地址保护。

### 3.3 白盒 AES

选择密钥融合的 AES-128 正向轮查表、内部编码和编码 XOR 网络。CTR 只需要 AES 加密方向。拒绝把现有 round key 分片、增加 XOR 层或换成一张 masked key 表称为白盒。

白盒减少直接提取标准扩展密钥的便利，不承诺抵抗所有白盒分析、DCA 或密钥提取攻击；验收不把功能测试解释为安全强度证明。

## 4. ISA v2：56 扩展为 96 个逻辑 opcode

新增 40 个，原 56 个语义保留：

| 指令组 | 新增数量 | 语义 |
| --- | ---: | --- |
| i32/i64 立即数形式 | 18 | 每宽度 ADDI、SUBI、MULI、ANDI、ORI、XORI、SHLI、LSHRI、ASHRI 共 9 个 |
| i64 复合形式 | 4 | MULADD64、SHLADD64、CMPSEL64、ANDCMPZ64；比较结果仍进入 i32 布尔槽 |
| i32/i64 三操作数融合 | 12 | 每宽度 XORADD、ANDADD、ORADD、ADDXOR、SUBXOR、MULXOR 共 6 个 |
| 地址计算与访存融合 | 6 | GEP_LOAD8/16/32/64、GEP_STORE32/64 |
| 合计 | 40 | 新 `OP_COUNT=0x60` |

约束：

- 指令编码仍用单字节，真实 opcode 与诱饵域保持不相交；所有界限根据 OP_COUNT 计算。
- 立即数编码使用对应宽度，位移量不做会改变 LLVM 语义的隐式取模。原程序未定义/poison 输入不用于差分测试的正确性断言。
- 融合只作用于已支持类型与合法依赖图。首版限定同一基本块，前驱只有唯一有效使用，不跨副作用、异常、volatile、atomic 或可能改变访存顺序的指令。
- 访存融合只处理 emitter 已支持的 GEP 形式，保留宽度、符号扩展、对齐及原内存访问顺序；无法证明等价时保留原指令组合。
- 不在未经允许的条件下重排浮点计算；本次不新增浮点算术融合。
- Size pass、emit pass 共用融合描述，bytecode verifier 校验指令长度、寄存器文件、立即数、branch boundary、需求集合。
- `extendedISA` 控制新发射路径，max 默认开启。关闭时沿用原发射选择；引擎需求裁剪避免 96 个 handler 全部无条件生成。
- ISA version 升至 2，并纳入 engine key、报告和测试。已有编译产物不与新版 bytecode/interpreter 混用。

## 5. 编码的 handler 目标与独立 engine 入口

### 5.1 编译和链接阶段

- `encodedTargets` 在 max 开启；medium/high 保持现有配置行为。
- 为目标槽生成专用待封装 section 和版本化描述符。描述符记录槽宽度、角色、anchor、目标范围、编码模式及稳定 seed 派生信息。
- 待封装产物可包含用于链接的原始地址；最终产物不能留下等价原始地址表或用于恢复它的重复描述符。
- engine 入口独立于 handler 表保存；不再占用固定 `OP_COUNT*K` 槽。
- handler、索引映射、诱饵、engine 入口布局按 seed 变化，runtime 解码接口不依赖最终 ELF section 名称。

### 5.2 最终封装与运行

- hardener 读取最终 ELF 地址，将目标转换成相对本地 anchor 的差值，用按槽派生的可逆编码封装。runtime 每次加载时解码；不构造长寿命完整明文表。
- 地址相对化保证 ASLR/load bias 下运行正确。64 位取模算术、负差值、little-endian 写入由明确定义的格式覆盖。
- 选择具体可逆编码时先执行 LLVM/LLD/AArch64 探针，检验 relocation、PIE、独立对象链接、GC sections 和相对地址的正确性。
- hardener 只移除完全属于待封装槽的 relocation，并校验没有其他代码依赖这些 relocation；对描述符损坏、布局不符或未知重定位拒绝处理。
- 检查动态加载器不会在启动时将槽写回原始指针。清除仅用于封装的明文目标载荷；从可重定位对象到最终 ELF 的正常外部调用 relocation 不属于该删除范围。
- 中央 dispatch 和 threaded tail 共用目标加载/解码实现，包含所有 CALL 变体和诱饵。
- 有效云 offset 原有语义保持；错误 offset 不变成允许任意越界读取的实现，非法槽进入 trap。cloudDispatch 仍须显式配置，max 不隐式依赖网络。

### 5.3 拒绝未封装产物

- 默认待处理状态使受保护入口在解码前 fail closed；hardener 完成目标封装后才能置为已处理。
- 正式链接流程：link → 封装目标 → audit → seal → verify → 原子推广。
- 仅有 encodedTargets、没有 sensitive manifest 的 ELF 也必须支持该流程；工具行为不能把 absence of manifest 当成 absence of targets。
- 重复封装不得再次编码同一槽；seal 重跑和 verify 的行为必须可重复、可解释。
- 对缺少配套后处理的构建给出明确错误/报告，不静默退回明文表。

验收对象是 stripped/unstripped 最终 AArch64 ELF 的数据与 relocation，不是 IR 中不存在某个名字。符号及正常代码引用仍可能定位 engine；目标是移除集中明文表线索，而非声称所有代码地址都不可发现。

## 6. 白盒 AES-128 CTR 后端

### 6.1 编译期生成

- `whiteboxAES` 在 max 开启，需要 encBytecode；与 bytecode 的现有 per-position Layer-1 保护组合。
- 编译期保留标准 AES 实现用于加密 bytecode和已知答案参照。目标文件不保存标准 AES key/expanded key 的配对恢复材料。
- 构建密钥融合的前 9 轮 8-bit 输入/32-bit 输出表及末轮字节表，覆盖 SubBytes、ShiftRows、MixColumns 和轮密钥注入。
- 对内部字节/半字节连接生成 seed 派生双射编码，通过编码的两输入 XOR 网络组合列贡献。表边界消除编码，不暴露标准轮密钥数组。
- 每个白盒实例与 bytecode key 对应。首版不为省体积把不同函数的加密 key 强制统一；允许相同 key 实例在相同模块中去重，禁止不同 key/config 错误共享。
- 基础轮表约 144 KiB/实例，实际体积还包含末轮、编码 XOR 网络和布局信息，必须测量并报告。按需生成、局部符号、独立 section 与链接 GC 控制无用实例。

### 6.2 运行期接口

- 将 round-key 参数接口替换为白盒描述符/表上下文接口：输入 16-byte counter block，输出 16-byte keystream。
- 保持现有 nonce 与 counter 字节序、16-byte block 缓存和随机 IP 读取语义。
- whitebox lazy context 仅包含 nonce、cached block、keystream window 和实例上下文，不包含 176-byte round-key 区。
- bulk 和 lazy 两种 bytecode解密路径均支持；max 使用 lazy。普通非白盒后端保留，但显式请求 whitebox 的函数不能因失败偷偷落回普通 AES。
- 共享引擎接收对应函数的白盒实例上下文，engine key 纳入后端类型，避免与普通 AES 不同 ABI 混用。
- per-call 可变缓存不共享；表只读；并发、递归、重复调用不依赖全局可变 AES 状态。
- 仅 VM 加密后端在本阶段切换白盒；StringEncryption 独立加密实现可能仍携带自己的 key 材料，检测必须按保护对象区分。

## 7. CALL 多态与统一解码

- `CallSW` 改为每个返回类别、每个变体分别记录构建上下文。
- 所有可达 CALL 变体均接收完整需求类型集合。取消将 K 个表槽固定到最后一个变体的 workaround。
- 初始构建和增量添加类型共用参数/返回转换实现；使用当前 engine 上下文，不读取另一个 VMImpl 中的 Eff*。
- 参数读取共用 StrongBC、lazy AES/白盒、register-index decode 和 register encryption 路径，删除简化 loader 的 StrongBC fatal 限制。
- 校验实际支持的精确函数类型、calling convention 和参数数量。不借本阶段掩盖未知 ABI；不支持的类型明确拒绝。
- demand freeze/commit 应先冻结类型需求，再生成 handler；增量 API 仍需正确，以覆盖嵌套及现有使用路径。

## 8. 嵌套 VM 隔离与内层加固

- helper 名称/所有权按有效 outer engine key 隔离，不能仅以固定模块符号复用不同配置下的 helper。
- inner engine key 区分层级、owner、加密/dispatch/ISA 配置；不强制所有内层落到 pool-0 单一实例。
- 固定深度 2；InnerCfg.nestedVM=false，避免递归虚拟化。
- 修复 helper wrapper 的 dominance 失效，支持 nestedVMHardened 的真实执行路径，并在 max 开启。
- 内层不重复创建反调试监控线程，复用外层有效检测状态和响应绑定。
- helper 虚拟化失败不能只输出 verbose 并继续声称成功。max 显式需要内层加固时给出可观察失败；strict/no-skips 直接中止。普通可选路径的失败状态写入报告。

## 9. ISA 布局变化与有效配置

- `operandLayout` 在 max 开启。按 engine key/seed 为 opcode 选择有限、可验证的操作数字段排列；emitter、size、verifier 和 handler 共用同一 layout 描述。
- 先保持总指令长度不变，不引入无法校验的随机变长 padding。
- randISA 补齐 Cast64、FCast、Select selector。改掉依赖逻辑枚举范围排序的 handler 判断，避免编码置换破坏 ext/trunc 语义。
- `wrapperFamily=auto` 在 max 开启，保留显式覆盖。
- 反调试绑定改为依据合并后的有效 AntiDebugConfig，而非只看旧 VM antiDebug。允许实际开启的 antidebug 配置与白盒解码上下文绑定；无需第二套 legacy timing detector。
- max 不隐式开启有误报风险的检测，也不启用 root/network 要求。没有有效检测来源时报告 bindAntiDebug 未生效及原因，而不是悄悄清零。
- 报告包括：请求配置、有效配置、依赖关闭原因、实际 opcode/变体数量、engine/helper owner、白盒实例数量、需链接后处理标记及成功/失败阶段。
- preset 先展开、显式参数覆盖的现有规则保留；engine key 纳入所有影响字节码、handler、runtime ABI 的新增字段。

## 10. 验收标准

### 功能与构建

1. 新 ISA 有 96 个真实逻辑 opcode，新增 40 个均有可执行、可发射的 witness，非仅枚举覆盖。
2. 定义良好的 i32/i64 边界、随机输入、控制流、负偏移、访存别名、立即数与融合回退差分结果与原函数一致。
3. verifier 拒绝截断指令、错误 slot/domain/layout、无效 branch target 和不足的需求集合。
4. FIPS AES-128 已知答案、CTR 的 0/1/15/16/17-byte 边界、多 block、随机 block seek、并发调用均通过。
5. AArch64 PIE 经封装后在 ASLR、-O0/-O2、strip、GC sections、独立对象与静态库链接场景正常运行；未封装入口拒绝执行。
6. CALL 5 类返回值与多个类型、每个变体、共享 engine 后注册类型、StrongBC+lazy+白盒组合均正确。
7. nested+max 内外层 owner/config 隔离、depth 2、多返回、LLVM verifier、失败诊断均通过。
8. opt、clang、hardener 正式构建和安装组件验证通过；测试产物静态链接 libc++，兼容 Termux/Android 终端。

### 抗分析结构与测量

9. 最终 ELF 没有目标 section 中原始 handler/engine 指针列表，没有能被动态 relocation 重新恢复的等价槽；engine 入口不占固定 handler 槽。
10. 白盒保护函数不存在 masked round-key+mask 配对恢复材料，runtime context 不产生完整标准 expanded key；允许 keystream block 为执行而短暂出现。
11. 同 seed 结果可复现，不同 seed 至少改变实际目标布局、白盒内部编码、操作数字段布局和独立引擎结构，不能只检查名称。
12. 在相同 fixture 与 seeds 下记录旧/new max 的编译耗时、峰值内存、.text/.rodata/relocation 体积、运行耗时。用户未设硬性倍率上限，仍须报告实际开销并避免无限增长。
13. AArch64 攻击 fixture 不向攻击者提供原始 key、明文字节码或中间 IR；区分攻击成功、超时、不支持和攻击工具故障，不以超时/故障直接宣称安全。

已有 290 Python 和 62 C++ 测试是本阶段基线；新增测试先失败后实现。重型 fixture 单独设置明确资源/时间预算，现有快速测试保持可运行。完成条件为上述功能、结构、工具链检查通过且成本测量报告齐全；无专业实测的抗提取能力不作保证。

## 11. 实施依赖顺序

1. 统一 CALL/byte-load 上下文并修复多态，补当前组合回归。
2. 建立 ISA v2/layout 描述，分组扩展 40 个真实 opcode。
3. 目标编码的最小 LLVM/LLD/AArch64 探针，然后接入 hardener 和正式链接封装流程。
4. 白盒 AES 已知答案验证，再接入 VM bulk/lazy 和 per-call context。
5. 嵌套 helper owner 隔离、内层 hardening 和有效反调试绑定。
6. max 展开、engine key/报告、全组合验证、最终 ELF 抗分析检查和开销测量。

任何阶段发现后端约束使选定表示不可行，先更新设计并说明原因，不能通过保留明文表、回退普通 AES 或虚增 opcode 数量宣称达标。
