/*===----------------------------------------------------------------------===*\
|*                                                                            *|
|*  obf_annotations.h  --  LLVM 混淆器注解速查表                              *|
|*                                                                            *|
|*  将此头文件放入项目，并使用 OBF() 宏或预设为函数添加注解，从而驱动 LLVM    *|
|*  混淆 Pass。此文件是参考头文件：Pass 读取的每个参数，其可接受范围和默认值  *|
|*  都记录在下方。                                                            *|
|*                                                                            *|
|*  此文件可以独立使用，没有外部依赖，只定义宏；在非 Clang 编译器下会展开为    *|
|*  空内容，因为这些注解是 Clang 扩展。将它随项目发布并 include 即可。          *|
|*                                                                            *|
|*  快速开始：                                                                *|
|*                                                                            *|
|*      #include "obf_annotations.h"                                          *|
|*                                                                            *|
|*      OBF("vm(hardened=1), mba, bcf")                                       *|
|*      int secret_check(const char *pw) { ... }                             *|
|*                                                                            *|
|*      OBF_MAX                                                               *|
|*      int license_verify(void) { ... }                                     *|
|*                                                                            *|
|*  然后使用启用混淆器的 Clang 工具链编译。只有带有注解的函数会被转换，其余    *|
|*  内容保持不变。                                                            *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifndef OBF_ANNOTATIONS_H
#define OBF_ANNOTATIONS_H

/*
 * Zone 卡密授权：
 * OBF("zoneauth(capability=main, policy=fail_closed), vm(...)")
 *
 * 目标必须将 zone_runtime/zone_wrapper.cpp、官方 Zone 静态 SDK 及其所需的
 * 静态依赖一起链接。卡密在运行时输入，不会存储在注解或编译器选项中。
 */

/*===----------------------------------------------------------------------===*\
|*  核心宏                                                                    *|
\*===----------------------------------------------------------------------===*/

/*
 * OBF(spec)
 *   为函数附加混淆配置。`spec` 必须是包含逗号分隔 Pass 列表的字符串字面量，
 *   例如 OBF("mba, bcf(prob=80)")。"obf: " 前缀会自动添加。
 *
 * OBF_FN(spec)
 *   与 OBF() 相同，但还会为函数添加 `noinline`。推荐用于小型或热点函数：
 *   否则内联器可能把函数体复制到没有注解的调用者中，破坏按函数混淆的边界。
 *
 * 在非 Clang 编译器下，两个宏都会展开为空，因此同一份源码仍可使用 gcc/msvc
 * 编译，只是不会执行混淆。
 */
#if defined(__clang__)
#  define OBF(spec)    __attribute__((annotate("obf: " spec)))
#  define OBF_FN(spec) __attribute__((annotate("obf: " spec), noinline))
#else
#  define OBF(spec)
#  define OBF_FN(spec)
#endif

/*===----------------------------------------------------------------------===*\
|*  内置预设                                                                    *|
|*                                                                            *|
|*  这是一个大致的强度/体积成本梯度。选择满足威胁模型的最低级别，因为每提升一档，*|
|*  都会增加代码体积并降低函数运行速度。                                    *|
\*===----------------------------------------------------------------------===*/

/* 廉价的算术/控制流噪声，几乎不增加体积，用于阻止简单阅读。 */
#define OBF_MINIMAL     OBF("substitution, mba(prob=40)")

/* 日常加固：MBA + 虚假控制流 + 基本块切分。 */
#define OBF_BALANCED    OBF("mba, bcf, split")

/* 较强的静态分析对抗：增加控制流扁平化、字符串加密、反反编译干扰结构和
 * 反优化保护，降低 -O2 还原混淆结构的可能性。 */
#define OBF_AGGRESSIVE  OBF("flattening, mba, bcf, split, strenc, adec, shield")

/* 最大强度：使用最高级别的字节码 VM（preset=max，每个函数拥有独立的变形引擎），
 * 并叠加静态混淆 Pass。体积最大、速度最慢，仅用于确实需要保护的少数函数，
 * 例如授权检查或信任根检查。 */
#define OBF_MAX         OBF("vm(preset=max), mba, bcf, flattening, strenc, adec, shield")

/* 使用各项技术默认参数的快捷宏。 */
#define OBF_VM          OBF("vm")
#define OBF_VM_HARDENED OBF("vm(hardened=1)")
#define OBF_STRINGS     OBF("strenc")
#define OBF_FLATTEN     OBF("flattening")
#define OBF_CONSTENC    OBF("constenc")
#define OBF_FMERGE      OBF("fmerge")

/*===----------------------------------------------------------------------===*\
|*  配置语法                                                                  *|
|*                                                                            *|
|*    "pass1, pass2(k=v), pass3(k1=v1, k2=v2)"                                *|
|*                                                                            *|
|*  - Pass 列表使用逗号分隔，括号 (...) 内的逗号不会造成歧义。               *|
|*  - 参数格式为 key=value；布尔值支持裸值、"带引号的值"、0/1 以及           *|
|*    true/false/yes/no/on/off。                                               *|
|*  - 未知 Pass 名称会被警告并拒绝，未知参数会被忽略。Pass 名称不区分大小写。 *|
|*  - 同一函数的多个注解会合并，后出现的参数优先。                           *|
|*  - 顶层预算参数可以作为任意 Pass 的参数出现：                             *|
|*        budget=N        此函数的 IR 膨胀倍数                                   *|
|*        budgetMax=N     此函数的绝对指令数上限                               *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

/*===----------------------------------------------------------------------===*\
|*  Pass 参考（规范名称 — 别名 — 参数 [范围]（默认值））                       *|
\*===----------------------------------------------------------------------===*/

/*----------------------------------------------------------------------------
 * mba                                                    混合布尔算术
 *   将算术/位运算改写为等价的 MBA 恒等式。
 *
 *   preset  [light|medium|high|max]  参数组合，在显式参数之前应用
 *           light  = 基本改写；medium = 增加噪声槽（近似默认值）；
 *           high   = 无内存 SLE 零值（推荐）；max = 叠加全部能力
 *   prob            [0-100]  (75)   被改写的符合条件位置的百分比
 *   depth|maxDepth  [1-10]   (?)    递归改写深度
 *   maxSites        [1-5000]        改写位置上限
 *   termsMin|linearTermsMin  [1-64]     线性组合项数下限
 *   termsMax|linearTermsMax  [>=min,<=96] 线性组合项数上限
 *   enableNonLinear [0/1]           允许非线性恒等式
 *   nonLinearWeight|nonLinearProb [0-100]  非线性混合权重
 *   enableLayered   [0/1]           分层/窗口改写
 *   layeredWindow   [0-256]         分层 Pass 的窗口大小
 *   layeredBudget   [0-32]          分层改写预算
 *   -- 无内存非线性零值（可通过 -O2，并抵抗 SMT 和线性 MBA） --
 *   inputZero        [0/1]          从输入推导的非线性提升零值
 *   inputZeroReplace [0/1]          放弃噪声槽膨胀，仅使用输入零值
 *   inputZeroCount   [1-8]          每个位置的输入派生形式数量
 *   inputZeroWeight  [0-100]        每个位置注入输入零值的概率百分比
 *   sle              [0/1]          SLE 池非线性零值（每种形式具有多样性）
 *   sleReplace       [0/1]          放弃噪声槽膨胀，仅使用 SLE 零值
 *   sleCount         [1-8]          每个位置的 SLE 形式数量
 *   sleWeight        [0-100]        每个位置注入 SLE 零值的概率百分比
 *      SLE 池从 $XOLLVM_SLE_POOL 加载（重新生成：utils/mba_sle_gen.py），
 *      未设置时使用内置默认值。推荐：mba(sle=1,sleReplace=1,sleCount=1)
 *
 *   e.g.  OBF("mba(prob=90, depth=3, enableNonLinear=1)")
 *   e.g.  OBF("mba(sle=1, sleReplace=1, sleCount=1)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * constenc                                               常量加密
 *   加密数值常量（整数和浮点数），每个常量都在运行时通过解密序列重建。
 *   它最先运行，在其他 Pass 修改控制流之前处理常量。
 *
 *   prob      [0-100]     (60)   被加密的符合条件常量的百分比
 *   maxSites  [0-100000]  (200)  每个函数的加密位置上限
 *   minAbs                (2)    跳过绝对值小于 minAbs 的常量
 *   encInt    [0/1]       (1)    加密整数常量
 *   encFP     [0/1]       (1)    加密浮点常量
 *   wrapMBA|wrapMba [0/1] (0)    使用 MBA 包裹已物化的常量
 *
 *   e.g.  OBF("constenc(prob=80, encFP=0)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * bcf                                                    虚假控制流
 *   使用不透明谓词保护的虚假分支包裹基本块。
 *
 *   prob      [0-100]     (?)   获得虚假保护分支的基本块百分比
 *   loop      [1-10]            重复应用转换的次数
 *   maxBlocks [0-100000]        跳过基本块数量超过此值的函数
 *
 *   e.g.  OBF("bcf(prob=80, loop=2)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * split                                                  基本块切分
 *   将基本块切成更小的片段，使控制流图碎片化。
 *
 *   num  [2-10]  (?)   每个符合条件的基本块切分出的片段数量
 *
 *   e.g.  OBF("split(num=4)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * substitution                          alias: sub      指令替换
 *   用更长的等价指令序列替换简单操作。
 *
 *   loop     [1-10]        指令替换表的应用次数
 *   maxSites [0-100000]    被替换位置的上限
 *
 *   e.g.  OBF("substitution(loop=2)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * flattening                            alias: fla      控制流扁平化
 *   将控制流图重建为由分发器驱动的状态机。
 *
 *   min|minBlocks   [2-100000]  (?)   触发扁平化所需的最少基本块数
 *   max|maxBlocks   [>=min,<=200000]  可处理的最大基本块数
 *   indirect|allowIndirect  [0/1]     允许使用 indirectbr 分发
 *   hybrid          [0/1]             混合分发器模式
 *   opaque|opaqueState      [0/1]     不透明状态变量
 *   fake|fakeTransitions    [0/1]     注入虚假状态转换
 *   fakecase|fakeCases      [0-64]    虚假 switch 分支数量
 *   domain|perDispatcherDomain [0/1]  每个分发器独立的状态域
 *   ptr|stateptr|obfuscateStatePtr  [0/1]  混淆状态指针
 *   alias|aliasptr|opaqueAliasStatePtr [0/1] 使用不透明别名混淆状态指针
 *
 *   e.g.  OBF("flattening(opaque=1, fake=1, fakecase=4)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * vcall                                                  虚拟调用伪装
 *   通过合成的虚函数表转发直接调用。
 *
 *   prob        [0-100]     (?)   被伪装的调用位置百分比
 *   maxSites    [0-100000]        被伪装位置的上限
 *   opaqueNames|opaqueVTableNames [0/1] 使用不透明的虚表符号名
 *   decoys|addDecoyEntries [0/1]        添加虚表诱饵项
 *   decoyMin / decoyMax                 诱饵项数量范围
 *   varyIndex|varyIndexPerCallsite [0/1] 每个位置使用不同的分发索引
 *   indexStrength                       索引混淆强度
 *   merge|mergeVTables  [0/1]           跨函数合并虚表
 *   encTable|encryptTable [0/1]         加密虚表项，在运行时由构造器填充
 *                                       （仅非合并模式）
 *
 *   e.g.  OBF("vcall(prob=60, decoys=1)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * sdiff                                                  语义扩散
 *   将一个值的定义分散到额外的计算槽中。
 *
 *   prob     [1-100]   (?)   被扩散的符合条件值的百分比
 *   slots    [1-8]           每个值使用的扩散槽数量
 *   maxSites [1-2000]        被扩散位置的上限
 *
 *   e.g.  OBF("sdiff(slots=4)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * strenc                                                 字符串加密
 *   加密字符串字面量，由运行时存根延迟解密。这是模块级 Pass，给任意一个
 *   函数添加注解即可对整个模块启用。
 *
 *   min|minlen|minLength [1-100]  (?)  仅加密长度达到此值的字符串
 *   cipher   {chacha|aes|xor}     (aes)  密码算法族（chacha = 无表实现）
 *   aes      [0/1]                (1)   启用 AES-CTR（设置 cipher 后忽略）
 *   keysplit [0/1]                (1)   将密钥拆分到多个片段
 *
 *   e.g.  OBF("strenc(cipher=chacha, min=4)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * fmerge                  alias: -                       函数合并
 *   将多个函数合并为一个由隐藏选择器分发的函数体，消除函数边界。
 *   这是模块级 Pass，并且最先运行；为函数添加相同的 group= 标签即可将它们
 *   放入同一个合并组。
 *
 *   group=NAME               分组标签（共享该标签的函数会合并；
 *                            空字符串 -> "_auto" 池）
 *   chunk|c   [2-16]   (4)   _auto 池的分块大小（每次合并的函数数）
 *   opaque|opaqueSel [0/1](1) 混淆选择器
 *   dispatch  {switch|indirectbr}  (switch)  分发机制
 *   min|minInsts       (4)   跳过指令数低于此值的函数
 *   max|maxInsts [>=min,<=100000] (2000)  跳过指令数高于此值的函数
 *   stripDbg  [0/1]    (1)   从合并后的函数体移除调试信息
 *   thunk|thunkAddrTaken [0/1] (0)  通过 thunk 合并取地址或外部函数
 *   dissim|dissimilar    [0/1] (1)  _auto 池按最大形状差异进行分组
 *   launder|launderSel   [0/1] (0)  从全局变量加载调用位置选择器
 *                                   （阻止去虚拟化）
 *
 *   e.g.  OBF("fmerge(group=checks, dispatch=indirectbr, launder=1)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * zoneauth（已移除）
 *
 *   Zone 授权功能已从编译器移除，运行时库已分离到 demo 项目独立维护。
 *   编译器只保留纯静态混淆 Pass。如需 Zone 授权，请在最终项目中
 *   自行集成 zone_runtime 源码。
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * 云值驱动 VM dispatch（cloudDispatch）端到端说明
 *
 *   作用：让每个被虚拟化函数的 handler 分发依赖一个云端临时值 V。V 缺失、
 *   过期或被篡改时，dispatch 偏移非 0，索引越界/命中陷阱自然崩溃；本地没有
 *   任何 "if (有效)/if (未过期)" 判断可被 NOP。
 *
 *   编译期（客户端）：
 *     vm(cloudDispatch=1) 让 VM 在两处 dispatch（中央与 threaded）注入对
 *     __zone_get_dispatch_offset() 的调用；该符号由 zone_runtime 的
 *     cloud_value_manager 提供。客户端编译期只需 VM_DISPATCH_OFFSET_MASK，
 *     不需要预知运行时 V。默认关闭时输出与非云构建一致。
 *
 *   运行时（客户端）：
 *     cloud_value_manager 首次 dispatch 时同步拉取当前 window 的 V（避免首跑
 *     用全零 V 必崩），之后按 VM_DISPATCH_PREFETCH_SEC 异步预取；按
 *     window_id 分桶，用 HMAC-SHA256(V, window_le64) 取低 VM_DISPATCH_OFFSET_MASK
 *     位作为偏移。V 通过 zone_wrapper 的既有登录/租约/capability 线路取得。
 *
 *   云端：
 *     持有固定密钥 k，为每个 window 搜索一个 V 使 HMAC(V, window) & MASK == 0，
 *     随 capability 响应下发 dispatch_v（32B base64）与 window_id。
 *     参考实现 zone_runtime/cloud/capability_v1.js。
 *
 *   约定（两端必须一致）：
 *     VM_DISPATCH_OFFSET_MASK（客户端 cloud_value_manager.h）== 云端
 *     dispatchOffsetMask。12-bit(0xFFF) 云端约 2^12 次 HMAC（毫秒级）；
 *     位宽越大越安全但云端搜索越贵，过大会超时。
 *
 *   排错：
 *     编译期调试打印默认关闭。仅本地排错时，链接调试版 zone SDK
 *     （ndk-build XOLLVM_ZONE_DEBUG_PKT=1）可打印收发数据包（含明文请求/
 *     响应），发布构建绝不包含这些代码。
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * aes_stub                                               AES 运行时存根
 *   链接共享的 AES-CTR 运行时存根。这是模块级能力，通常在 strenc/vm 需要
 *   AES 时自动引入，很少需要单独添加注解。
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * adec                    alias: antidecompiler          反反编译
 *   注入干扰反汇编器和反编译器的 gadget。
 *
 *   prob      [1-100]   (?)   每项技术的基础概率
 *   maxSites  [1-500]         gadget 位置上限
 *   strength  [0-3]           全局 gadget 强度
 *
 *   技术开关（0/1）——完整名称 / 简写：
 *     indirectBr / ibr          asmAntiDisasm / asm    deadCodeDecoys / decoy
 *     aliasConfusion / alias    fakeLoop / loop        rdtscStretch / rdtsc
 *     constLaunder / clndr      stackPollution         callObfuscation
 *
 *   各技术概率覆盖（[1-100]，或 -1 表示使用基础概率）：
 *     asmProb ibrProb decoyProb callProb aliasProb
 *     fakeLoopProb rdtscProb constLaunderProb
 *   各技术强度（[0-3]，或 -1）：decoyStrength、stackStrength
 *
 *   过滤器 / 输入：
 *     techniques="a,b"   技术名称白名单
 *     categories="a,b"   gadget 类别过滤器
 *     gadgets="path.json" 外部 gadget 文件
 *     asmInline="..."    使用 ';' 分隔的原始汇编 gadget 内容
 *
 *   e.g.  OBF("adec(prob=50, ibr=1, decoy=1, strength=2)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * antidebug                                              反调试检测
 *   在函数入口执行反调试检测；检测到异常时记录响应状态，并可让函数返回
 *   对应返回类型的零值。所有检测器、dynamic、rootRequired 默认均为 0。
 *   dynamic 按有效配置复用模块内线程和响应状态；不同配置独立，异常锁存。
 *
 *   tracerPid     [0/1]       检测 /proc/self/status 中的 TracerPid
 *   ptrace        [0/1]       每线程首次入口执行 PTRACE_TRACEME，复用结果
 *   timing        [0/1]       检测运行时间异常
 *   maps          [0/1]       检查 /proc/self/maps 中明确的调试器名称
 *   integrity     [0/1]       与 vm 组合时启用字节码完整性构造函数
 *   debuggerProcess [0/1]    枚举 /proc/<pid>/comm 检查工具进程（需 root）
 *   injection     [0/1]       maps 中 Frida/Xposed/Substrate/Riru/LSPosed 特征
 *   debugPorts    [0/1]       本机 IPv4 23946/23947/27042，单次等待至多 20 ms
 *   vpn           [0/1]       /proc/net/dev 中 tun/ppp/pptp/ipsec 加编号接口
 *   proxy         [0/1]       大小写 http_proxy/https_proxy/all_proxy 环境变量
 *   iptables      [0/1]       只读 nat/filter/mangle 的 REDIRECT/本机 DNAT（需 root）
 *   selinux       [0/1]       /sys/fs/selinux/enforce：0 命中，1 正常
 *   rootRequired  [0/1]       严格权限和读取策略；本身不启用任何检测器
 *   dynamic       [0/1]       启用动态监控线程
 *   interval      [50-60000] (1000)  动态检测间隔，单位毫秒
 *   threshold     [1-...] (1000000)  timing 阈值，单位纳秒
 *   responseCorrupt [0/1] (1) 检测到异常时让函数返回安全失败值
 *
 *   新增七项及 rootRequired 仅对 Android/AArch64 生效。rootRequired=0 跳过
 *   debuggerProcess/iptables，其余探测读取失败时跳过。rootRequired=1 先检查
 *   geteuid()==0；权限不足直接触发响应，启用项读取/解析失败也触发响应。
 *   proxy 不读取 Android 系统代理设置；VPN/工具名/端口均为特征检测。
 *   dynamic 在入口与后台检测；线程退出用停止标志和 join 回收。ptrace 仅在
 *   入口执行，integrity 仅在 VM 初始化执行；后台需配合其他轮询检测器使用。
 *   PTRACE_TRACEME 会改变线程跟踪状态，可能使后续 tracerPid 检测命中父进程。
 *   responseCorrupt=0 只记录状态；报告 anti_debug 记录请求配置，目标/权限门控
 *   仍可能跳过检测。完整性检测沿用 VM 的字节码损坏响应。
 *
 *   e.g.  OBF("antidebug(tracerPid=1, injection=1, dynamic=1, interval=250)")
 *   e.g.  OBF("antidebug(rootRequired=1, debuggerProcess=1, iptables=1, selinux=1)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * shield                  alias: antiopt                 反优化保护
 *   设置屏障，使后续 -O2/-O3 Pass 无法移除混淆结构。
 *   应最后添加。（OBF_MAX / OBF_AGGRESSIVE 已经包含此能力。）
 *
 *   maxSites [0-10000]  (?)   屏障位置上限
 *   volatile [0/1]            易失性内存屏障
 *   identity [0/1]            不透明恒等式保护
 *   dse      [0/1]            防止死存储消除
 *   cfg      [0/1]            控制流图保护
 *
 *   e.g.  OBF("shield(volatile=1, cfg=1)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * vm                      alias: virtualize, virt        代码虚拟化
 *   将函数编译为由内置解释器执行的字节码。这是强度最高、开销也最大的技术。
 *
 *   preset  [light|medium|high|max]  预设参数组合，在下方显式参数之前应用，
 *                            但下方参数仍然可以覆盖预设值。
 *                            max = 全部能力 + 每个函数独立的变形引擎。
 *   minBlocks        (1)     基本块少于此值时不进行虚拟化
 *   maxBlocks        (400)   基本块多于此值时不进行虚拟化（0 = 无限制）
 *   handlerVariants  [1-64] (3)  多态 handler 变体（1 = 关闭）；函数内每次
 *                            opcode 分发都会在运行时选择变体，而不是每次构建固定一个
 *   handlerDecoys    [0-3] (0)  静态 + 运行时诱饵 handler（1：仅 14 个静态；
 *                              2：28 个静态 + 50% 不透明假条件运行时保护；
 *                              3：预留；适用于普通引擎，嵌套引擎层跳过）
 *   obfRegIdx        (1)     使用编译期盐值 XOR 混淆寄存器索引
 *   encDispatch      (1)     加密 opcode 到 handler 的分发表
 *   encBytecode      (1)     在加载时使用 AES-128-CTR 加密字节码流
 *   lazyDecrypt      (0)     每次取指时解密字节码（静态保存密文）
 *   constInStream    (0)     将常量放入加密的字节码中
 *   strongBytecode   (1)     每个位置使用 PRF 密钥流（0 = 较弱的 salt^idx）
 *   blindTargets     (1)     使用 XOR 隐藏字节码分支目标
 *   hardened         (0)     MBA + 不透明谓词 + 引擎加固；隐含启用 regEncrypt，
 *                            并控制反调试陷阱
 *   regEncrypt       (0)     加密静态保存的寄存器文件
 *   rollingRegKey    (0)     每次存储时更新对应槽位的寄存器密钥
 *   nestedVM         (0)     使用第二个引擎虚拟化热点算术运算
 *   nestedVMOpcodes  (0)     嵌套 opcode 数量上限（0 = 所有符合条件的 opcode）
 *   threadedDispatch (0)     将分发内联到每个 handler（无中央循环）
 *   keyedDispatch    (0)     使用指令指针对每个 opcode 字节加密
 *   superOps         (0)     fuse mul+add / shl+add / icmp+select /
 *                            and+icmp==0 chains into single super-op opcodes
 *   randISA          (0)     每次构建随机排列操作数字段编码
 *   cloudDispatch    (0)     云值驱动的动态 dispatch 偏移：运行时由
 *                            __zone_get_dispatch_offset() 返回一个由云值 V
 *                            派生的偏移（合法值=0；过期/缺失/篡改时非 0），
 *                            直接叠加到 handler 表索引上。本地无任何范围/时效
 *                            校验，错误偏移使索引越界或落入陷阱，自然崩溃。
 *                            需要最终项目自行集成 zone_runtime 提供云值 V。
 *                            默认关闭（关闭时不引用运行时符号，输出不变）。
 *   enginePoolSize   (1)     将函数分散到 N 个不同引擎
 *   perFnEngine      (0)     为此函数分配独立引擎
 *   metamorphicEngines (0)   使每个引擎的 handler 体多样化
 *                            （需要 enginePool 或 perFnEngine）
 *   antiDebug        (0)     传统 VM 反调试陷阱（仅显式启用）
 *   bindAntiDebug    (0)     将调试器检测绑定到 AES 密钥
 *                            （需要 hardened + antiDebug）
 *   adDispatchThreshold  (5000)  分发门的 rdtsc 周期差阈值
 *   adHandlerThreshold   (5000)  handler 抽查的 rdtsc 周期差阈值（去抖）
 *   adDispatchInterval   (64)    每 N 次取指检查一次（必须是 2 的幂）
 *   adHandlerProb        [0-100] (10)  携带陷阱的 handler 百分比
 *
 *   antidebug(...) 是独立的显式启用配置：
 *     tracerPid, ptrace, timing, maps, integrity, dynamic（默认均为 0）
 *     Android/AArch64：debuggerProcess, injection, debugPorts, vpn, proxy,
 *     iptables, selinux, rootRequired（默认均为 0，权限策略见 antidebug 小节）
 *     interval（1000 ms）、threshold（1000000 ns）、responseCorrupt（1）
 *     dynamic 至少需要一个检测器
 *
 *   （已移除的 useAES 参数仍会被接受但忽略；AES 是唯一的密码算法。）
 *
 *   e.g.  OBF("vm(preset=max)")
 *   e.g.  OBF("vm(hardened=1, handlerVariants=4, rollingRegKey=1)")
 *   e.g.  OBF("vm(enginePoolSize=4, metamorphicEngines=1, randISA=1)")
 *   e.g.  OBF("vm(handlerVariants=8, handlerDecoys=2)")  -- 变体分发
 *                            + 28 个静态/运行时诱饵 handler，关闭 nestedVM
 *--------------------------------------------------------------------------*/

/*===----------------------------------------------------------------------===*\
|*  全局参数（驱动器命令行选项，不是注解）                                    *|
|*                                                                            *|
|*  这些参数通过 opt/clang 命令行设置，而不是写在源码中。列在这里是为了保持   *|
|*  参考信息完整：                                                            *|
|*                                                                            *|
|*    -obf-seed=N              可复现构建的基础种子                            *|
|*    -obf-deterministic       根据模块 ID 派生稳定种子                         *|
|*    -obf-verbose             记录注解解析和 Pass 决策                         *|
|*    -obf-verify              每个 Pass 后验证 IR（失败时终止）                 *|
|*    -obf-max-function-insts  跳过指令数超过 N 的函数                         *|
|*    -obf-max-function-blocks=N  跳过基本块数超过 N 的函数                    *|
|*    -obf-max-loop-depth=N    跳过循环嵌套深度超过 N 的函数                   *|
|*    -obf-ir-budget-multiplier  全局 IR 膨胀上限（默认 50 倍）                  *|
|*    -obf-ir-budget-max=N     单函数绝对 IR 指令上限                         *|
|*    -obf-shield-auto         对未显式指定 shield 的混淆函数自动加保护         *|
|*    -obf-no-skips            将 Pass 跳过升级为致命错误（测试用）              *|
|*    -obf-seed-manifest       输出函数/Pass 种子清单                          *|
|*    -obf-seed-manifest-md    将种子清单写入 IR 元数据                       *|
|*    -obf-report-dir=目录     输出 CFG DOT 和 JSON 报告                       *|
|*    -obf-report-json=文件    输出 JSON 混淆映射，使用 '-' 输出到 stdout        *|
|*    -obf-graph-dir=目录      输出程序调用总图和逐函数最终 CFG SVG              *|
|*    -obf-pipeline-ordering="mba,split,bcf"  强制部分 Pass 顺序                *|
|*    -obf-pipeline-ordering-ann  按注解顺序执行，而不是拓扑排序               *|
|*    -obf-metrics-function=名称  只输出指定函数的 IR 指标                     *|
|*    -obf-metrics-include-decls  同时输出函数声明的指标                      *|
|*    -obf-vm-allow-antidebug-bypass  仅 CI/测试使用的 VM 反调试绕过开关        *|
|*                                                                            *|
|*  （Zone 授权相关参数已从编译器移除，运行时库分离到 demo 项目）            *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#endif /* OBF_ANNOTATIONS_H */
