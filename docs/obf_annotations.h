/*===----------------------------------------------------------------------===*\
|*                                                                            *|
|*  obf_annotations.h  --  LLVM 混淆器注解速查表                              *|
|*                                                                            *|
|*  将此头文件放入项目，并使用 OBF() 宏或预设为函数添加注解，从而驱动 LLVM    *|
|*  混淆 Pass。此文件说明常用参数、生效范围、组合限制及失败行为；默认值以当前   *|
|*  配置实现为准。完整构建/验收命令见同目录《项目功能与命令总览.md》。           *|
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
|*      OBF_FN("vm(preset=max,nestedVM=0)")                                  *|
|*      int license_verify(void) { ... }                                     *|
|*                                                                            *|
|*  然后使用启用混淆器的 Clang 工具链编译。一般按函数选取；strenc/fmerge 等有   *|
|*  模块级影响。注解是请求，须检查报告确认实际转换，不能只凭编译成功判断生效。 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifndef OBF_ANNOTATIONS_H
#define OBF_ANNOTATIONS_H

/*
 * Zone 卡密授权由最终项目的 zone_runtime 集成；zoneauth 注解已移除。
 *
 * 仅在业务使用 Zone/云 VM 时，目标才需要集成 zone_runtime、官方 Zone 静态
 * SDK 和依赖，并初始化登录/心跳/capability。普通静态混淆不依赖 Zone。
 * cloudDispatch=1 由编译器注入 __zone_get_dispatch_offset() 外部调用，最终项目
 * 提供该实现；不是删除 zoneauth 后连云分发也删除。卡密不写入注解/选项。
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
 * 普通 Clang 虽会保留 annotate，也不会自动运行 XOLLVM：源码编译需
 * -mllvm -enable-obfuscation；IR 路径需 opt -passes=obfuscation。
 * OBF_FN 只防止内联，不保证未使用函数不会被链接 GC，不保证 VM/Pass 必然提交。
 * “模块级”通常指一个编译单元的 LLVM Module，不是整进程所有 .o/.so/SDK。
 */
#if defined(__clang__)
#  define OBF(spec)    __attribute__((annotate("obf: " spec)))
#  define OBF_FN(spec) __attribute__((annotate("obf: " spec), noinline))
#else
#  define OBF(spec)
#  define OBF_FN(spec)
#endif

/*
 * 敏感决策边界：sensitive(region=<标识>, strict=<0|1>)
 *
 * 把一次敏感判断（验签、比较、授权决策）连同它的成功/失败动作收进一个
 * 完整函数，并注解该函数。编译器会：
 *   - 校验区域边界（结果不得从 return/store/未知调用/inline asm 逃逸，
 *     且区域内必须有基于结果的成功/失败分支）；
 *   - strict=1 时，边界错误或无法虚拟化一律编译失败（report_fatal_error）；
 *   - 要求该函数同时启用 vm（否则报错）；
 *   - 校验通过后附加 !obf.sensitive.validated，并在 VM 提交后附加
 *     !obf.sensitive.committed，作为提交后结构门禁的依据。
 *
 * 写法要点：
 *   - region 是诊断用的稳定标识，不参与安全判断；
 *   - strict=1 时函数必须能被 VM 化：不能含 EH/invoke、callbr、indirectbr、
 *     musttail、naked，且需满足 vm 的 minBlocks/maxBlocks；
 *   - 区域内不要用会抛异常的构造（std::string/std::vector）或返回 bool
 *     （-O0 会生成 i1 槽，VM 不支持）——把资源准备放在注解函数之外。
 *
 * 示例：
 *   extern int verifier(const unsigned char*, unsigned long);
 *   extern void allow_action();
 *   extern void deny_action();
 *   OBF_FN("sensitive(region=auth,strict=1),vm(preset=max,nestedVM=0)")
 *   void verifyAndAuthorize(const unsigned char* data, unsigned long size) {
 *       int verdict = verifier(data, size);
 *       if (verdict == 1) { allow_action(); } else { deny_action(); }
 *   }
 * 局部内存的 GEP/指针转换派生地址也会递归检查，并传播其 load 污点。
 * 当前敏感来源是可识别的外部非 void 调用结果，不自动理解所有本地业务判断；
 * return verifier(...) 会泄漏决策，不是完整边界。strict=0 不保证拒绝交付。
 * 这不是授权算法正确性证明，也不自动开启 cloudDispatch 或进程级到期终止。
 *
 * 最终 ELF 完整性：含严格敏感区域的模块会发射 .text.xollvm.integrity
 * manifest 占位与运行时校验 ctor；由后链接工具 xollvm-elf-hardener 回填
 * 摘要与范围。链接包装器（demo/jni/ndk-linker-wrapper/clang++）在链接后
 * 自动 targets + audit + seal + verify，再原子推广。相关环境变量：
 *   XOLLVM_ELF_HARDENER          xollvm-elf-hardener 路径（链接时必需）
 *   XOLLVM_ELF_ZERO_THRESHOLD    可执行段零洞阈值，默认 512（含）
 *   XOLLVM_REAL_CLANG            NDK clang++（真实链接器）
 *   XOLLVM_OBFUSCATOR_CLANG      xollvm clang++（编译阶段）
 *
 * 退出码（xollvm-elf-hardener）：0 通过 / 2 malformed / 3 策略违规。
 * vm(encodedTargets=1) 限 AArch64 LE ELF PIE，须通过正式安装入口链接：
 *   XOLLVM_LINK_COMPILER=/path/to/clang++ bash /path/to/xollvm-link object.o -o app
 * 入口顺序为 link→targets→audit→seal→verify→原子推广，失败保留旧输出。
 * XOLLVM_ELF_HARDENER 可覆盖同目录工具；仅 targets 的 ELF 也可验收。
 *
 * 范围说明：manifest 自身参与摘要（窗口置零），覆盖 EHDR+程序头及全部
 * 文件支持的可执行 PT_LOAD；seal 后不能 strip 或修改这些字节。
 * verify 另校验版本、VA、范围数量和全部范围槽；文件尾追加数据应由 APK/包
 * 签名负责。动态符号（如外部 API）仍可能保留在 .dynsym，这是已知事实。
 * ctor 是加载期校验，不是持续检查进程全部内存；外部库/所有可写数据不自动覆盖。
 * 没有 manifest 的 targets-only ELF 可通过工具验收，但不获得同样的运行时摘要校验。
 * strip/objcopy 等放在最后加固之前，最终交付文件必须再经过 targets/audit/seal/verify。
 */

/*===----------------------------------------------------------------------===*\
|*  内置预设                                                                    *|
|*                                                                            *|
|*  这是一个大致的强度/体积成本梯度。选择满足威胁模型的最低级别，因为每提升一档，*|
|*  都会增加代码体积并降低函数运行速度。                                    *|
\*===----------------------------------------------------------------------===*/

/* 轻量算术噪声；真实体积/性能成本取决于函数与预算，不承诺“几乎无开销”。 */
#define OBF_MINIMAL     OBF("substitution, mba(prob=40)")

/* 日常加固：MBA + 虚假控制流 + 基本块切分。 */
#define OBF_BALANCED    OBF("mba, bcf, split")

/* 较强的静态分析对抗：增加控制流扁平化、字符串加密、反反编译干扰结构和
 * 反优化保护，降低 -O2 还原混淆结构的可能性。 */
#define OBF_AGGRESSIVE  OBF("flattening, mba, bcf, split, strenc, adec, shield")

/* 旧组合预设，当前不可直接使用：vm 与 flattening 在流水线中互斥，会编译失败。
 * 此处保留原宏定义，文档不改变业务展开行为；需要 max VM 时显式使用
 * OBF_FN("vm(preset=max)") 并搭配兼容 Pass，且满足 AArch64/后链接要求。
 * max VM 的成本依真实函数而定，不应作为所有函数的默认配置。 */
#define OBF_MAX         OBF("vm(preset=max), mba, bcf, flattening, strenc, adec, shield")

/* 敏感决策边界（strict）：验签/比较/授权函数。region 名称按项目自定。 */
#define OBF_SENSITIVE(region) OBF("sensitive(region=" region ",strict=1), vm(preset=max)")

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
|*  - 参数格式为 key=value；建议统一 0/1。VM 只接受 0/1/true/false，不支持裸 *|
|*    key、yes/no/on/off；其他 Pass 的宽松解析不能套用到所有配置。             *|
|*  - 未知 Pass 警告后被丢弃，不一定编译失败；未知 key 在不少 Pass 被忽略，    *|
|*    sensitive 等另有严格校验。Pass 名规范化，key 大小写依各实现，请照例拼写。 *|
|*  - 同一函数的多个注解会合并，后出现的参数优先。                           *|
|*  - 每函数预算放在已识别的 Pass 括号内，例如 vm(budgetMax=40000)：          *|
|*        budget=N / budgetMultiplier=N  此函数的 IR 膨胀倍数                 *|
|*        budgetMax=N     此函数的绝对 IR 指令上限                             *|
|*    注解值 0 沿用 CLI，不是单函数字面“无限制”；勿写独立 budgetMax= token。 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

/* 通用生效/成本规则：
 * - 默认使用拓扑依赖顺序，注解书写顺序不等于实际执行顺序；fmerge/strenc 为模块阶段。
 * - prob 只针对符合条件的位置，100% 不能越过 IR/ABI/规模限制；无候选可无变化。
 * - 普通可选 Pass/VM 可跳过，VM wrapper 可因 hard cap budget_rollback；严格
 *   sensitive 或 -obf-no-skips 才会将相应失败升级为编译错误。不能以输出正确代替验收。
 * - 全局 multiplier 默认 50，hard cap 默认 0；一般预算有 256 条最低基线再受 cap
 *   限制。全局 multiplier=0 关闭预算追踪；增加 IR 预算不增加 VM 寄存器容量。
 * - 必须看 report passes 的 ran/skipped、skip_reason；VM phase=committed 后再看
 *   requested/effective/disabled_reasons，最终 encodedTargets 还需后链接验收。
 * - -obf-verify 只验证 IR 结构，不证明业务等价、抗逆向或授权安全。
 */

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
 *   prob            [0-100]  (40)   被改写的符合条件位置的百分比
 *   depth|maxDepth  [1-10]   (3)    递归改写深度
 *   maxSites        [1-5000] (120)  改写位置上限
 *   termsMin|linearTermsMin  [1-64] (6)   线性组合项数下限
 *   termsMax|linearTermsMax  [>=min,<=96] (10) 线性组合项数上限
 *   enableNonLinear [0/1]           允许非线性恒等式
 *   nonLinearWeight|nonLinearProb [0-100]  非线性混合权重
 *   enableLayered   [0/1]           分层/窗口改写
 *   layeredWindow   [0-256]         分层 Pass 的窗口大小
 *   layeredBudget   [0-32]          分层改写预算
 *   -- 无内存非线性零值（目标是提高 -O2/SMT/线性 MBA 分析成本，不是不可还原保证） --
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
 *   范围：选中的整数运算，不是整体加密或授权校验。深度/项数/多轮会增加 IR、
 *   编译时间和运行成本；无可改写操作、预算或概率可能使请求无实际变化。
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
 *   支持整数 1..32/64 位及 float/double；跳过 switch/GEP/PHI/alloca 等结构常量、
 *   intrinsic、inline asm 和要求 immarg 的参数。不是整段 .rodata 加密，运行值可观察。
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * bcf                                                    虚假控制流
 *   使用不透明谓词保护的虚假分支包裹基本块。
 *
 *   prob      [0-100]     (30)  获得虚假保护分支的基本块百分比
 *   loop      [1-10]      (1)   重复应用转换的次数
 *   maxBlocks [0-100000]  (0)   超过门限跳过；0 为自动策略
 *
 *   e.g.  OBF("bcf(prob=80, loop=2)")
 *   只改符合条件的正常块；EH/特殊控制流和预算可限制转换。不自动做运行时授权检测。
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * split                                                  基本块切分
 *   将基本块切成更小的片段，使控制流图碎片化。
 *
 *   num  [2-10]  (5)   每个符合条件的基本块切分出的片段数量
 *
 *   e.g.  OBF("split(num=4)")
 *   块太短、EH/PHI/musttail 等限制会减少可切位置；碎片化不是 VM 或语义加密。
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * substitution                          alias: sub      指令替换
 *   用更长的等价指令序列替换简单操作。
 *
 *   loop     [1-10]     (1) 指令替换表的应用次数
 *   maxSites [0-100000] (0) 被替换位置的上限；0 为自动预算
 *
 *   e.g.  OBF("substitution(loop=2)")
 *   仅支持已实现的等价替换规则；浮点/任意 intrinsic 不自动覆盖，多轮增大成本。
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * flattening                            alias: fla      控制流扁平化
 *   将控制流图重建为由分发器驱动的状态机。
 *
 *   min|minBlocks   [2-100000] (3)    触发扁平化所需的最少基本块数
 *   max|maxBlocks   [>=min,<=200000] (200) 可处理的最大基本块数
 *   indirect|allowIndirect  [0/1] (0) 允许含间接调用的候选函数
 *   hybrid          [0/1]             混合分发器模式
 *   opaque|opaqueState      [0/1]     不透明状态变量
 *   fake|fakeTransitions    [0/1]     注入虚假状态转换
 *   fakecase|fakeCases      [0-64]    虚假 switch 分支数量
 *   domain|perDispatcherDomain [0/1]  每个分发器独立的状态域
 *   ptr|stateptr|obfuscateStatePtr  [0/1]  混淆状态指针
 *   alias|aliasptr|opaqueAliasStatePtr [0/1] 使用不透明别名混淆状态指针
 *
 *   e.g.  OBF("flattening(opaque=1, fake=1, fakecase=4)")
 *   与同函数 vm 互斥（包括 OBF_MAX 旧组合），显式排序不能解除；已有 indirectbr、
 *   callbr、musttail、naked、convergent、WinEH funclet 等会跳过。Itanium EH 只改正常块。
 *   规模/间接调用资格检查仍有效；不是把整个程序转成 VM。
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * vcall                                                  虚拟调用伪装
 *   通过合成的虚函数表转发直接调用。
 *
 *   prob        [0-100]     (30)  被伪装的调用位置百分比
 *   maxSites    [0-100000]  (0)   被伪装位置上限；0 为自动预算
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
 *   这是调用点伪装，不是 VM，也不虚拟化 callee 函数体。只收模块内有定义的直接
 *   callee，跳过外部声明/intrinsic/函数指针调用/varargs/musttail。merge 与 encTable
 *   同开会回退明文合并表；加密表依赖 ctor 初始化。默认放在 flattening/VM 之后。
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * sdiff                                                  语义扩散
 *   将一个值的定义分散到额外的计算槽中。
 *
 *   prob     [1-100]   (45)  被扩散的符合条件值的百分比
 *   slots    [1-8]     (3)   每个值使用的扩散槽数量
 *   maxSites [1-2000]  (80)  被扩散位置的上限
 *
 *   e.g.  OBF("sdiff(slots=4)")
 *   增加计算/访存槽，不是对整个进程内存做加密；受候选、概率及预算限制。
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * strenc                                                 字符串加密
 *   加密字符串字面量，由运行时存根延迟解密。这是模块级 Pass，给任意一个
 *   函数添加注解即可对整个模块启用。
 *
 *   min|minlen|minlength [1-100]  (4)  仅加密长度达到此值的字符串
 *   cipher   {chacha|aes|xor}  (chacha) 算法族（ChaCha20 = 无表实现）
 *   aes      [0/1]                      显式 aes=1 选 AES-CTR，0 选弱 XOR；
 *                                      未指定时默认 ChaCha，cipher 优先
 *   keysplit [0/1]                (1)   将密钥拆分到多个片段
 *
 *   e.g.  OBF("strenc(cipher=chacha, min=4)")
 *   模块多请求合并：min 取最大，算法/keysplit 开关 OR，ChaCha 优先，不能逐函数隔离。
 *   仅处理可丢弃常量 C 字符串；跳过含 % 格式串、过短/外部 ABI 全局、地址转整数等。
 *   全局初始化等未改引用可保留原明文，不保证 strings 扫描无结果。函数使用替换为
 *   局部解密缓冲区，不保留静态字面量的永久地址/生命周期；返回/异步保存其指针或
 *   地址身份比较须先检查生成 IR 和业务语义。运行时可见明文，不是秘密存储方案。
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
 *   group 只在同 Module 内有效；至少需要足够合格候选。默认 thunk=0 只收内部且
 *   未真实取地址的函数；thunk=1 保留外部/取地址入口，不保证消除所有符号。
 *   跳过 varargs、EH、inline asm、特殊参数 ABI、indirectbr/blockaddress 等；同组
 *   配置不一致时按函数名字典序首成员决定并警告。合并后需重新核对其他 Pass 报告。
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * zoneauth（已移除）
 *
 *   Zone 授权功能已从编译器移除，运行时库已分离到 demo 项目独立维护。
 *   如需 Zone 授权，请在最终项目自行集成 zone_runtime；vm(cloudDispatch=1)
 *   仍是有效编译配置，但需要该项目提供运行时与云服务，不是 zoneauth 的替代注解。
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * 云值驱动 VM dispatch（cloudDispatch）端到端说明
 *
 *   范围：只对启用 cloudDispatch 且 VM 已 committed 的函数/对应云引擎分发生效，
 *   不是全程序 VM 壳，不自动覆盖原生函数、非云 VM 或外部库。共享引擎并不代表
 *   整个进程持续在 VM 内执行；函数调用到原生 callee 时同样会离开 VM 分发。
 *
 *   作用：handler 索引叠加由临时云值 V 派生的 offset。合法 V 对应 0；失效值
 *   通常非 0，可导致错误 handler、越界或陷阱。不是单独 if(expired) 授权分支。
 *   encodedTargets=1 仍有 descriptor 状态/索引边界检查，越界执行 brk/SIGTRAP，
 *   不能笼统说成本地没有任何范围检查或一定 SIGSEGV。未处理致命信号结束整个进程。
 *
 *   触发时机（重要）：
 *     - 断网时缓存仍在当前有效窗口，可继续执行；断网不等于立刻云值失效。
 *     - 云 VM 正在运行时，失效后下一次实际 handler 分发即可失败，不用等重新调用。
 *     - 若只执行原生代码/非云 VM、等待输入，或阻塞在原生外部调用里，没有执行新
 *       的云 handler 分发就没有该索引越界。后台预取失败本身不主动 trap/kill。
 *     - 故此功能不保证“无论业务在做什么，到期固定时间内全进程自动停止”。
 *     - 若尚未执行失效分发，先恢复网络，下一次同步刷新成功后可正常执行；这是
 *       云值刷新，不是捕获崩溃/重试恢复。已经被 trap 结束的原进程不能恢复。
 *
 *   编译期（客户端）：
 *     vm(cloudDispatch=1) 让 VM 在两处 dispatch（中央与 threaded）注入对
 *     __zone_get_dispatch_offset() 的调用；该符号由 zone_runtime 的
 *     cloud_value_manager 提供。客户端编译期只需 VM_DISPATCH_OFFSET_MASK，
 *     不需要预知运行时 V。默认关闭时输出与非云构建一致。
 *
 *   运行时（客户端）：
 *     cloud_value_manager 首次/跨窗口 dispatch 尝试同步拉取当前 window 的 V，
 *     不是首次拉取必然成功。另按 VM_DISPATCH_PREFETCH_SEC 异步预取；按
 *     当前 window_id 计算 HMAC-SHA256(V, window_le64)，与 VM_DISPATCH_OFFSET_MASK
 *     按位与作为偏移。V 通过 zone_wrapper 的登录/租约/capability 线路取得。
 *     跨窗口刷新失败仍使用当前窗口计算，不能沿用缓存窗口延长旧 V 有效期。
 *     当前默认 window=60 秒、prefetch=50 秒、mask=0xFFF；时钟经服务端校准。
 *     到失败的实际时间还取决于窗口位置、网络超时、调度与是否执行到云分发，
 *     不能承诺“从断网瞬间起第 60 秒必然退出”。
 *
 *   云端：
 *     持有固定密钥 k，为每个 window 搜索一个 V 使 HMAC(V, window) & MASK == 0，
 *     随 capability 响应下发 dispatch_v（32B base64）与 window_id。
 *     参考实现位于最终项目 ../demo/jni/zone_runtime/cloud/capability_v1.js。
 *
 *   约定（两端必须一致）：
 *     VM_DISPATCH_OFFSET_MASK（客户端 cloud_value_manager.h）== 云端
 *     dispatchOffsetMask，窗口及字节序也须匹配。12-bit(0xFFF) 期望搜索约 2^12
 *     次 HMAC，延时依服务资源；增大位宽会增加搜索成本，不等于完整安全性证明。
 *     截断 HMAC 不是确定性过期标志：不匹配 V/window 在理想均匀模型下仍约有
 *     1/4096 概率得到 0；非零也不保证任何基索引立刻越界（可能仍落表内）。
 *     掩码位宽不是授权密钥强度；不能将每次过期必崩当作数学保证。
 *
 *   排错与验收：
 *     编译报告确认函数 passes.vm 全部 ran、phase=committed、effective.cloudDispatch
 *     为 true；预算回滚后输出正确不代表云 VM 生效。encodedTargets 还需最终化。
 *     仅 offset!=0、到达调用标记和 SIGTRAP/SIGSEGV 不足以证明来自云分发；需
 *     同线程 offset 调用现场、故障 PC、实际 descriptor/索引越界与指令数据流归因。
 *     utils/production_acceptance.py cloud 显式联网验收，含无关崩溃拒绝与 offset=0
 *     重放对照；卡密仅经 XOLLVM_ZONE_CARD。recovery 与 expiry 是独立测试进程，
 *     前者在触发失效分发之前恢复网络，不表示已崩进程恢复；不修改全设备网络。
 *     授权登录、心跳、请求超时和退出清理由最终项目的 zone_runtime 集成负责。
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * aes_stub                                               AES 运行时存根
 *   字符串 AES-CTR 存根在需要时自动链接；aes_stub(mba(...),bcf(...)) 为共享
 *   解密存根附加子 Pass。strenc_stub 当前不是可用注解名，会被当作未知 Pass 丢弃。
 *   单独请求不保证有候选字符串。
 *   模块选用一份存根配置，调用者应保持一致；字符串默认 ChaCha 与 VM AES 层独立。
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * adec                    alias: antidecompiler          反反编译
 *   注入干扰反汇编器和反编译器的 gadget。
 *
 *   prob      [1-100]   (50)  每项技术的基础概率
 *   maxSites  [1-500]   (40)  gadget 位置上限
 *   strength  [0-3]     (2)   全局 gadget 强度
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
 *   与 antidebug 不同：干扰静态分析，不提供“发现调试器即退出”。可用技术依目标，
 *   rdtsc 仅 x86；自定义 asm/clobber 须匹配 ABI。不是反编译不可恢复保证。
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * antidebug                                              反调试检测
 *   在函数入口执行反调试检测；检测到异常时记录响应状态，并可让函数返回
 *   对应返回类型的零值。所有检测器、dynamic、rootRequired 默认均为 0。
 *   dynamic 按有效配置复用模块内线程和响应状态；不同配置独立，异常锁存。
 *
 *   tracerPid     [0/1]       检测 /proc/self/status 中的 TracerPid
 *   ptrace        [0/1]       兼容为只读 TracerPid 检测，不执行 PTRACE_TRACEME
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
 *   responseCorrupt [0/1] (1) 检测到异常时让函数提前返回零值（void 直接返回）
 *
 *   新增七项及 rootRequired 仅对 Android/AArch64 生效。rootRequired=0 跳过
 *   debuggerProcess/iptables，其余探测读取失败时跳过。rootRequired=1 先检查
 *   geteuid()==0；权限不足直接触发响应，启用项读取/解析失败也触发响应。
 *   proxy 不读取 Android 系统代理设置；VPN/工具名/端口均为特征检测。
 *   dynamic 在入口与后台检测；线程退出用停止标志和 join 回收；创建失败锁存。
 *   ptrace=1 与 tracerPid 共用只读检测，不改变父子跟踪和信号关系。
 *   普通 MT/root 终端不等于调试器附加；默认不因 root 身份拒绝运行。
 *   与 vm 组合时 guard 在正式 wrapper 提交后插入，integrity 在 VM 初始化执行。
 *   responseCorrupt=0 只记录状态；报告 anti_debug 记录请求配置，目标/权限门控
 *   仍可能跳过检测。完整性检测沿用 VM 的字节码损坏响应。
 *   返回 0/null 不必然是业务安全失败，例如返回 0 表示成功的接口须自行设计边界。
 *   dynamic 后台只检测/锁存；独立 guard 在对应函数入口消费状态，不会异步杀死
 *   正在执行任意原生函数的进程。VM bindAntiDebug 由对应解码路径消费状态；异常
 *   不因调试器离开自动复位。timing 受负载/调度影响，须测误判；不是网络到期看门狗。
 *   integrity 的 ctor 检查与最终 ELF manifest 校验不同，均不是持续扫描所有内存。
 *
 *   e.g.  OBF("antidebug(tracerPid=1, injection=1, dynamic=1, interval=250)")
 *   e.g.  OBF("antidebug(rootRequired=1, debuggerProcess=1, iptables=1, selinux=1)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * shield                  alias: antiopt                 反优化保护
 *   设置屏障，降低后续 -O2/-O3 移除混淆结构的可能性，不保证任何优化都无法还原。
 *   默认在主要混淆后、adec 前执行；OBF_AGGRESSIVE 已包含，OBF_MAX 另有组合冲突。
 *
 *   maxSites [0-10000] (200)  屏障位置上限
 *   volatile [0/1]            易失性内存屏障
 *   identity [0/1]            不透明恒等式保护
 *   dse      [0/1]            防止死存储消除
 *   cfg      [0/1]            控制流图保护
 *
 *   e.g.  OBF("shield(volatile=1, cfg=1)")
 *   不是运行时安全检测或 VM；会增加访存/体积，必须检查最终优化后的产物。
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * vm                      alias: virtualize, virt        代码虚拟化
 *   将被选函数编译为由内置解释器执行的字节码。不是 ELF 全程序 VM 壳；未注解
 *   原生函数、外部库和整个调用树不会自动 VM 化。共享/独立引擎是解释器复用方式，
 *   与进程持续运行 VM 是不同概念；开销依函数与组合实测。
 *
 *   preset  [medium|high|max]  预设参数组合，在下方显式参数之前应用，
 *                            但下方参数仍然可以覆盖预设值。
 *                            max = 独立变形引擎、4 变体、两层嵌套、白盒 AES、
 *                            96 opcode、字段布局、最终目标编码、auto wrapper。
 *                            不自动启用检测器、root 检测或云值依赖。
 *   minBlocks        (1)     基本块少于此值时不进行虚拟化
 *   maxBlocks        (400)   基本块多于此值时不进行虚拟化（0 = 无限制）
 *   handlerVariants  [1-64] (3)  多态 handler 变体（1 = 关闭）；函数内每次
 *                            opcode 分发都会在运行时选择变体，而不是每次构建固定一个
 *   handlerDecoys    [0-3] (0)  静态 + 运行时诱饵 handler（1：仅 14 个静态；
 *                              2：28 个静态 + 50% 不透明假条件运行时保护；
 *                              3：预留；适用于普通引擎，嵌套引擎层跳过）
 *   obfRegIdx        (1)     使用编译期盐值 XOR 混淆寄存器索引
 *   encDispatch      (1)     加密 opcode 到 handler 的分发表
 *   encBytecode      (1)     构建期 AES-128-CTR 加密；非 lazy 时加载 ctor
 *                            去除整段 AES 外层，不保证运行期只存在密文
 *   lazyDecrypt      (0)     每次取指时解密字节码（静态保存密文）
 *   constInStream    (0)     将常量放入加密的字节码中
 *   strongBytecode   (1)     每个位置使用 PRF 密钥流（0 = 较弱的 salt^idx）
 *   blindTargets     (1)     使用 XOR 隐藏字节码分支目标
 *   hardened         (0)     MBA + 不透明谓词 + 引擎/wrapper 加固；隐含
 *                            regEncrypt，不自动开启所有反调试检测器
 *   regEncrypt       (0)     XOR 保护寄存器文件槽，读出计算时仍有真实值
 *   rollingRegKey    (0)     每次存储时更新对应槽位的寄存器密钥
 *   nestedVM         (0)     使用第二个引擎虚拟化热点算术运算
 *   nestedVMOpcodes  (0)     嵌套 opcode 数量上限（0 = 所有符合条件的 opcode）
 *   nestedVMHardened (0)     独立加固 owner 专属内层引擎；需要 nestedVM。
 *                            最多两层，内层不再嵌套或另起检测监控线程。
 *   threadedDispatch (0)     将分发内联到每个 handler（无中央循环）
 *   keyedDispatch    (0)     使用指令指针对每个 opcode 字节加密
 *   superOps         (0)     fuse mul+add / shl+add / icmp+select /
 *                            and+icmp==0 chains into single super-op opcodes
 *   randISA          (1)     随机排列 subop/predicate/kind 的语义编码（ISA v2）
 *   operandLayout    (0)     按 seed 排列固定指令字段；CALL/SWITCH 尾保持规范
 *   extendedISA      (0)     发射新增立即数、算术链与 GEP 访存融合 opcode
 *   encodedTargets   (0)     AArch64 ELF64LE PIE handler/engine 目标编码；需
 *                            xollvm-link 后处理，编译报告仅标记 pending
 *   whiteboxAES      (0)     密钥融合查表 AES-CTR；每实例 372736 字节表，
 *                            无运行时 expanded-key 重建；需要 encBytecode。
 *                            lazy 每调用独立 16 字节块缓存，允许逆向 seek。
 *   wrapperFamily    {outlined|split|arena|auto} (split) wrapper 结构族
 *   cloudDispatch    (0)     云值驱动的动态 dispatch 偏移：运行时由
 *                            __zone_get_dispatch_offset() 返回一个由云值 V
 *                            派生的偏移（合法值=0；失效值通常非 0，非确定保证），
 *                            叠加到实际 handler 分发索引；encodedTargets 有边界
 *                            检查，越界 trap。触发时机/概率限制见上方云 VM 小节。
 *                            需要最终项目自行集成 zone_runtime 提供云值 V。
 *                            默认关闭（关闭时不引用运行时符号，输出不变）。
 *   enginePoolSize   (1)     将函数分散到 N 个不同引擎
 *   perFnEngine      (0)     为此函数分配独立引擎
 *   metamorphicEngines (0)   使每个引擎的 handler 体多样化
 *                            （需要 enginePool 或 perFnEngine）
 *   antiDebug        (0)     传统 VM 反调试陷阱（仅显式启用）
 *   bindAntiDebug    (0)     将共享检测响应锁存绑定到字节码解码盐值
 *                            （需要 hardened、有效检测源及 responseCorrupt）
 *                            可由独立 antidebug 提供；不恢复白盒 AES 密钥。
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
 *   VM 布尔参数仅接受 0/1/true/false；坏整数、未知 preset/wrapper 拒绝。
 *   -obf-report-json 的 VM witness v2 分开 requested/effective、依赖关闭原因、
 *   实际 wrapper、caller/engine opcode、变体和嵌套 helper；whitebox_instances
 *   是当前 caller 的表数，module_whitebox_instances 是模块总数（含内层）。
 *   descriptor 中的 key/add/rotation 可由静态分析逆解，不能视为不可破解。
 *   输入限制：EH/invoke、musttail、callbr、已有 indirectbr、naked 会拒绝；未支持
 *   IR/intrinsic、特殊 ABI/聚合值、寄存器文件溢出会导致 skip 或 strict 失败。
 *   CALL 最多 16 个实参，支持普通标量/指针/float/double 路径，不等于任意 STL/EH。
 *   比较分支支持 i1 不等于任意 load/store i1 槽受支持，-O0 bool 代码须看报告。
 *   llvm.fmuladd/fma/fabs/minnum/maxnum/copysign 当前不做非等价降级；基础浮点乘加
 *   可在语义允许时用 -ffp-contract=off 避免融合 intrinsic，但不是提供 fma 支持。
 *   encBytecode=0 归一化关闭 lazyDecrypt/hardened/constInStream；whiteboxAES=1
 *   同时 encBytecode=0 会报错。关闭 nestedVM 会关闭 nestedVMHardened；检查 effective。
 *   encodedTargets/max 的完整交付要求 AArch64 ELF64LE PIE；ARM32 的 max 默认会
 *   明确拒绝。当前已验收 ARM32 子集为 max 显式 encodedTargets=0,nestedVM=0 等，
 *   FP 使用 -ffp-contract=off；不代表所有架构/IR 已覆盖。本机后端仅 AArch64/ARM。
 *   lazy 白盒按调用缓存 16 字节块，不保证进程内永无明文；白盒表开销按实例累计。
 *   最终 ELF 攻击接口：python -m utils.deobf_bench --build-dir PATH
 *     --attacks aarch64-vm-targets 或 aarch64-vm-bytecode，结果明确区分
 *     RECOVERED/NOT_RECOVERED_WITHIN_BUDGET/TIMEOUT/UNSUPPORTED/TOOL_ERROR。
 *   字节码动态白盒提取适配器尚未实现，UNSUPPORTED 不代表防护成功。
 *   成本 CLI：python utils/vm_hardening_cost.py --baseline-opt PATH
 *     --current-opt PATH --seeds 1,42,20260930 --timeout 180 --output PATH
 *   同一 NDK -O0 后端测量5类fixture；JSON保存逐阶段时间/RSS、section体积、
 *   三次native计时和最终artifact hash。允许 --resume，历史工具hash必须一致。
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
|*    -enable-obfuscation      Clang 源码入口启用混淆（用 -mllvm 传入）         *|
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
