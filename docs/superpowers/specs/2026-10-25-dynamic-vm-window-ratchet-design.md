# 动态 VM Window Ratchet 与 Guardian/Worker 架构

日期：2026-10-25

状态：已获用户确认进入正式架构规格编写阶段；本文是实现前设计，不代表功能已经完成。

权威上位设计：

```text
/data/user/0/com.termux/files/home/xollvm-android/动态VM保护架构_方案总设计_v1.md
```

本文不改变上位设计的目标，只把其运行时执行模型、材料粒度、进程结构和开发/生产云端边界具体化。当前已有的 XOVM2 relay、canonical protocol、WAL、generation、lease、registration 和 ELF identity 实现作为基础设施；现有 `encoded_bc + decode_map` package 保留为 v1 参考/互操作测试格式，不作为最终动态 VM 执行格式。

## 1. 目标与不可宣称性质

### 1.1 必须达到的工程目标

最终客户端交付应满足：

1. 公共 ELF 中没有可以独立恢复完整业务执行能力的明文 handler、完整明文 bytecode、完整稳定 handler index 表、静态执行密钥或 session 材料。
2. 大体积静态内容可以随 ELF/APK/CDN 分发；授权服务不为每个用户生成和传输完整执行包。
3. 每次启动建立新的 session；运行材料按 window/generation 推进，旧 window 不能跨 session 或跨允许期限直接复用。
4. VM 执行不依赖一个全局 `opcode -> handler` 表或一个集中式 `switch` dispatch 点。
5. 当前 handler 和有限 bytecode window 只在受控短生命周期内进入可执行/明文状态，执行完成后清理。
6. B 模式按原始请求 `t0` 管理：`t0+110s` 开始获取下一代材料，`t0+120s` 禁止新调用取得旧代；已 pin 的调用允许完成。
7. 材料缺失发生在保护业务副作用前时，保护入口同步失败；后台续期线程不直接执行保护业务、不因暂时网络失败后台 kill 进程。
8. Guardian、Worker 和启动握手不能通过直接运行 Worker 或替换普通命令行参数绕过。
9. 云端程序采用 C++ 实现，开发模式可在本地运行并使用合成 provider；生产模式必须关闭调试后门、fault hook、详细材料日志和本地 provider。

### 1.2 不承诺的性质

在无 TEE、无硬件不可导出密钥、且攻击者拥有 root、可控制进程和 TTD 的条件下，软件不能保证：

- 一次有效运行的明文 handler、寄存器和输入输出绝对不会被记录；
- 完整 TTD 绝对无法恢复一次运行的业务语义；
- Guardian/Worker、反调试或 `fork` 能成为 root 之上的信任根；
- chaff 能在密码学意义上阻止动态观察；
- 软件清零能证明秘密从未被复制。

本架构的准确安全声明是：

```text
一次运行捕获不自动等于永久跨会话复用；
静态产物不直接提供完整执行能力；
传统单一 dispatch 观察点和完整全局 handler 表被移除；
完全控制 root 客户端仍可能恢复当前运行的业务语义。
```

## 2. 与总设计第 5 节攻击面矩阵的对照

上位设计第 5 节是目标矩阵。Window Ratchet 架构不把“困难”写成“不可能”，并对每项给出实际边界：

| 总设计攻击 | 上位设计目标 | Window Ratchet 的处理 | 结论 |
|---|---|---|---|
| 静态提取密钥/索引 | 无静态秘密 | ELF 只含加密 artifact、公开格式和验证材料；window key、session nonce、continuation 状态不进 ELF；不生成全局 decode map | 对静态提取有效；运行时捕获不在此项保证内 |
| 静态 patch 写死 index | 无值可写、无验证单点 | 不使用固定全局 handler index；下一跳由当前 window 的认证 continuation 和 session/generation 状态决定；保护入口仍有必要的冷路径边界检查 | 能消除固定 index patch；不能阻止 root 直接 patch 所有执行代码 |
| 动态读一次写死 | 会话随机化 | session、generation、window ticket、previous-state commitment、chaff 参数和 handler placement 每次变化；旧 window 不能直接作为新 session 输入 | 只能阻止简单跨运行复用；当前运行仍可能被记录 |
| 离线运行 | 无 S 无法解码 | artifact 可离线取得，但没有在线 session capability、window grant 和有效 ratchet 状态不能取得首个/后续窗口材料；无材料保护入口同步失败 | 满足在线材料依赖；不宣称硬件级离线不可绕过 |
| 假服务器 | ECDH 服务器认证 | 继续使用签名 trust bundle、临时 X25519、transcript/AAD、AEAD；本地 debug provider 与 production trust route 分离 | 协议层可验证；生产 trust provider 仍需部署验收 |
| 抓包重放 | 临时密钥 + 单调 counter | request_id/nonce/request_hash 幂等、session/generation/window sequence、previous-state commitment 和服务端 replay fence；同一 grant 不能推进两个状态 | 对跨 session、跨 generation 重放有效；完全控制客户端可 patch 本地状态 |
| patch 派生函数 | 极难 | 派生逻辑分布在 Guardian、Worker 和 window continuation；用途域分离；不把所有材料集中成长期 root struct | 增加分析成本；不能声称不可 patch |
| dispatch 点记账 | 链式直跳 + 即焚 + 投毒 | 使用 continuation tail、局部 shard、短期 JIT buffer；不生成全局 handler 表；chaff 由 window seed 驱动 | 消除单一静态 dispatch 观察点；TTD 仍可记录多个动态边界 |
| 单步全 dump | 性能代价 + 时间完整性 | handler/bytecode window 短生命周期、W^X、每线程 buffer、heartbeat/lease/window deadline、完整性影响下一状态 | 增加 dump 成本和降低复用价值；不能保证 root 无法 dump |
| 完整逆向 + 硬件级分析 | 终究可行 | 接受该上限；没有 TEE；服务端只保留 window 授权和未来状态，不把软件混淆宣传成绝对防护 | 明确符合现实边界 |

### 2.1 对矩阵的关键纠偏

该架构比方案 A/B/C 更准确地满足总设计，但不是因为“JIT/chaff 自动击败 TTD”：

- 方案 A 的大数据问题由静态 artifact/CDN 解决，授权服务只发小 window grant。
- 方案 B 的固定密钥复用问题由 session/generation/window ratchet 和 previous-state commitment 缓解；不发送一个永久 build key。
- 方案 C 的传统 dispatch 问题由局部 continuation 和 handler tail 解决；不保存全局 `decode_map`。
- 无 TEE 时，动态捕获仍可恢复当前运行语义，因此攻击矩阵必须保留 `完全逆向 + 硬件级分析：终究可行` 的诚实结论。

### 2.2 严格符合性结论

如果把总设计第 5 节的“❌”理解为“即使攻击者拥有 root、可暂停/修改进程并运行 TTD，也绝对不能完成该攻击”，那么本架构在无 TEE、无服务端关键操作的当前约束下**不能完全符合**。差异不是实现细节，而是信任边界不同：总设计矩阵描述的是目标安全结果，本架构描述的是普通 CPU 上可落地的成本、复用和失效边界。

严格审计如下：

| 总设计矩阵项 | 严格状态 | 原因和剩余缺口 |
|---|---|---|
| 静态提取密钥/索引 | 基本符合 | artifact 不含执行密钥和全局 map；仍需最终 ELF/section/符号审计证明 |
| 静态 patch 写死 index | 结构上符合，root 下不绝对 | 不存在固定全局 index；但 root 可 patch continuation、保护入口或失败分支，不能声称“无分支可 patch” |
| 动态读一次写死 | 条件符合 | session/window/generation 可让旧材料跨会话失效；root 仍可记录当前会话并 patch 本地状态机 |
| 离线运行 | 对静态 artifact 符合，对受控 root 客户端不绝对 | 离线无 grant 不能正常解密；root 可修改本地 fail-closed 路径，除非未来引入不可控外部权威 |
| 假服务器 | 协议层符合 | immutable trust bundle 和签名校验可拒绝假服务器；生产部署、证书/密钥运维仍需验收 |
| 抓包重放 | 协议层符合，对本地 root 不绝对 | counter、session、previous-state 和 server replay fence 拒绝网络重放；root 可在本地伪造消费结果 |
| patch 派生函数 | 部分符合 | 分布式派生、用途分离、短生命周期提高成本；没有 TEE 时仍可被完整逆向和 patch |
| dispatch 点记账 | 基本符合成本目标 | 不存在单一全局 dispatch；TTD 仍可收集多个 continuation/handler 边界 |
| 单步全 dump | 部分符合成本目标 | W^X、短窗口和 deadline 降低稳定复用价值；root 仍可暂停并读取当前进程 |
| 完整逆向 + 硬件级分析 | 符合 | 明确接受“终究可行”的天花板 |

因此本文不能把第 5 节的全部 `❌` 原样复述为当前方案已实现。若项目必须满足矩阵中对 root+TTD 也成立的绝对语义，仍缺少至少一个普通进程无法篡改的信任边界：TEE/硬件执行、远端权威操作或其他独立安全处理环境。当前已批准的方案选择不引入它们，所以交付验收应使用上表“严格状态”，不得使用“已彻底抵抗 root+TTD”的结论。

## 3. 组件和进程结构

### 3.1 单 ELF 交付边界

正式交付只有一个受控 ELF 入口。Guardian/Worker 可以是不同编译单元、不同 section 或不同内部入口，但不能依赖 `/data/local/tmp`、普通可写目录或可替换外部 helper 作为安全信任根。

逻辑组件：

```text
xovm_bootstrap / launcher
    ├── Guardian role
    └── Worker role
```

启动路径：

```text
受控 ELF 入口
  -> 校验目标 artifact/自身边界
  -> 创建 socketpair、随机 boot nonce 和受控 FD
  -> 启动 Guardian role
  -> Guardian 完成 session.open 和首个 window 授权
  -> 启动或 exec Worker role
  -> Guardian/Worker 双向 challenge
  -> Worker 完成内部握手后才进入业务 main
```

直接运行 Worker 内部入口必须失败：缺少受控 FD、boot nonce、当前 session、window grant 或 Guardian channel 时，在保护业务副作用前同步失败。

`su` 只负责启动受控 ELF，不作为安全信任根。不向第三方 `su` 进程注入线程，不依赖其生命周期，不把 ptrace 关系或外部进程内存当成授权状态。root 可以终止、patch、伪造或替换所有普通世界进程，这属于明确威胁边界。

### 3.2 Guardian

Guardian 负责：

- `session.open`、`session.renew`、`session.close`；
- 保存最小 session、counter、generation 和 lease 状态；
- 在原始 `t0+110s` 开始有界获取下一代 window 材料；
- 维护服务端 replay fence 和响应重试；
- 监视 Worker 存活、启动 epoch、process start identity 和 IPC 状态；
- 向 Worker 发送当前允许的 window grant；
- 在 shutdown 时先阻止新 window，再回收 channel 和请求。

Guardian 不执行保护业务，不保存完整 bytecode、完整 handler bundle 或全局 decode map，不在网络请求期间持有 Worker 执行锁。

### 3.3 Worker

Worker 负责：

- 业务 `main`；
- 当前 region 的保护入口；
- pin 当前 generation/window；
- 按需解密有限 bytecode block 和 handler shard；
- W^X/JIT buffer 生命周期；
- continuation tail 和 chaff；
- 正常返回、同步 fault 和窗口清理。

Worker 不生成 generation，不延长 lease，不访问长期 signing key，不接受无 Guardian channel 的外部 package 注入。

### 3.4 Guardian/Worker 相互验证

使用受控 `socketpair`/继承 FD，不使用环境变量、命令行 token 或普通临时文件传递启动授权。

Guardian challenge 至少绑定：

```text
boot_nonce
session_id
generation
challenge_counter
worker_nonce
previous_state_digest
```

Worker response 至少绑定：

```text
challenge_id
process_start_identity
current_generation
current_window_id
state_digest
worker_nonce_response
```

Worker 同时验证 Guardian 的 session epoch、generation 连续性、window grant 绑定和 channel peer credentials。challenge 是故障检测与绕过成本层，不是 root 之上的不可伪造信任根。

## 4. 静态 artifact 与小窗口材料

### 4.1 静态 artifact

大体积内容可以随 ELF/APK/CDN 分发，并按 content hash 缓存。artifact 的内容包括：

```text
EncryptedVmArtifact
    artifact_hash
    build_id
    region_id
    vm_format_version
    encrypted bytecode blocks
    encrypted handler shards
    continuation descriptors
    relocation descriptors
    public ABI/layout descriptor
    non-secret integrity commitments
```

artifact 不包含：

```text
明文 bytecode
明文 handler
完整全局 opcode/handler map
session root material
perm_seed
decode_salt
chaff_seed
integrity_salt
```

artifact 可以被复制，不能脱离有效 session/window 材料完成保护执行。

### 4.2 WindowGrant

授权服务只返回小窗口材料：

```text
WindowGrant {
    format_version
    build_id
    region_id
    session_id
    generation
    window_id
    previous_state_hash
    next_state_hash
    issued_at
    expires_at
    key_version
    encrypted_window_material
    grant_hash
}
```

`encrypted_window_material` 只覆盖当前有限 continuation block、有限 handler shard、当前窗口解码盐、chaff 参数和 integrity 参数。不包含完整函数 bytecode、完整 handler bundle、完整未来 window key 或完整 decode map。

窗口粒度优先采用 superinstruction group/continuation block/敏感函数阶段，初始实现不得假设每条指令一次网络请求。窗口大小是性能和捕获成本的测量参数，不在本规格中虚构安全数值。

### 4.3 状态推进

每个窗口必须满足：

```text
H(previous_state || session_id || generation || window_id || region_id)
    == grant.previous_state_hash
```

成功消费后只允许推进到认证的 `next_state_hash`。跳过窗口、重复使用已消费 window、跨 region 使用 window 或将旧 generation 接入新 session 都必须拒绝。

这不是不可绕过的本地状态机；它的作用是让一次捕获的 window 不直接成为完整长期执行凭据，并让服务端可以对未来窗口和高风险行为进行吊销/限速。

## 5. 材料派生和租约

### 5.1 传输层

继续使用现有协议基础：

```text
X25519-Ed25519-HKDF-SHA256-AES256GCM
```

传输层验证顺序保持：canonical/schema、pending request、签名、X25519 非零、HKDF、AEAD、payload hash、binding、期限、generation/counter、原子发布。

传输层密钥不能直接作为长期 VM 执行 root key。

### 5.2 用途分离

通过认证 response 后，短生命周期地派生用途材料：

```text
M_session
    ├── M_window
    ├── M_perm
    ├── M_decode
    ├── M_chaff
    ├── M_integrity
    └── M_jit
```

每个派生使用独立 domain label，并绑定：

```text
build_id
region_id
session_id
window_id
previous_state_hash
key_version
```

派生后清理共享秘密和不再使用的中间 buffer。生产 API 不暴露“注入未认证 root material”的入口。

文档不宣称完整共享秘密从未在密码库内部短暂存在；只要求它不进入长期 session struct、WAL、SQLite、日志、core dump 或稳定可复用的执行对象。

### 5.3 120/110 秒租约

对 B/lease：

```text
t0             = 第一次提交该逻辑请求前的 BOOTTIME
renew_at       = t0 + 110s
deadline       = t0 + 120s
```

行为：

- `now < renew_at`：当前代可被新调用取得；Guardian 可预取下一代。
- `renew_at <= now < deadline`：新代获取在途；旧代仍可被新调用取得，已 pin 调用继续。
- `now >= deadline`：旧代禁止新 acquire；已 pin 调用允许完成；无新代的保护入口同步失败。

同步获取预算、原始 `t0`、重试 request_id/nonce、后台失败不 kill 的规则沿用已批准协议规格。A/session 不自动变成 B/lease；C/operation 在具体业务专项批准前明确拒绝。

## 6. Bytecode、handler 和 JIT 数据流

### 6.1 Bytecode

编译期：

```text
LLVM IR
  -> logical VM representation
  -> instruction boundary/operand descriptor
  -> encrypted bytecode blocks
  -> private registration + public identity
```

运行期：

```text
当前 continuation
  -> 取得当前 block material
  -> 校验 block AAD/commitment
  -> 解密有限 bytecode block 到临时 RW/non-executable buffer
  -> 读取有限指令/操作数
  -> 清理 block 明文和 block key
  -> 由 handler tail 推进下一 continuation
```

不得把完整 bytecode 解密到长期 `MaterialStore`。不得从客户端保存的 static artifact 猜测 opcode 边界；边界来自版本化、认证的 continuation descriptor。

### 6.2 Handler

每个 handler shard 包含：

```text
encrypted machine code
authenticated descriptor
allowed relocation entries
ABI/variant identity
next-tail metadata commitment
```

最终 ELF 不保留明文 handler。构建工具必须在最终 AArch64 ELF 上验证：

- PC-relative relocation 范围；
- 外部调用只经过批准 ABI；
- 不存在未声明的绝对地址/指针；
- 机器码长度和 descriptor 一致；
- 加密后无法从 section/符号恢复明文 handler。

### 6.3 JIT/W^X buffer

运行期流程：

```text
分配 RW、不可执行 buffer
  -> 解密一个 handler
  -> 应用受允许 relocation
  -> 切换 RX
  -> flush instruction cache
  -> 执行
  -> 返回清理路径
  -> 切换回 RW
  -> 清除明文和 key
  -> 隔离/释放 buffer
```

禁止 RWX。当前 handler 执行期间不能擦除自身指令；线程、递归和嵌套调用不能复用仍 active 的 buffer。EH/longjmp/非局部退出没有明确清理证明时必须编译失败或明确拒绝。

### 6.4 Continuation 链

最终热路径不使用：

```text
global_handler_table[opcode]
switch(opcode)
central_dispatch(opcode)
```

每个 handler 尾部只处理当前局部 continuation 和有限下一跳：

```text
当前 handler
  -> 读取当前有限 bytecode block
  -> 计算下一 continuation commitment
  -> 取得下一局部 handler shard
  -> JIT 解密
  -> 直接跳转
```

可以存在公共的密码学、分配和 W^X 辅助函数，但不能存在一个解释全部 opcode 的集中式语义 dispatch。编译器/独立 ELF 审计必须检查最终机器码和引用关系，而不是只检查 IR 函数名。

## 7. Chaff 与完整性

### 7.1 Chaff

`M_chaff` 只决定当前 window 内的诱饵插入位置和 variant：

```text
真实 continuation
  -> 可选 chaff handler
  -> 清除 chaff buffer
  -> 返回真实 continuation
```

chaff 不得改变业务内存、返回值、异常、浮点状态、外部调用、文件/网络副作用或持久日志。chaff 是动态轨迹污染层，不是授权或完整性边界。

### 7.2 Integrity

`M_integrity` 可参与下一 continuation/window 的派生和完整性 commitment，避免形成一个孤立的：

```text
if (valid) execute(); else fail();
```

但是冷路径仍必须明确拒绝：协议版本错误、签名错误、AEAD 错误、build/region/session/generation 不匹配和过期材料。错误材料不能进入未认证的可执行缓冲，也不能用随机崩溃替代内存安全边界。

## 8. C++ 云端程序与开发/生产模式

### 8.1 选择 C++ 的范围

云端程序采用独立的 C++20 backend，不把生产依赖接入 LLVM 根构建。职责分为：

```text
xovm-cloud-core
    canonical protocol
    registration/snapshot
    policy
    session/replay/generation
    window grant state machine
    response sealing

xovm-cloud-server
    raw TCP socket boundary
    admin route
    trust route
    health/readiness
    provider loading
```

当前 C++ relay backend 的 SQLite/WAL/snapshot/session 基础设施优先复用。window builder/provider 是新增接口，不能把完整 window bundle 重新塞回旧 `ParsedPackage`/`decode_map` 结构。客户端网络热路径不使用 libc 的 `socket/connect/send/recv` 包装器；这不要求整个客户端 ELF 脱离 `libc.so`，也不要求云端 C++ 服务器脱离 libc。

### 8.2 Debug 模式

开发阶段允许本地运行 C++ cloud server：

- 使用临时 test key、test trust bundle、fake clock、synthetic registration；
- 只监听 loopback；
- 使用明确的 debug build/profile 编译宏或配置；
- 允许 fault injection、协议日志摘要和测试 provider；
- 不允许把 debug provider、私钥、fixture token 或 fault hook 编译进 production artifact；
- debug artifact 的 `build_id`/`vm_format_version` 与 production artifact 不相同；
- debug server 不能被生产 client 的 trust configuration 接受。

### 8.3 Production 模式

生产构建必须：

- 关闭 debug provider、fault injection、材料明文日志和本地 root bypass；
- 从外部 secret/key provider 注入 signing key、trust root、relay credential；
- 启动自检缺少 provider、policy、trusted time、key 或 migration 时 fail closed；
 - 只暴露 raw TCP listener；客户端不使用 HTTP/HTTPS/TLS 库；
- 生产 endpoint/origin、software ID、protocol/version 和 trust bundle 作为独立 release 配置绑定；
- 不接受 localhost/debug origin、debug trust epoch 或 debug artifact identity。

开发服务器与生产服务器可以使用不同 endpoint，也可以使用不同编译目标地址，但“改一个地址就变生产”不是安全边界。生产/调试必须是不同 profile、不同 trust bundle、不同 artifact identity 的明确构建产物；不得在生产二进制中留下可切换到本地 debug server 的隐藏开关。

### 8.4 目标地址和客户端配置

允许编译阶段为 debug/production 注入不同的 backend origin，但必须同时绑定：

```text
profile
software_id
trust bundle
artifact/build identity
allowed protocol version
```

客户端不能接受服务端响应中的新 origin、新 trust root 或任意 redirect。生产 endpoint 变更必须通过新的受信配置/发布流程完成，不使用运行期环境变量覆盖。第一版客户端使用编译期绑定的 IP/端口，不实现 DNS；地址变更通过签名配置或新版本发布完成。

## 8.5 Raw socket 与应用层加密协议

TLS/HTTP 不属于客户端协议要求。客户端网络层使用直接 TCP socket 和应用层认证加密；服务端仍可使用普通 C++20、libc、SQLite 和独立的 TCP listener。

客户端网络层分为四层：

```text
xovm_sys_socket
    AArch64 syscall: socket/connect/send/recv/close

xovm_frame
    fixed header
    length framing
    per-direction sequence
    size/time limits

xovm_crypto
    X25519 ephemeral exchange
    Ed25519 server authentication
    HKDF-SHA256 key separation
    AES-256-GCM or ChaCha20-Poly1305

xovm_api
    login
    announcement
    update
    algorithm material
    remote variables
```

这只绕过常见的 libc 网络包装器 hook，不是 root 环境下的不可观察边界。root 仍可能在 syscall 指令、进程内存、AEAD 前后缓冲区或内核网络层观察和修改通信。

### 握手

客户端发送 `HELLO`：

```text
magic
protocol_version
software_id
build_id
client_nonce
client_ephemeral_x25519_pub
request_id
supported_cipher_suite
```

服务端返回 `SERVER_HELLO`：

```text
protocol_version
session_id
server_nonce
server_ephemeral_x25519_pub
counter
key_version
expires_at
server_signature
```

服务端 Ed25519 签名覆盖完整 transcript。客户端只接受编译期绑定的 trust bundle，不接受服务端下发的新 trust root、origin 或任意 redirect。

双方计算：

```text
Z = X25519(client_ephemeral_private, server_ephemeral_public)
transcript_hash = Hash(all_handshake_fields)
K_root = HKDF(Z, transcript_hash, "xovm/raw-socket/session")
```

再用独立域标签派生：

```text
K_c2s
K_s2c
K_material
K_control
```

业务数据不直接使用 `K_root`。所有帧使用 AEAD，帧头作为 AAD，并绑定 `transcript_hash`、方向、`key_version` 和方向独立 sequence。必须拒绝重复/回退 sequence、错误 session、错误 AAD/tag、过期 session、超大 payload 和已消费 request_id。

### 功能面

云端只保留以下六类客户端业务接口：

```text
ANNOUNCEMENT
UPDATE
ALGORITHM_ACQUIRE
REMOTE_VARIABLES
LOGIN_ACCOUNT
LOGIN_CARD
```

接口职责：

- `ANNOUNCEMENT`：公告版本、优先级、有效期、内容和签名；
- `UPDATE`：更新元数据、hash、分块信息和签名；大文件不由授权状态机重新生成；
- `ALGORITHM_ACQUIRE`：当前动态 VM 的 WindowGrant；
- `REMOTE_VARIABLES`：固定 schema、类型和长度限制的签名变量集合，不允许远程脚本执行；
- `LOGIN_ACCOUNT`：账号认证、会话刷新和登出；
- `LOGIN_CARD`：卡密认证、绑定/解绑和材料权限建立。

复杂 admin API、通用 provider route、任意 operation API、C 模式 operation lease、完整 package 下发、完整 bytecode/decode_map 接口和通用 REST/GraphQL 不属于客户端第一版范围。

账号/卡密认证只在已经通过服务端签名认证的 AEAD session 内发送。卡密不是 VM 材料密钥，也不是长期客户端密钥。账号密码的第一版可以在已认证 AEAD 内传输；生产替换为 PAKE 时不改变外层 frame 格式。

### 可靠传输要求

raw TCP 不提供消息边界。实现必须处理：

- 部分 send/recv；
- 粘包/拆包；
- `EINTR`、超时和连接关闭；
- 最大帧长度；
- IPv4/IPv6；
- 网络切换和 session 重建。

第一版不实现 DNS。若未来需要域名，必须新增受签名配置控制的解析路径，不调用任意系统 DNS 结果作为信任根。

## 9. 当前 package 协议的处置

现有：

```text
encoded_bc
decode_map
static_decode_descriptor
```

保留为：

- v1 canonical parser；
- Node/C++ 跨语言测试向量；
- 当前 relay/backend 的过渡 fixture；
- 历史行为对照。

不得继续把它扩展为最终 VM 执行接口，也不得在新 dynamic VM witness 中声称它满足 handler 加密、JIT、chaff 或无全局 dispatch。

新格式至少需要升版本并冻结以下概念：

```text
EncryptedVmArtifact
WindowGrant
ContinuationWindow
HandlerShard
JitExecutionBuffer
GuardianChannel
```

在这些结构的字段、哈希前像、窗口推进、错误边界和生产 provider contract 获得独立审查前，不修改当前 v1 wire schema 以伪装兼容。

## 10. 实施前置条件和验证矩阵

### 10.1 必须先完成的设计审查

实现前必须单独冻结：

1. encrypted artifact 的构建/发布/验证格式；
2. WindowGrant 的 canonical schema、AAD、hash 和 replay fence；
3. continuation descriptor 和有限窗口边界；
4. AArch64 handler relocation/ABI/W^X 规则；
5. Guardian/Worker FD 握手和 challenge 状态机；
6. B 模式 `t0+110s/t0+120s` 及无材料同步 fault 边界；
7. debug/production C++ provider 和 trust 配置隔离；
8. root+TTD 能力边界和报告措辞。

### 10.2 必须通过的测试

- 静态 ELF 不含明文 handler、完整明文 bytecode、全局 decode map 和生产秘密；
- artifact 无 window grant 不能执行；
- window grant 绑定错误 build/region/session/generation/window 时拒绝；
- previous-state 不匹配、重复 window、跳过 window、过期 window 均拒绝；
- 有材料时结果和副作用正确；
- 无材料时保护入口同步失败且业务副作用为 0；
- `t0+110s` 续期、`t0+120s` 新调用拒绝、119 秒 pin 调用完成；
- Guardian/Worker 任一方直接启动、FD 替换、challenge 重放、generation 回退均失败；
- JIT 遵守 W^X，handler 执行后明文清理；
- chaff 不改变业务结果和副作用；
- central dispatch 和全局 handler map 不出现在最终目标结构中；
- debug cloud server 的 key/trust/artifact 不能被 production client 接受；
- C++ server 缺 provider 时不监听；
- C++ server 本地 debug 模式可使用 fake clock 和 fault injection，但生产 profile 没有这些入口。

### 10.3 攻击报告边界

必须分别报告：

```text
静态恢复失败/成功
跨 session 复用失败/成功
旧 window replay 失败/成功
动态捕获当前运行成功/失败
Guardian bypass 成功/失败
TTD 恢复当前业务语义成功/失败
工具错误
环境阻塞
```

不能把：

- 无关 SIGTRAP；
- 进程崩溃；
- 字符串不存在；
- 一次正常过期拒绝；

单独报告成“架构已抵抗 TTD”。

## 11. 分阶段实施顺序

### Phase 0：设计冻结

- 审核本文；
- 冻结 artifact/window/continuation/Guardian channel schema；
- 保持现有 v1 package 不变；
- 为 C++ cloud server 增加 debug/production provider contract 文档，不先接生产密钥。

### Phase 1：静态 artifact 和窗口格式

- 构建加密 bytecode block/handler shard；
- 编写独立 verifier；
- 证明最终 ELF 不含明文 handler/bytecode；
- 实现 C++ debug server 的 window grant 生成。

### Phase 2：Guardian/Worker 启动和租约

- 单 ELF launcher；
- socketpair/受控 FD；
- challenge/response；
- 110/120 秒 lease；
- 无材料同步 fault；
- fork/exec/退出和 shutdown 回归。

### Phase 3：Continuation/JIT 执行

- handler tail；
- W^X buffer；
- AArch64 relocation/cache flush；
- 有材料/无材料真实 native fixture；
- 不实现全局 decode map。

### Phase 4：Chaff 和完整性

- window chaff schedule；
- side-effect neutrality；
- integrity commitment；
- 动态 trace 成本实测。

### Phase 5：生产 C++ cloud server

- trusted time；
- signing/CSPRNG provider；
- policy/admin/trust bundle；
- production config；
- TLS/reverse proxy/deployment；
- live acceptance。

Phase 5 前不得宣称生产 ready。无 TEE 和无服务端关键操作时，不得宣称 root+TTD 不可恢复。
