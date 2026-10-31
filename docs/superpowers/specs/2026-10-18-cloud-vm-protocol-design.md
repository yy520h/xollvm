# Cloud VM material v2：协议、身份与部署适配子规格

日期：2026-10-18。任务：foundation plan Task 0。

状态：**2026-10-18 controller 与独立 reviewer 专项审核通过，冻结为基础阶段实现契约**。用户已授权连续实施与可逆细节裁决；I1 按总规格 §8 校正评审依据，M1 重试调度说明经 fix round 1 复审通过。此批准仅针对协议文档，不代表产品实现完成或生产可用。

权威上位规格：`2026-10-18-cloud-vm-material-design.md`；任务接口来源：`../plans/2026-10-18-cloud-vm-foundation-plan.md` §0–2。本子规格补全其概念结构；wire 字段与哈希前像以本文为准。批准后的破坏性变更必须升协议/格式版本，不能让两端各自猜测。

## 1. 范围、套件与信任边界

基础阶段支持 A=`session`、B=`lease`，在同进程按区域混合。C=`operation` 可登记为策略，但所有材料请求明确返回 `operation_not_implemented`，不分配材料/代号，不降级为 A/B。C 的输入规范化、服务端必要步骤与提交幂等必须另有专项协议；本协议没有可以假装启用 C 的可选字段。

唯一协议版本 `protocol_version=2`；唯一套件字符串：

```text
X25519-Ed25519-HKDF-SHA256-AES256GCM
```

- 每个**新逻辑请求**双方各生成一次新的 X25519 临时密钥；完全相同请求的传输重试复用原客户端临时密钥，服务端返回已提交的原响应字节。
- Ed25519 服务签名密钥只做签名，不作 X25519 使用；离线信任根与在线签名密钥也分离。使用纯 Ed25519，非 Ed25519ph/ctx。
- HKDF-SHA256 为 RFC 5869 的 extract+expand；AES-256-GCM 使用 32 字节 key、12 字节 IV、完整 16 字节 tag，无截断。
- 生产必须使用经宿主认证的 HTTPS 传输，验证证书/目标服务，不跟随跨源重定向。协议签名独立认证材料，TLS/宿主凭据认证客户端；软件 ECDH 本身不认证客户端。
- 请求没有卡密、token、`device_id` 或客户端自报 `auth`。这些仅由宿主安全渠道处理。`software_id` 是路由/绑定值，必须与可信身份相等。
- 基础执行包不是机器码；认证后只可进入版本匹配的 VM，不能当作 native handler/JIT 内容执行。

双方临时私钥在完成/放弃请求后销毁，服务端提交响应后无需保留临时私钥。仅在密钥确实销毁且未被捕获时，历史传输对**后来单独泄露在线 Ed25519 私钥**具有前向保密；泄露注册材料、捕获端点明文/临时密钥、进程回滚不在该保证内。Node GC、软件清零与非 HSM 环境不构成硬件隔离承诺。

## 2. 字节约定、规范 JSON 与硬限制

### 2.1 基本类型

下文所有对象都是**封闭对象**：表格/结构列出的字段恰好出现一次，全部必需；未知字段、缺字段、`null`、隐式默认值均拒绝。不同消息类型使用明确的不同字段集合；不传空串代替缺失字段。

| 记号 | 精确定义 |
| --- | --- |
| `U32` | JSON number，十进制 `0` 或 `[1-9][0-9]*`，值不超过 4294967295；字段再施加较小范围 |
| `U64` | JSON **string**，内容为 `0` 或 `[1-9][0-9]*`，最多 20 字符，值不超过 18446744073709551615；JS 用 BigInt，C++ checked uint64 |
| `H` | 正则 `[0-9a-f]{64}`，SHA-256 的小写 hex；进入密码原语时明确使用 `unhex(H)` 得到 32 字节 |
| `R32` | 与 H 相同编码，但语义为 CSPRNG 产生的 32 字节随机值，非哈希；全零拒绝 |
| `Id` | `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`，1–64 ASCII 字节；大小写敏感，不 trim/normalize |
| `Name` | `[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}`，1–128 ASCII 字节；region 名只用于可读身份 |
| `B64(n)` | RFC 4648 标准 alphabet `A–Z a–z 0–9 + /`，必要的 `=` padding，无空白；解码恰好 n 字节，重新编码必须完全相同 |
| `Mode` | 恰好 `session`、`lease`、`operation` 之一；运行材料只支持前两个 |

时间戳 `*_at_ms`、`*_until_ms` 是 UNIX epoch 毫秒 `U64`；时长 `*_ms` 是字段范围内的 `U32`。仅用于服务端时序与签名期限检查，不用客户端可修改墙钟延长本地期限。

### 2.2 Canonical encoding `C(value)`

1. JSON 的对象、数组、上述整数、ASCII 字符串、布尔值可编码；本规格未使用布尔值的具体 schema 不能接受它代替整数。无浮点、负数、`-0`、指数、NaN/Infinity。
2. 所有对象键匹配 `[a-z][a-z0-9_]{0,63}`，按 ASCII 字节升序排序，递归编码；数组保持顺序。对象键不能按 locale 排序。
3. 字符串只允许 U+0020–U+007E；编码时只有 `"` 与 `\` 分别写成 `\"` 与 `\\`，其余 ASCII 原样，包括 `/`。不输出 `\u`。实际字段仍受更严格 regex 约束。
4. UTF-8，无 BOM、空白、尾随换行/数据；逗号和冒号两侧无空白。
5. 解码先限制总长度、深度和 token 长度，严格 UTF-8，逐层拒绝重复键；再验证 schema 并重编码。必须 `C(decoded) == original bytes` 才接受。禁止用 replacement character 修复非法 UTF-8。
6. Node 的 `JSON.parse` 不能单独承担 duplicate-key/资源限制检查；必须先有受限 token 扫描或流式解析。C++ JSON SAX 同样提前限制。不能先分配任意深对象再检查。

例：对象 `z="18446744073709551615", a=1` 的唯一编码是：

```text
{"a":1,"z":"18446744073709551615"}
hex = 7b2261223a312c227a223a223138343436373434303733373039353531363135227d
```

`{"a":1,"a":2}`、`{"a":1.0}`、`{"a":1e0}`、`{"a":-0}`、带空格版本、`{"z":"\u0031"}` 都拒绝；即使通用 JSON parser 得到同值也不能接受。

### 2.3 限制（MiB=1048576，包含边界）

| 对象/资源 | 上限或约束 |
| --- | --- |
| 请求体 Q | 8192 字节；HTTP Header 总量另限 16384 字节 |
| 原始成功响应 E | **16777216 字节（16 MiB）**，流式读取过程中强制，不信任 Content-Length |
| 解密明文 P / 原始 ciphertext | 各 **11250348 字节**；控制明文仅 4096 字节 |
| 原始 bytecode | **8388608 字节（8 MiB）**，至少 1 字节；base64 最大 11184812 字符 |
| 包中除 encoded_bc 字符串外的总开销 | 65536 字节（包含其他 JSON 语法） |
| decode_map | 恰好 256 个 U32；每项 0–255 或 65535 |
| wire 对象嵌套 | 根深度 1，最大 8；单对象最多 40 键；wire 单数组最多 256 项 |
| 单字段普通字符串 | 256 字节，除按上述长度校验的 base64 与 Name |
| public manifest | 4 MiB；1–4096 区域；递归深度 8 |
| 单个私有 CanonicalRegion | 192 MiB；offset/opcode 数组各最多 8388608 项；逐项流式校验 |
| 单次私有登记包 | 512 MiB；超过则拒绝并拆分构建，禁止无界 JSON DOM |
| 私有 decode descriptor | canonical bytes 不超过 4096 字节 |
| trust bundle | 65536 字节，最多 64 个签名 key 记录 |

base64 分配前检查 ASCII 长度为 4 的倍数、padding 位置/位规范及 `decoded_len=3*(len/4)-padding`，checked arithmetic 后再分配。两层 base64 的保守响应上界为 `4*ceil(11250348/3)+65536=15066000`，小于 16 MiB。拒绝 HTTP 压缩（`Content-Encoding` 必须 absent 或 `identity`），避免压缩解包绕过上限。原始登记包是单独的管理员渠道，不适用 wire 16 MiB 上限。

## 3. 身份、登记包与最终产物：无递归哈希

### 3.1 通用 framing

`SHA256(bytes)` 返回 32 字节；`hex(bytes)` 为小写 hex。定义：

```text
F(label, p1, ..., pn) = ASCII(label) || 00 ||
                       BE32(len(p1)) || p1 || ... || BE32(len(pn)) || pn
```

label 在本文逐一固定，无 NUL；`BE32` 为 4 字节无符号大端。无额外参数个数，无终止符，无最后换行。每个 label 的参数数量由下面公式固定。符号 `...` 仅是数学重复记号，不是可省略 wire 字段。

### 3.2 CanonicalRegion

私有 `RegionCore` 的**全部字段**：

```text
format_version: 1
isa_version: U32 (=1 in foundation)
target_triple: "aarch64-linux-android26"
region_name: Name
mode: Mode
canonical_bc: B64(bytecode_size)
bytecode_size: U32 (1..8388608)
instruction_offsets: U32[]
logical_opcodes: U32[]
opcode_count: U32 (1..256)
engine_abi_hash: H
register_counts: U32[] (1..32 entries, each 0..65535)
call_abi_hash: H
layout_hash: H
static_decode_descriptor: DecodeDescriptor
```

`DecodeDescriptor` 恰好为 `{decode_salt:U32, isa_version:1, layout_hash:H, operand_encoding_hash:H}`。`isa_version/layout_hash` 必须与 region 相等。这里的 ABI/layout/operand hashes 是编译器对其版本化规范描述字节的 SHA-256 承诺（**不是本机 struct 内存、地址或可读名字的 hash**）；VM 格式实现必须能重算并验证这些描述。寄存器数组下标代表该 ABI 描述中的 register bank；不会从数组长度猜 ABI。传输仅承诺和比较这些摘要，不重新定义 LLVM ISA。

offsets 从 0 开始、严格递增、都小于 bytecode_size，长度与 logical_opcodes 相等且非空；logical opcode 在 `[0, opcode_count)`，允许该域中有本区域未用的 opcode。导出器提供真实指令边界，验证器按版本化 VM 格式验证分支/CALL/变长尾。相同 logical opcode 必须映射到相同构建 byte，不同 logical opcode 的构建 byte 不同。只在这些 offsets 置换 opcode，禁止扫描每个 byte 猜边界。

```text
region_content_hash = hex(SHA256(F("XOVM2/region-content", C(RegionCore))))
RegionIdentity = {format_version:1, region_name, region_content_hash,
                  engine_abi_hash, call_abi_hash, layout_hash, mode, target_triple}
region_id = hex(SHA256(F("XOVM2/region-id", C(RegionIdentity))))
CanonicalRegion = RegionCore + {region_content_hash, region_id}
```

`+` 表示添加指定新成员，不覆盖已有键；`RegionCore` 本身没有 region_id、region_content_hash、build_id。region_id 不依赖 build_id；一个 build 内 region_id 与 region_name 都唯一。多 TU 相同完整 CanonicalRegion 可在聚合时去重；同名不同内容失败。具有同名函数但不同业务/ABI/模式时身份不同。

### 3.3 Public manifest / private registration

`PublicRegion` 恰好为 `{region_id, region_content_hash, region_name, mode, engine_abi_hash, call_abi_hash, layout_hash}`，值与相应 CanonicalRegion 相等。`PublicCore`：

```text
format_version: 1
protocol_version: 2
vm_format_version: 1
target_triple: "aarch64-linux-android26"
software_id: Id
regions: PublicRegion[] (1..4096, region_id ASCII ascending, no duplicates)
```

```text
build_id = hex(SHA256(F("XOVM2/build-id", C(PublicCore))))
PublicManifest = PublicCore + {build_id}
PrivateRegistration = {format_version:1, build_id, regions:CanonicalRegion[]}
```

私有 regions 与公开数组同序且一一对应，不允许遗漏或额外区域。服务端重算全部身份和 bytecode 配对关系，不能信任上传的 hash 声明。秘密的生成不使用 obfuscation seed；仅输入字节完全相同时内容身份可复现。实际秘密不同导致内容摘要变化是正常现象。

PublicCore/Manifest **没有** final_artifact_hash、seal_hash 或私有 bytecode/descriptor；不是把这些字段置零后算 hash。public/private 成员集合混用立即拒绝。

### 3.4 最终产物和发布顺序

`final_artifact_hash = hex(SHA256(final verified ELF file bytes))`，是对最终文件逐字节的普通 SHA-256，无域前缀，无排除范围。顺序：link → materials 回填 build_id → targets → audit → 最终 strip（如需要）→ seal → verify → 计算 final_artifact_hash → 管理员 enableBuild → 原子发布文件。

`ReleaseRecord={format_version:1,build_id,final_artifact_hash,software_id}` 单独在服务端保存并随可信发布渠道交付为 sidecar；**不回写 ELF/manifest/seal**。一个 build_id 仅允许一个已启用 final_artifact_hash；相同 pair 重试幂等，不同 hash 拒绝，必须重新准备新构建身份（例如新 software release 的实际编译内容）。本基础协议不支持在同一 build_id 上替换发布文件。

客户端 transport 从验证过的安装包元数据读取 final_artifact_hash，并对安装 ELF 文件重新计算；不能 hash 已重定位的内存映像。宿主如果不能可靠提供最终文件/元数据，初始化失败。请求中的摘要只是配对约束，**不等于设备完整性远程证明**；服务端仍核对管理员启用的 pair。摘要总是进入请求和响应 transcript。

### 3.5 ELF `.rodata.xovm.material` 固定格式（Task 3B）

只接受 ELF64 little-endian AArch64。section 是 N 个连续 **120 字节**记录，1≤N≤4096；大小必须恰好 `120*N`，无记录间 padding/尾随字节。每条记录：

| section 内相对记录起点偏移 | 字节数 | 内容 |
| --- | --- | --- |
| 0 | 8 | magic `58 4f 56 4d 4d 41 54 00`（`XOVMMAT\0`） |
| 8 | 2 | little-endian version=1 |
| 10 | 2 | little-endian header_size=16 |
| 12 | 4 | little-endian record_size=120 |
| 16 | 4 | little-endian descriptor abi_version=1 |
| 20 | 4 | little-endian mode：1=session，2=lease，3=operation |
| 24 | 32 | raw build_id；仅未 finalization 时允许全零 |
| 56 | 32 | raw region_id |
| 88 | 32 | raw engine_abi_hash |

wrapper 指向记录的 offset 16，即 104 字节 `XovmRegionDescriptor`；编码器按字段写字节，解析器不 memcpy 宿主 padding。目标代码需 static_assert 字段偏移/尺寸。编译器保留 section 和引用，链接器保持 section（不可被 strip/GC 移除）。finalizer 先验证全部记录的唯一 region、mode、ABI 与 manifest 集合完全相等，再统一回填；同 ID 已回填幂等，部分冲突失败不发布。最终 runtime 拒绝全零 build_id。此布局不改变内存中的 `XovmMaterialView` C ABI。

## 4. 配对执行包、package_binding 与哈希

`PackageBinding`（本文也称 `package_binding`）恰好为：

```text
build_id: H
region_id: H
session_id: R32
generation: U64 (1..UINT64_MAX)
request_hash: H
mode: "session" | "lease"
lease_ms: U32 (session=0; lease=1..120000)
engine_abi_hash: H
```

`makePackage(region, package_binding, randomBytes)` 输入没有 package_hash。`PackageCore` 恰好为：

```text
format_version: 1
binding: PackageBinding
bytecode_size: U32 (1..8388608)
encoded_bc: B64(bytecode_size)
decode_map: U32[256]
static_decode_descriptor: DecodeDescriptor
```

```text
package_hash = hex(SHA256(F("XOVM2/package", C(PackageCore))))
MaterialBinding = PackageBinding + {package_hash}
ExecutionPackage = PackageCore with its binding replaced by MaterialBinding
P = C(ExecutionPackage)
payload_hash = hex(SHA256(P))
```

只有 **binding 的直接成员 package_hash** 从 package_hash 前像中移除；其他任何字段不能移除/置零。payload_hash 对完整 P 计算，但不存入 P。最终 transcript 同时带完整 MaterialBinding 和 payload_hash。依赖顺序严格是 request → PackageBinding → PackageCore → package_hash → P → payload_hash → transcript → ciphertext → signature，没有环。

配对生成使用无偏 Fisher–Yates / rejection sampling 在 256-byte 域选不同编码；decode_map[本代 byte] = 构建 physical opcode，其余=65535；有效 map 值互异，有效项数=本区域 logical_opcodes 的不同值数量（不超过 opcode_count）。仅对 instruction_offsets 改字节，操作数/分支位置不变；反映射恢复的每字节必须等于 canonical_bc。服务端对 CanonicalRegion 验证这些配对性质；客户端不持规范业务副本，只验证已认证包的格式、ABI 和 VM 安全边界。不得把随机传输 IV 当作字节码已随机化的证据。重复随机映射在数学上可能出现；跨代检查覆盖实际编码，不能用无限重抽样承诺不可能碰撞。

解密解析器验证所有长度、256 项 map、descriptor、版本、完整 binding、package_hash、ABI 和执行格式。`parseExecutionPackage` 只产生结构化解析结果；只有密码入口能构造私有的 `VerifiedPackage`。生产 API 无 public bool/构造器允许绕过认证。包摘要不是独立授权证明。

## 5. 请求、响应、错误的封闭 schema

### 5.1 请求 Q 与 request_hash

所有请求公共字段：

```text
protocol_version: 2
suite: "X25519-Ed25519-HKDF-SHA256-AES256GCM"
type: "session.open" | "session.renew" | "session.close" | "material.issue"
software_id: Id
build_id: H
final_artifact_hash: H
request_id: R32
client_nonce: R32
client_ephemeral_key: B64(32)
```

按 type 添加下列**全部**字段；其余类型不带它们：

| type | 额外字段 |
| --- | --- |
| session.open | 无；session_id 必须由服务端产生 |
| session.renew / session.close | `session_id:R32, counter_epoch:R32, previous_counter:U64` |
| material.issue | `session_id:R32, counter_epoch:R32, region_id:H, engine_abi_hash:H, mode:Mode, previous_generation:U64` |

`previous_generation=0` 表示第一次获取，之后为客户端已接受的代号；服务端要求不大于已分配值（允许丢失响应），新分配总是服务端当前值+1。客户端不能指定新 generation。control 的 previous_counter 不大于该 session 最近 control counter；open 的记录为首次值。

```text
request_hash = hex(SHA256(F("XOVM2/request", C(Q))))
```

Q 内没有 request_hash。HTTP method 固定 POST、路径固定 `/xovm/material/v2`、Content-Type 固定 `application/json`，body 恰好 C(Q)。adapter 将 exact body hash 与认证的 method/path/audience 绑定；凭据头不进入 Q/日志/hash。不同 host origin 是不同信任配置，不能复用 pending request。

### 5.2 控制明文

session.open / renew 成功的明文对象恰好：

```text
{format_version:1, session_id:R32, counter_epoch:R32,
 control_valid_for_ms:U32, session_valid_until_ms:U64}
```

control_valid_for_ms 为 1..86400000；close 成功使用相同 schema，时长=0、session_valid_until_ms=issued_at_ms。P 为其 C 编码。控制回应只产生 `VerifiedSessionControl`，绝不能作为材料包。P 的重复 session/epoch/期限值必须与 transcript 的对应值相同。

### 5.3 成功 transcript T

T 恰好包含以下字段（列举顺序非编码顺序，C 自动排序）：

```text
protocol_version: 2
suite: fixed suite string
type: same as Q.type
software_id: Id
build_id: H
final_artifact_hash: H
request_id: R32
request_hash: H
client_nonce: R32
client_ephemeral_key: B64(32)
server_nonce: R32
server_ephemeral_key: B64(32)
server_key_id: Id
trust_epoch: U64
session_id: R32
counter_epoch: R32
counter: U64 (1..UINT64_MAX)
issued_at_ms: U64
auth_valid_until_ms: U64
session_valid_until_ms: U64
accept_for_ms: U32 (1..120000)
payload_hash: H
binding: MaterialBinding | ControlBinding
```

`binding` 对 material.issue 为 §4 MaterialBinding；对控制消息恰好是 `{session_id:R32, request_hash:H, control_valid_for_ms:U32}`。必须依据 type 选 schema，不根据用户传入字段猜类型。

公共请求字段、session_id（open 除外）、epoch（open 除外）都必须与 Q 相同。MaterialBinding 的 build/session/request_hash、mode/region/engine 必须与 T 和 Q 一致；mode 还必须等于注册策略。不得接受同 build 不同 release 的响应。客户端的 pending expected descriptor、安装 release pair、可信软件/服务身份再次比对。

新发放时 `issued_at_ms < auth_valid_until_ms`；open/renew 的 `session_valid_until_ms=issued_at_ms+control_valid_for_ms`，且不晚于 auth_valid_until_ms。material 的 session_valid_until_ms 等于事务内当前会话控制期限，issued_at_ms 必须早于它。close 允许等于 issued_at_ms。所有加法检查 U64 溢出。

材料 B：依据已批准 `2026-10-18-cloud-vm-material-design.md` §8 第132–134行，D≤120秒且服务端可缩短 D；本协议以 `lease_ms = accept_for_ms = min(120000, auth_valid_until_ms-issued_at_ms, session_valid_until_ms-issued_at_ms)` 落实该上限，服务策略可进一步缩短为正数。正的授权/session/key/bundle 剩余窗口可产生短租约，不要求凑满120秒才发放；非正剩余仍拒绝。A：lease_ms=0，accept_for_ms 按同一 min 规则给出**此次响应接收窗口**，不转换为 A 的调用期限。控制消息 accept_for_ms=min(120000,auth 剩余)，open/renew 再限制为 control_valid_for_ms。close 允许 1..120000 的响应接收窗口；已经关闭的 session 不再授权材料。

所有类型的 accept_for_ms 还要缩短到 `min(原值, signer.not_after_ms-issued_at_ms, bundle.valid_until_ms-issued_at_ms)`；任一剩余非正则 key_unavailable。B 的 lease_ms 同步取该缩短值，仍与 accept_for_ms 相等。客户端必须重验所有这些上界，而非只信任一个时长值。

### 5.4 成功 envelope E

```text
{transcript:T, ciphertext:B64(len(P)), tag:B64(16), signature:B64(64)}
```

没有其他字段；IV 从 KDF 得出，不传一个可被替换的 IV 字段。HTTP 200 body=C(E)。响应禁止缓存到共享 HTTP cache，使用 `Cache-Control: no-store`。同请求的服务端幂等缓存是内部持久记录，不是 HTTP cache。

### 5.5 错误

错误 body 恰好 `{protocol_version:2, type:"error", request_id:R32, code:ErrorCode, retry_after_ms:U32}`；尚未通过 schema 的 request_id 不回显，解析/超限错误直接 HTTP 400/413 空 body。错误最长 4096 字节。非 200 永远不能构造 VerifiedPackage。

| HTTP | code | retry_after_ms |
| --- | --- | --- |
| 401 | unauthorized | 0 |
| 403 | revoked, build_unavailable, policy_mismatch | 0 |
| 409 | request_conflict, request_retired, session_closed, counter_epoch_mismatch, generation_ahead | 0 |
| 422 | unsupported_version, unsupported_suite, unsupported_vm, operation_not_implemented, invalid_key | 0 |
| 429 | rate_limited | 1..10000 |
| 503 | authority_unavailable, store_unavailable, key_unavailable, counter_exhausted | 1..10000 |

错误依赖 HTTPS，不额外做 DH/签名。它不能更新时钟、counter、信任根、会话或撤销已发布 A/B 材料；仅表示本次请求未得到材料。不得因错误文本选择 legacy 协议/静态解码路径。日志只有 code、非秘密 ID 与状态，不能输出 P、私有登记包、凭据或完整请求上下文。

## 6. 加密与签名的逐字节定义

### 6.1 固定计算顺序

服务器先完成授权、状态配对与包生成；冻结 P 和 T 后：

```text
TH       = SHA256(F("XOVM2/transcript", C(T)))
Z        = X25519(server_ephemeral_private, raw_client_ephemeral_public)
K        = HKDF-SHA256(IKM=Z, salt=TH,
                     info=F("XOVM2/response-key", TH), L=32)
IV       = HKDF-SHA256(IKM=Z, salt=TH,
                     info=F("XOVM2/response-iv", TH), L=12)
AAD      = F("XOVM2/aad", C(T))
(CT,TAG) = AES-256-GCM-Encrypt(K, IV, plaintext=P, AAD=AAD)
SIGINPUT = F("XOVM2/signature", C(T), CT, TAG)
SIG      = Ed25519-Sign(server_signing_private, SIGINPUT)
E        = {transcript:T, ciphertext:base64(CT), tag:base64(TAG),
            signature:base64(SIG)}
```

客户端 Z 使用其临时私钥与 T 的服务端临时公钥。任一导入/derive 错误、非 32 字节结果或 Z 全零都拒绝并清理，不能继续 HKDF。两端额外要求 X25519 公钥的 little-endian u 坐标 `<2^255-19`（高位必须零），拒绝非规范编码；小阶/all-zero 情况以 derive 错误或 Z==0 拒绝。不能依赖某个库静默 mask 非规范公钥实现互通。

签名在解密前验证，认证双方 ephemeral keys、nonces、request_hash、全部期限、服务 key ID、epoch、counter、完整 binding 及 payload_hash，也直接覆盖 CT/TAG。AAD 覆盖相同完整 T。请求被篡改后客户端的原 Q/request_hash 不匹配；payload_hash 在解密后再重算，不能仅信任签名中声明的值。

每次加密只用一次 (K,IV)。双方 nonce 每新逻辑请求独立随机，不能由时间、counter 或 obf seed 代替；服务端在 `(issuer_id,subject_id,software_id,device_binding,build_id)` 范围内跨 session 检测 client_nonce 或 client ephemeral 公钥单独复用（同 request_hash 的重试除外），拒绝新请求复用，open 同样受检。不同请求绝不重用服务端临时密钥/nonce。已缓存响应重传只复制 CT/TAG/SIG，**不调用第二次 GCM**。CSPRNG 错误直接失败。

### 6.2 framing 示例

nonce 编码例：临时测试的原始32字节 `00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f` 在 Q 的 canonical JSON 中恰好表示为 `"client_nonce":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"`；这是字段编码演示，生产不能使用计数序列作 nonce。nonce 的 hex 文本进入 C(Q)/C(T)，不把它替换成 raw 字节；只有定义要求的 hash 输出或 DH public key 解码后才以 raw bytes 送密码原语。

以下小输入仅验证 framing，不是合法完整 transcript 或生产密钥：测试 TH 为32个零字节，C(T) 示例为 `7b7d`（`{}`），CT 示例为 `0001ff`，TAG 示例为16个零字节。参数个数与实际公式一致；每串 hex 完整，无省略：

```text
F("XOVM2/response-key",TH)
584f564d322f726573706f6e73652d6b657900000000200000000000000000000000000000000000000000000000000000000000000000
F("XOVM2/response-iv",TH)
584f564d322f726573706f6e73652d697600000000200000000000000000000000000000000000000000000000000000000000000000
F("XOVM2/aad",C(T))
584f564d322f61616400000000027b7d
F("XOVM2/signature",C(T),CT,TAG)
584f564d322f7369676e617475726500000000027b7d000000030001ff0000001000000000000000000000000000000000
```

实际 HKDF info 各恰好一个参数 TH，长度字段 `00000020`；实际 AAD 一个参数 C(T)；实际 SIGINPUT 三个参数 C(T)、原始 CT、16-byte TAG，不能传 base64 文本或 TH 代替 C(T)。F 的标签后 `00` 与 BE32 的零字节都必须保留。

### 6.3 Node crypto / OpenSSL 3 对照

| 原语 | Node | OpenSSL 3 EVP |
| --- | --- | --- |
| 密钥生成 | `generateKeyPairSync('x25519')` / `generateKeyPairSync('ed25519')` | `EVP_PKEY_Q_keygen` 对应名称 |
| raw public | 导出 JWK 的 x（先 base64url 解码为 32 bytes），再标准 base64 用于 wire | `EVP_PKEY_get_raw_public_key` |
| raw public 导入 | SPKI DER prefix+raw，`createPublicKey({format:'der',type:'spki',key})` | `EVP_PKEY_new_raw_public_key_ex` |
| DH | `diffieHellman({privateKey,publicKey})` | `EVP_PKEY_derive_init/set_peer/derive` |
| HKDF | `Buffer.from(hkdfSync('sha256',Z,TH,info,L))` | `EVP_KDF` HKDF，digest SHA256、mode EXTRACT_AND_EXPAND、key=Z、salt=TH、info=info |
| GCM | `createCipheriv('aes-256-gcm',K,IV,{authTagLength:16})`，先 setAAD，再 update/final/getAuthTag | AES-256-GCM，显式 IVLEN=12，AAD update 在数据前，GET_TAG 16 |
| GCM 解密 | `createDecipheriv`、setAAD、setAuthTag、update/final | SET_TAG 16，必须 `EVP_DecryptFinal_ex==1` |
| Ed25519 | `sign(null,SIGINPUT,key)` / `verify(null,SIGINPUT,key,SIG)` | DigestSign/VerifyInit digest=NULL；one-shot DigestSign/Verify，无 SHA256 预哈希 |

X25519 SPKI prefix=`302a300506032b656e032100`；Ed25519 SPKI prefix=`302a300506032b6570032100`，后接 raw public 32 bytes。测试 fixture 如需 raw private seed 导入，PKCS8 prefix 分别 `302e020100300506032b656e04220420` / `302e020100300506032b657004220420`，后接**测试用**32 bytes。生产不得把 seed 硬编码到客户端/文档。

GCM 的 update 可能在 final 认证前输出暂存明文；该缓冲区仍是未认证内存，不解析/发布/执行，失败时清理。签名私钥由 key-provider 操作，不以字符串跨模块传递；清理 Z、K、IV、临时私钥及失败明文的最短可控生命周期。

## 7. 接收状态机与请求时钟

### 7.1 PendingRequest

发送前保存不可变的 `{Q bytes, request_hash, client ephemeral private handle, origin, process_epoch, PID, expected descriptor/release, original_sent_boot_ns, retry budget}`。原始 t0 在**第一次向 transport 提交该 Q 前**读取 `CLOCK_BOOTTIME`；进程内只存一份，重发不得刷新。wall clock、接收时刻或 HTTP retry start 不能替换 t0。新的 request_id 才是新逻辑请求，并生成新密钥/nonce/t0。

进程重启不恢复 pending 私钥或 A/B 明文；fork 子进程不能使用继承的 session/locks/handles，基础版本要求 exec 后重新初始化。丢失 pending 就拒绝响应，不能从 T 重建 t0。open 也遵守同样规则。

### 7.2 authenticateResponse 顺序

1. 流式响应限额、canonical/schema、base64 长度、已知协议/套件。只读有限 T；不依据未验证的 counter/期限更新状态。
2. 查找仍有效的 PendingRequest，检查 process/PID/origin、全部请求回显、release/region/ABI、session/epoch。解析已知 key ID 与受信 bundle（§10），未知 key 不从 E 学习。
3. 按 SIGINPUT 验证 Ed25519，再检查 signer 授权期限、trust/counter epoch。失败不做候选发布。
4. DH 非零检查、HKDF、GCM 验证；明文长度恰好 CT 长度；SHA256(P)==payload_hash。
5. P 严格 canonical/schema；material 验证 package_hash 与全部 expected binding/VM 格式；control 验证 payload 与 T 重复字段一致。
6. t1/发布时 `now=BOOTTIME`；检查所有 checked 加法和接收窗口 `now < t0 + accept_for_ms*1000000`。相等即拒绝。校验未来 generation、counter；一切通过才构造 VerifiedPackage/VerifiedSessionControl。
7. 在短状态锁内重查 active process/session、期限、当前代/counter，并原子发布。网络、签名、解密、分配不持材料锁。迟到候选不可覆盖新代。

同一个已接受响应的重复交付是 no-op，不刷新任何期限/引用；在各自分配 scope 内，不同响应不得使用相同 generation 或 counter。control 与 material high-water mark 分流，跨区域互不误拒绝，见 §9。

### 7.3 A/B 与 session control 的区别

- **A**：有效 session 内首次 issue 从 generation=1 开始，原请求重试不增代；运行时不定时续发 A。若首次响应丢失且原请求已放弃/retired，可用新 ID 在同一有效 session 恢复获取，生成新代与新配对包；这不使已有 A 材料定时过期。收到合法 A 后可在该进程会话存续内新调用获取；不存在 120 秒 A 截止。
- **B**：`deadline_ns=t0+lease_ms*1000000`；`renew_at_ns=t0+max(0,lease_ms-10000)*1000000`。这是已批准总规格 §8 第132–134行的原 t0 与短租约规则；lease_ms=120000 对应110/120秒，45000对应35/45秒，≤10000时立即安排有界续期。now==deadline 已过期；到达响应时若过 renew_at 立即安排有界预取。下一代必须重新 issue，生成新的配对编码，不是更新旧代期限。
- 有效期内 pin 的 B 调用允许完成，最后一引用释放才清理旧代；递归再次进入业务保护入口算新调用，重新检查期限。内部 helper 仅在明确属于同一调用时共享固定句柄。
- session control 期限只管**是否还能向服务器取得新材料**，不把已交付 A 变成 B，也不追溯撤回已 pin 调用。B 续期失败不影响 A。显式本地 logout/shutdown/会话替换才阻止 A 的新 acquire；后台错误不 kill/trap。
- open/renew 的 control deadline 也用该控制请求原 t0+control_valid_for_ms，保守地提前更新；建议在 `t0+max(0,TTL-60000ms)` renew。控制续期延长同一 session 的服务端权限，不重置 generation/counter，不刷新任何 A/B 包期限。

### 7.4 有界调度

每区域最多一个新逻辑 issue 在途；一个 session 最多一个控制请求在途。同步无材料获取从该业务调用进入获取路径的 `call_start` 起总预算5000ms，包含必要 open/renew、等待、所有传输与认证/发布，换逻辑请求不重置该预算。每个逻辑请求（同步/后台）最多3次传输尝试（首次计入），总窗口从其原 t0 起最多10000ms；单次 transport timeout 不超过3000ms并截断到剩余预算。全部时间使用 BOOTTIME/checked 纳秒运算。

自动重试按以下结果分类；成功或已接受响应的精确重复按 §7.2 处理，不进入失败重试：

- **可重试：** 临时 DNS/连接失败、transport timeout、连接重置或在完整响应到达前断开；以及来自已验证 TLS origin、通过 §5.5 canonical/schema、HTTP/code 配对且 request_id 匹配的 `429 rate_limited`、`503 authority_unavailable/store_unavailable/key_unavailable`。网络不确定结果不等于服务端未提交，必须重发原 Q。
- **不可自动重试：** 400/413、401/403、409、422、`503 counter_exhausted`、其他 HTTP/code、不合法/超限响应、TLS身份失败、签名/tag/hash/binding验证失败、shutdown/取消、已经过期的成功响应。counter_exhausted 必须走 §10 的受信 epoch 恢复，不能因其 retry_after_ms 为正就循环；其他拒绝需先解决对应状态/授权/配置，不自动换ID绕过。完整但非法的响应不得伪装为可重试的网络截断。

可重试错误中的 `retry_after_ms` 是**必须遵守的最短等待**，不是提示；只在上述合法错误中取值1..10000ms。网络失败没有该字段，取 `server_wait_ms=0`。非法/缺失/越界值使错误不可重试，不 clamp 到合法值；本协议不使用 HTTP Retry-After 头代替该字段。

设第 n 次重试 n=1或2（首次失败后 n=1），抽一次整数 full jitter `J∈[0,min(1000,250*2^(n-1))]` ms。在结果完整接收/失败被确认时记录 `failure_time`，计算 `not_before=failure_time+max(server_wait_ms,J)`；等待与退避取 max，不相加，也不在再次唤醒时重抽抖动。任何等待/重试均保持原 Q、request_id、key、nonce、previous_generation 和原 t0 不变。

请求硬截止为 `request_end=t0+10000ms`；同步另取 `end=min(request_end,call_start+5000ms)`，后台 end=request_end；已知的可信响应接收截止只能再缩短 end。每次等待/发包前若次数已耗尽、now≥end或not_before≥end，立即放弃该逻辑请求，不能截短必须等待后抢发，也不能移动 t0/end。否则等待至 not_before，唤醒后重查次数/截止，transport timeout=min(3000ms,end−now)。认证/发布也必须在 end 与 §7.2 的原 t0 接收窗口内完成；等待、网络与认证共同消费预算。

有效429/可重试503产生的 `failure_time+server_wait_ms` 下限还保存在当前 origin/授权上下文的请求调度器中，适用于新ID、并发请求及后续业务调用，不能通过放弃原请求绕过；并发响应取这些下限的最大值。后续调用若无法在自己的剩余同步预算内等待则同步失败。后台耗尽可重试预算后另冷却10000ms，下次发包须同时满足冷却与该服务端等待下限；不可重试结果停止对应自动重试链，待可信状态恢复或新的显式业务获取再判断。

同步预算耗尽或遇不可恢复结果且无有效材料时，在保护副作用之前同步 fault；后台仅记录失败。预算耗尽可放弃原请求，后续有界业务获取可按上述等待约束用新ID恢复，服务端从真实当前代+1发放。不能在短 TTL 或立即过期响应上忙循环。旧代到期不停止已 pin 调用，但不能供新 acquire；shutdown 取消/回收预取，任何已关闭 epoch 的完成回调不能发布。

## 8. 会话开立、续期、结束与权限

1. `session.open`：宿主重新验证真实登录/租约/设备绑定和 software scope；核对 enabled release pair。事务生成随机 session_id，绑定可信 `issuer_id,subject_id,software_id,device_binding,build_id,final_artifact_hash,counter_epoch`；生成控制 counter 与响应并原子保存。默认 control TTL=min(86400000ms,可信 auth 剩余)，必须正数。
2. runtime 认证 open 后激活 process session，并按区域懒获取 A/B。相同安装文件的每次进程启动必须新 open，不能从磁盘恢复有效 session/material。session_id 仅是标识，不是 bearer credential。
3. `session.renew`：同一身份 tuple，session 尚 active 且未过控制期限，重新检查当前授权/吊销，再给新的控制期限；只延长服务端可发放窗口。已过期 session 不复活，必须新 open；切换到新 session 时旧材料停止新 acquire，活跃句柄可完成。
4. `material.issue`：每次均重新检查可信宿主与当前持久权限；region policy 来自登记记录。B 可在 session 活跃时分代续发；A 按需首次分配/恢复获取，原请求可幂等重试。
5. `session.close`：事务将 session 置 closed，停止后续 issue/renew；关闭本地不等待网络成功。close 自身丢响应可用相同 request 重试，从关闭 tombstone 取原回应。除这种 close 重试，closed/expired session 不允许读取缓存材料。
6. auth tuple 改变（切换账号/设备/软件）、显式 logout 或 counter epoch 更换必须建立新 session。宿主凭据刷新但 tuple 不变允许 renew。客户端正文不能把 session 归属改给新主体。

控制到期/服务端吊销不能数学擦除已交付 A；B 在本地原期限/下一次续期检查显现。正常客户端遵守显式本地 logout，完全控制进程的攻击者可能继续复用捕获材料，报告必须保留这一限制。

## 9. 事务、幂等、generation 与 counter

### 9.1 不同计数的作用

| 值 | 分配与作用 |
| --- | --- |
| request_id/client_nonce | 独立随机 R32，防混淆/识别逻辑请求，不是序号 |
| generation | 每 `(session_id,region_id)` 独立 U64；起于1；只有新成功材料分配递增 |
| counter | 每 `(counter_epoch,software_id,build_id,stream)` 独立 U64；stream 为 region_id，control 使用保留字 `control`；跨 session 单调 |
| counter_epoch | 随机 R32，持久化的服务数据时代；由受信根签名 bundle 授权，不能任意从响应学习 |
| trust_epoch | 根签名 bundle 的递增 U64 版本，与 counter/generation 无关 |

客户端记忆每 stream 的已接受 counter 与每 session/region 的 generation。只接受 counter 更大、generation 更大的新材料；原已接受响应精确重复为 no-op。正常请求允许跳过丢失的代号，不要求连续。不同 region 的回应可以乱序，不用一个全局最大 counter 误拒绝。open/renew/close 控制另有 high-water mark。

### 9.2 唯一键和线性化提交

请求幂等键为 `(issuer_id,subject_id,software_id,device_binding,request_id)`；不是仅 session 局部，否则 open 无法幂等。record 保存 request_hash、scope、状态与原 response bytes。相同键不同 hash 返回 request_conflict，不能增代。相同键相同 hash 且仍被授权时只能返回**逐字节相同**已提交响应；不会重签名/重加密/换 key/换期限。

事务必须同时覆盖：当前 build/release 状态、region policy、session 状态/归属、可信权限 revision fence、request record、nonce/key 重用索引、generation、该 stream counter、响应字节。单个 JS Map 锁、单实例 mutex 或只锁 region 行不足以和跨实例吊销/启用顺序一致。

执行顺序：

```text
validate bounded Q -> trusted auth bound to Q hash -> transaction
  check authorization/build/session/revocation fence
  lookup request key (conflicting hash fails before allocation)
  if committed and currently permitted: return saved bytes
  if retired: return request_retired
  validate policy/previous_generation/counter epoch
  allocate generation/counter (checked; no wrapping)
  make package/control, ephemeral DH, encrypt, sign, save exact bytes
  save all state and commit authorization fence atomically
send only committed bytes
```

事务回调可能因序列化冲突重跑；未提交候选的密钥/密文销毁，不能向网络暴露，也不能提前记录成功。签名失败/随机失败/提交失败全部回滚。服务器内部可在事务持锁期间做有界密码运算；超过服务端事务预算 5000ms 中止。外部 HSM 签名须可取消或在预算内，不能把未提交签名结果直接发给客户端。

同一 ID/hash 不承诺在授权已吊销后仍返包：先检查当前权限，已吊销只返回拒绝。缓存响应若承诺的 auth_valid_until_ms 超过当前可信 grant 的 valid_until_ms，或当前策略已不允许其绑定，也拒绝（policy_mismatch），不能重写原响应缩短期限。幂等承诺是“不再产生另一个成功响应”，不是绕过吊销的取包能力。吊销与发放有一个线性化顺序：吊销提交后不能再提交新发放/缓存交付授权；先提交的发放可能已在网络中，不能承诺收回。

### 9.3 持久缓存与 tombstone

保存成功响应原始字节至少到 `issued_at_ms+accept_for_ms`；之后可删除大响应，但保留 request hash/scope/counter/generation 的 compact tombstone，重试返回 request_retired，不能重建新成功响应。活跃可重试窗口内丢失持久 bytes 是存储错误，不能“修复”为新包。新授权状态不允许把已 retired 的 ID 重用。

nonce/key 重用索引与 closed session 身份在其授权 build 命名空间的整个生命周期保留；该 build 永久退役、今后永远拒绝该 build_id 后可清理。request 幂等键跨 build，故其 compact `(authRequestKey,request_hash)` tombstone 继续保留，直到对应 software/主体命名空间永久退役；不能删掉后让另一个 build 用同 ID 获得不同响应。超过存储配额时拒绝新请求，不淘汰仍可接受的 replay fence。备份恢复不能悄悄丢失这些记录后继续使用原 counter_epoch。

### 9.4 登记、启用和吊销

管理员接口与 runtime 发放接口分离，要求独立 publisher/revoker scope。`registerBuild(publicManifest,privateRegistration)` 事务创建 pending，完整验证后变 validated；同身份不同内容冲突。`enableBuild(buildId,finalArtifactHash)` 需经过发布工具的最终验证证明与可信管理员权限，原子 validated→enabled 并锁定 release pair。enabled→revoked 是永久状态，首版不支持恢复启用；新发布使用新 build 身份。

revocation 记录、auth revision、enabled 状态与 issue 在同一串行化域参与，不能仅在请求开始前读一次未加 fence 的缓存。region 密文、注册秘密 at rest 的加密/访问控制由受审部署适配器提供；普通日志与可公开备份不得出现它们。

## 10. 在线签名 key、信任根与 counter 轮换

客户端安装可信 root Ed25519 public key 及其 root_key_id（Id），来自可信应用发布，不从材料响应获取。在线 key 记录的 key ID 不可在同一信任域复用来代表不同 key。

`TrustCore` 全字段：

```text
format_version: 1
protocol_version: 2
software_id: Id
root_key_id: Id
trust_epoch: U64 (1..UINT64_MAX)
counter_epoch: R32
issued_at_ms: U64
valid_until_ms: U64
keys: SigningKey[] (1..64, key_id ASCII ascending, unique)
```

`SigningKey` 恰好 `{key_id:Id, public_key:B64(32), not_before_ms:U64, signing_until_ms:U64, not_after_ms:U64, status:"active"|"retired"|"revoked"}`；时间要求 `not_before < signing_until <= not_after`，Ed25519 raw key 严格导入。TrustCore 要求 issued_at_ms < valid_until_ms。`TrustBundle={body:TrustCore,signature:B64(64)}`：

```text
root_sig = Ed25519-Sign(root_private, F("XOVM2/trust-bundle", C(TrustCore)))
```

使用已安装根验签，software/root_id 匹配，只接受更高 trust_epoch；相同 epoch 必须逐字节相同。bundle 是独立可信配置渠道输入，不嵌在 E 中由 E 自己授权。未知 server_key_id 可触发一次有界 bundle 更新，更新失败拒绝材料；不信任响应附送的新公钥。

客户端验证 T.issued_at_ms 在 signer 的 `[not_before,signing_until)` 内，T 的 accept 窗口不能越过 signer not_after 或签发时 bundle 的 valid_until_ms。还需使用宿主提供的可信时间区间（或受信时间锚+BOOTTIME）确认当前 bundle 有效；该区间上界不早于下界、宽度至多 5000ms，要求整个区间在当前 bundle 的 `[issued_at_ms,valid_until_ms)` 内。签发时 bundle 由 T.trust_epoch 标识；客户端保留 pending 请求期间用过的根认证 bundle，用它检查签发期限，再用当前 bundle 复查 key 状态/cutoff/counter_epoch。若旧 epoch bundle 不在本地且无法有界取得并验证则拒绝，不凭 T 自报期限。普通可修改系统时间不能独自成为根期限依据。无可信时间/信任 bundle 时拒绝新开立和新材料；已发布 A/B 按既有生命周期处理，不借此延长租约。

轮换流程：根发布更高 trust_epoch，新增 active key；先部署 bundle，再切服务签名 key；旧 key 置 retired 并设置 signing_until_ms 为停止签发时刻，not_after_ms 留足至少120000ms的旧响应验证尾窗，允许验证截止前已提交的原重试响应。服务不再用 retired key 签新包。当前 bundle 标记 revoked 的 key 一律拒绝包括缓存响应；不能靠旧 bundle 降级。保留旧公钥及签发时 bundle 至少覆盖重试窗口，私钥移除不需要重加密历史响应。T.trust_epoch 不得高于已安装 bundle；旧 epoch 响应仅在当前 bundle 仍含同一 public key 且非 revoked、counter_epoch相同且 pending 有效时允许。retired 是正常轮换状态，不是泄露撤销；涉嫌私钥泄露必须 revoked，不能信任其回填的 issued_at_ms。

根轮换首版只通过由现有可信应用更新机制验证的安装包更换 trust store；无 in-band 自签名根接受路径。丢失根/恢复不可信备份时停止发放，重新部署可信状态。

generation/counter 达到 UINT64_MAX 后禁止自增回零；generation exhaustion 需新 session，counter exhaustion/服务备份回滚需**新 counter_epoch + 根签名更新 + 关闭所有旧 session**。所有重试 tombstone 原样保留或永久退役旧命名空间。key rotation 本身不重置 counter；counter epoch 变化也不授权新 Ed25519 key。client 的持久最大 epoch/counter 可帮助正常防回滚，但不声称能抵抗攻击者恢复整个客户端磁盘/进程快照。

## 11. Trusted host 与持久适配器接口

### 11.1 可信授权提供者（不是 JSON auth 字段）

部署方提供内部 `AuthProvider.authenticate(transportContext, requestHash, audience) -> AuthGrant`。audience 固定为本配置的 HTTPS origin 加 `/xovm/material/v2`；transportContext 来自真实登录/租约宿主，必须验证凭据、防跨软件/跨设备转用并绑定当前 exact Q hash。AuthGrant 是封闭模块内部的不可由网络构造的 handle，暴露只读事实：

```text
issuer_id: Id
subject_id: Id
software_id: Id
device_binding: H
lease_valid: true
revoked: false
valid_until_ms: U64
authorization_revision: U64
request_hash: H
scopes: set of material.issue/session.control/build.publish/build.revoke
```

宿主的非 ASCII 原始账号/设备 ID 必须由适配器用稳定命名空间映射为 Id/H，不直接拷贝客户端字符串；device_binding 是已验证凭据绑定的摘要，不是对正文 device_id 哈希后当真。

`tx.requireAuth(auth, requestHash, requiredScope)` 必须登记提交时的 authorization revision fence，并在与 grant/revoke **同一线性化域**校验未吊销、租约仍有效、tuple 相同。宿主若仅提供无事务保证的瞬时 bool，不能宣称此接口满足生产要求。可用宿主事务内执行 callback 或共享强一致授权版本表实现；不能用本地 TTL cache 掩盖缺失能力。宿主不可用、超时、时间不可信全部 fail closed。

### 11.2 Store 接口和补全

保留计划接口：

```text
issueMaterial(request, auth, store, clock, randomBytes) -> Promise<canonical response bytes>
transaction(buildId, regionId, sessionId, callback) -> Promise<committed callback result>
tx.getBuild(), tx.getRegion(), tx.getSession(), tx.saveSession(session)
tx.saveReply(requestId, requestHash, responseBytes)
registerBuild(publicManifest, privateRegistration)
enableBuild(buildId, finalArtifactHash)
```

冻结以下必要扩展，均为服务器内接口，不是额外 wire 字段：

```text
handleSession(request, auth, store, clock, randomBytes) -> Promise<canonical response bytes>
tx.requireAuth(auth, requestHash, requiredScope)
tx.getReply(authRequestKey) -> absent | committed | retired
tx.reserveRequest(authRequestKey, requestHash, scope)
tx.claimClientEphemeral(authBuildScope, clientNonce, clientPublicKey, requestHash)
tx.nextGeneration(sessionId, regionId) -> U64
tx.nextCounter(counterEpoch, softwareId, buildId, stream) -> U64
tx.setBuildState(expectedRevision, nextState, releasePair)
tx.closeSession(sessionId)
```

`regionId=null` 为控制事务内部 sentinel，不进入 JSON；open 的 sessionId=null 时依赖 request 唯一键与原子 session 插入，生成冲突则重新随机。`saveReply` 使用 requireAuth/reserveRequest 设置的可信 namespace，必须原样持久保存 Buffer。看似单 region 的 transaction 实际必须包含 §9 的共享 build/auth/counter/reply read/write set；适配器用串行化事务/显式锁顺序或 compare-and-swap+fence 保证，不能只按传入三元组隔离。

回调结果在 durable commit 前不能返回；commit 不确定时调用方按原 ID重试并查询，不能假定失败后重新分配。多进程同时相同请求只提交一个响应，两个不同请求的 generation/counter 严格单调；吊销、启用与发放竞争按提交顺序处理。

### 11.3 Clock / KeyProvider / 启动契约

- `clock.trustedNowMs()` 返回 `{lower_ms:U64,upper_ms:U64}`，上界不小于下界，宽度最多5000ms；`issued_at_ms=upper_ms`，计算授权剩余用此上界，签名 not_before 则要求 lower_ms 已达到，不能提前启用 key。commit 时再次检查上界仍早于授权/session/key 截止且 revision fence 未变；时间回退、无有效时间界或候选接收窗口已用尽则中止。测试 FakeClock 不链接生产入口。
- `KeyProvider.signEd25519(keyId, bytes)` 返回 64-byte signature；active key 与 root bundle/软件相匹配；生产来自受控配置注入或受审 key service，缺失时启动失败。root 私钥不部署在线服务。
- 生产 `randomBytes` 固定系统 CSPRNG，不能通过普通请求/config flag 指定可复现 seed；确定 RNG/测试密钥只在显式 reference/test 构造器。
- adapter 提供有版本的 `capabilities()` 与启动 `selfCheck()`：auth request binding、revocation commit fence、cross-instance serializability、durability、trusted time、secret storage/key injection。仅返回自称 true 不足以验收，需下列合同实测与部署记录。
- 生产启动缺任何一项返回非零/`production_adapter_missing`，不监听可发放材料的 production endpoint，不自动创建 Map store、测试 AuthGrant 或临时 signing key。上线后依赖失效返回 503 并拒绝发放。

### 11.4 本地 reference 与实际平台集成的明确边界

当前未提供真实平台 host authority、持久事务与保密配置注入的可验证契约；**生产部署状态为 BLOCKED**。不得读取/复制上层 `capability_v1.js` 中的配置以补齐；本 Task 0 没有读取该文件。

本地 reference 可以仅绑定 loopback，使用进程内临时测试 Ed25519/X25519、公然标记的测试 AuthProvider 和 MapStore，证明算法与状态逻辑。reference/test 配置单独命名，不得经 production flag 启用测试后门；测试临时根与生产 trust store 隔离。它不证明多实例持久性、真实卡密授权、上线吊销或业务 C 的服务端依赖。

后续真实接入只能由具体平台适配器把已有登录/租约结果转换为上述 AuthGrant，提交持久原子接口及 key-provider 证据；不在这里指定云供应商/替换平台。live 验收在这些条件未满足时报告 BLOCKED，不计 PASS。

生产适配器合同最低验收：两实例同 ID 同 hash 返回相同 bytes；同 ID不同 hash 拒绝；commit 前/后进程崩溃；response 丢失重试；并发两个续期；吊销穿插发放和缓存读取；pending/validated/enable 竞争；存储不可用；counter 溢出；旧备份恢复/epoch；未知 key/根轮换；trusted time 失效；伪造正文 auth/device；不同软件/设备 session 转用。全部要有实际持久后端和宿主证明，Map 测试不能替代。

## 12. 专项审核检查表与后续验证

Task 0 的完成标准是具体文档及一致性检查；没有产品模块测试/构建已通过的结论。Task 1/5 应将本文公式落实为独立 Node/OpenSSL 已知答案和拒绝向量，fixture 只含临时/公开测试 key，包含：

1. C/F 字节、所有前像、8 MiB BC/16 MiB wire 边界、base64 pad bits、重复键、u64 最大值/溢出、负零/指数、未知字段/版本。
2. X25519 非规范/小阶/全零共享秘密；Node→OpenSSL 与 OpenSSL→Node；Ed25519 原始消息签名；错误 signature/tag/AAD、任一 ephemeral/nonce/key ID/期限/binding/counter 被替换。
3. 明文 payload_hash 与非递归 package_hash 重算；混搭 bytecode/map/descriptor；从真实编译导出的 VM 内容反映射逐字节一致，未知 ABI/越界分支拒绝。
4. open 丢响应重试、renew 不刷新 A/B、已过期 session 不复活、close 幂等；A startup，B完整租约110/120秒与119秒pin、45秒租约35秒续期、≤10秒立即有界续期、截止相等拒绝新调用、休眠、原t0重试、迟到旧代、并发不同region。调度覆盖合法429/可重试503、counter_exhausted不自动重试、非法错误/TLS/认证失败、max(server_wait,J)、等待恰好达到/超过剩余预算、跨open/renew的5000ms同步总预算、3次尝试/10000ms上限、新ID不能绕过服务端等待下限。
5. build/region 名相同内容不同、seal 之后改文件、manifest 身份排除、120-byte ELF record offsets、全零 pending ID 不得执行。
6. §11 部署合同与故障注入；reference 与 production/live 状态分别报告。完整捕获、时钟/状态冻结、跳过期限判断能复用的能力继续如实记录。

### 裁决记录（供 controller/reviewer）

- **Ruling 0.1：** 上位“先用户审核”按本次明确委派改为 controller/reviewer 专项审核；不再暂停等新用户批准。成本：若审核提出变更，先修文档再冻结 Task 1/5 wire。
- **Ruling 0.2：** PackageBinding 不含自身 hash，MaterialBinding 添加 package_hash；payload_hash 在 T，T hash 在 KDF，签名最后产生。解决概念接口的自引用风险；成本：Task 1/4/5 必须统一采用此精确结构。
- **Ruling 0.3：** session 控制窗口与 A/B 材料窗口分开，控制 renew 不延长已交付 B，A 没有隐式120秒。成本：新增 handleSession/VerifiedSessionControl 路径。
- **Ruling 0.4：** final ELF hash 是独立 release record，不回写 ELF；每 build 固定一个 release。成本：不能对同 build_id 原地重新 seal/换发布文件。
- **Ruling 0.5：** counter 采用 per-build/per-region stream，control 独立；epoch 根授权，事务扩展覆盖共享状态。成本：适配器需跨这些行与权限 fence 的线性化能力。
- **Ruling 0.6：** request 大响应可过接收窗后清理，但跨 build 的 compact request hash tombstone 保留到对应主体/软件命名空间永久退役；授权吊销优先于缓存重发。成本：持久元数据空间，不能用 TTL 驱逐绕过幂等。
- **Ruling 0.7：** Task 3B 使用每条16-byte头+104-byte描述符的120-byte固定记录。成本：编译器/finalizer/独立 fixture 同步布局。
- **Ruling 0.8：** 缺生产 host authority/事务/key 配置证据时只允许 reference；认证时间也需可信来源。成本：真实 live 接入保持 BLOCKED，不能从旧 JS 猜凭据或平台能力。
- **Ruling 0.9：** opcode_count 表示逻辑 opcode 域，未在本区域出现的 opcode 不发放 decode_map 项；A 丢响应可在同 session 用新逻辑请求恢复取包。成本：Task 4 按实际用到的集合验证 map，Task 5 区分恢复获取与定时续租。

原总规格在本 worktree 中保持逐字节副本；计划副本的 Global Constraints 已按 controller 对 I1 的裁决同步总规格 §8 第132–134行，源工作区规格/计划未改。本轮仅澄清权威租约规则及 M1 重试调度；协议仍待 reviewer 复核与 controller 批准，不替代产品实现和部署专项验证。
