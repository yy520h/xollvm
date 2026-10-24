# 云 VM 构建材料与调用级租约基础阶段 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` for inline execution, or `subagent-driven-development` if the user explicitly selects delegation. 用户已批准本计划及分任务代理连续执行；任务状态以原 checkout 的 `.superpowers/sdd/2026-10-18-cloud-vm-foundation-plan/progress.md` 为准。Task 0 专项协议已通过独立复审。

**Goal:** 建立能实际执行 A/B 保护区域的构建绑定材料系统，验证三种模式的策略边界；C 区域在其业务专项实现完成前明确拒绝，不伪装成 A/B。

**Architecture:** 编译器把成功提交的区域字节码及编码描述导出为秘密登记包，最终客户端仅保留公开描述和通用引擎。服务端按构建和区域生成本代重编码载荷；运行时认证并固定整套材料，在函数调用边界取得、轮换和释放。旧零偏移、静态自解密回退与新版材料路径显式隔离。

**Tech Stack:** LLVM 23/Clang、C++20、Android AArch64 API 26、NDK r30、本项目 OpenSSL 3、Node.js 内置 crypto/node:test、pytest、现有 ELF hardener。

**Spec:** `docs/superpowers/specs/2026-10-18-cloud-vm-material-design.md`（2026-10-18 用户已确认）。执行者必须同时阅读规格与本计划。

## Global Constraints

- 三个模式：启动会话级 A；持续租约级 B；普通区域 A / 重点区域 B / 严重区域 C 的混合模式。
- B 租约上限 **120 秒**；完整租约在原请求 t0 后 **110 秒**开始续期。依据已批准总规格 §8（第132–134行），服务端可缩短为正时长 D≤120秒，本地截止为 t0+D，续期起点为 t0+max(0,D−10秒)；有效期内取得句柄的调用允许完成，到期后的新调用不取得旧代。
- 后台不执行保护业务、不 kill、不故意后台 trap；无材料的真实调用在保护业务副作用前同步故障。
- 接收验证包括认证、版本、长度、构建、区域、会话、代号；不执行未认证的机器码。
- 构建秘密不用 obf seed 派生，不进入公开产物、Git、命令行或普通日志。
- 期限由本地运行时管理，旧材料不会数学上自动过期；冻结状态和完整捕获不能标成不可能。
- 产物检查必须覆盖原生回退、明文字节码、常量初始化与静态解码路径，不能只搜索符号名字。
- 首个端到端目标 Android/AArch64；不支持的配置编译失败，旧 ARM32 非新云模式继续回归。
- 构建使用 Termux 普通用户。原生测试/交付链接 `-static-libstdc++`；MT 运行脚本显式 `bash`。
- 使用已有 Node/OpenSSL 能力；引入额外生产依赖或改变部署平台前先确认。
- 仅用户明确要求时提交；不得自动 push。每次提交前检查 status、diff 和最近 10 条提交，只 stage 所属任务文件。

## Review Focus

1. **身份漂移**：相同区域名字但不同编码/ABI、多个编译单元合并、seal 前后摘要，不能登记错误的配对包（任务 3、9）。
2. **时间边界**：恰好 120 秒、休眠跨期、迟到旧响应、缩短租约及断网恢复，不能延长旧期限（任务 6）。
3. **活跃旧调用**：重入、递归、两线程交错轮换、fork/退出，不能混用密钥或清除仍在使用的代（任务 6、8）。
4. **秘密旁路**：导出失败/预算回滚、相同公开 seed、测试后门、日志和 staging ELF，不能留下等价本地执行能力（任务 2、3、8、9）。
5. **伪造成功**：重复 JSON 键、整数溢出、合法响应错配请求、正常 trap 与补丁重放，不能把解析成功或无关崩溃当成授权保护通过（任务 1、5、10）。

---

## 0. 范围、仓库与审核关口

### 0.1 分成可独立验收的工作包

本文件只详细计划**基础阶段**。这不是缩减三个模式的最终目标。

| 工作包 | 本轮交付 | 后续规格/计划入口 |
| --- | --- | --- |
| 基础材料与 A/B | 编译导出、服务端重编码、认证、运行时租约、native 结果和攻击报告 | 本文件任务 0–10，包含任务 3B |
| C 级具体操作 | 本轮编译器可识别但明确拒绝未实现的 operation；不按 A/B 运行 | 基础阶段后，先确认一个真实操作的输入、服务端必要材料/状态、提交和幂等边界，再单独设计/计划 |
| native handler 加固 | 本轮不宣称 handler 密文执行或 chaff 已完成 | 单独审核 AArch64 relocation/W^X/cache/lifetime 探针，再为加密 handler、threaded JIT、chaff 写专项计划 |

所有协议产品实现受任务 0 的子规格批准约束。生产云入口还依赖真实部署环境的可信授权上下文与事务存储；本地参考服务通过不代表线上服务已部署。

### 0.2 真实仓库边界（已核对）

- 编译器仓库：`/data/user/0/com.termux/files/home/xollvm-android/xollvm`，当前基线 `9c2fbbb`。
- 集成仓库：`/data/user/0/com.termux/files/home/xollvm-android`，当前基线 `748ef03`，包含 `demo/`。
- 集成仓库的 `demo/jni/zone_runtime/capability_client.cpp` 已有用户修改：切换原 capability 敏感函数的 VM 加密配置。不得覆盖或随新任务批量提交。
- 上层的 `capability_v1.js` 和用户 v1 方案是未跟踪输入资料；前者含服务端配置，不复制、不自动 stage。
- 本计划内未带仓库前缀的相对路径均属于编译器仓库；`集成仓库:` 前缀表示另一个仓库。
- 表格/任务中的 `VMPass_Emitter.h`、`VMPass_Impl.h` 简写分别指 `include/llvm/Transforms/Obfuscator/VMPass_Emitter.h`、`include/llvm/Transforms/Obfuscator/VMPass_Impl.h`，不是仓库根新建的同名文件。

执行前使用 `using-git-worktrees` 选择隔离方式。若使用两个 worktree，必须显式传入项目根及工具目录；现有测试中由 `__file__` 推导父目录的规则不能假定适用于所有隔离目录。

### 0.3 命令约定

在编译器仓库执行测试前设置：

```bash
export PYTHONDONTWRITEBYTECODE=1
export XOLLVM_PROJECT_ROOT="/data/user/0/com.termux/files/home/xollvm-android"
export XOLLVM_OPT="/data/user/0/com.termux/files/home/xollvm-android/build-sensitive/bin/opt"
export XOLLVM_TEST_CLANG="/data/user/0/com.termux/files/home/xollvm-android/build-sensitive/bin/clang"
export TMPDIR="/data/data/com.termux/files/usr/tmp/opencode"
```

隔离构建时整套替换为该工作区实际路径。新测试通过 `utils/cloud_material_support.py` 读取这些变量，不使用静默工具回退。每个输出目录必须新建或为空；重复验收换编号，不用删除历史证据解决冲突。

## 1. 文件与职责映射

### 1.1 编译器与构建（编译器仓库）

| 文件 | 职责 |
| --- | --- |
| `include/llvm/Transforms/Obfuscator/ObfuscationConfig.h`, `VMPass.cpp` | `cloudMaterial=off/session/lease/operation` 与 `materialRegion`；显式配置和依赖验证 |
| `VMPass_Requirements.cpp`, `VMPass_Plan.cpp`, `ObfReport.cpp` | 引擎分组、strict 提交/导出事务、requested/effective witness |
| `include/llvm/Transforms/Obfuscator/VMPass_Material.h`, `VMPass_Material.cpp`（新） | 规范区域记录、导出、无全局明文回退的材料 wrapper 构造 |
| `VMPass_Emitter.h`, `VMPass_Emitter.cpp`, `VMPass_Verifier.cpp` | 导出真实指令边界及逻辑 opcode，保持 CALL/SWITCH 与变长尾一致 |
| `VMPass_Impl.cpp`, `VMPass_Crypto.cpp`, `VMPass_Wrapper.cpp` | 新路径跳过旧静态密钥/白盒/明文字节码初始化，调用 acquire/view/release |
| `VMPass_Impl.h`, `VMPass_Dispatch.cpp` | 新材料引擎参数和动态 opcode 映射，中央与 threaded 路径一致 |
| `ObfuscationOptions.cpp` 及对应头 | 私有导出目录选项、构建材料事务入口 |
| `tools/cloud-material/export.mjs`, `format.mjs`（新） | 校验私有模块记录，生成构建清单与秘密登记包；从 stdin/文件读取，不打印秘密 |
| `tools/xollvm-elf-hardener/MaterialManifest.cpp`（新）及现有工具入口 | 最终 ELF 区域清单回填和公开摘要审计 |
| `tools/xollvm-link`, `CMakeLists.txt`, hardener CMake | 新显式 finalization 阶段与测试注册 |

### 1.2 云与公共运行时核心（编译器仓库的新模块）

| 文件 | 职责 |
| --- | --- |
| `cloud/material_v2/codec.mjs`, `protocol.mjs` | 严格格式及经批准的密码协议 |
| `cloud/material_v2/package.mjs` | 生成真正不同且语义等价的本代字节码和配对映射 |
| `cloud/material_v2/service.mjs`, `store.mjs` | 授权、登记、续期、原子 generation；存储与部署接口分离 |
| `runtime/cloud_material/material_abi.h` | 编译器生成代码和 runtime 的固定 C ABI |
| `runtime/cloud_material/material_package.h/.cpp` | 已认证执行包解析、边界/映射/身份验证 |
| `runtime/cloud_material/material_protocol.h/.cpp` | OpenSSL 接收认证，内部 VerifiedPackage 构造 |
| `runtime/cloud_material/material_store.h/.cpp` | 不可变代、固定调用句柄、时钟和候选代发布 |
| `runtime/cloud_material/material_runtime.cpp` | C ABI 与受控同步故障入口 |

这些模块归编译器仓库统一版本管理；demo 只添加薄网络适配层，避免两份核心实现漂移。

### 1.3 集成仓库

| 文件 | 职责 |
| --- | --- |
| `demo/jni/zone_runtime/material_transport.h/.cpp`（新） | 快照授权状态，发送新版协议，认证返回后发布；不借用旧零偏移值 |
| `demo/jni/zone_runtime/zone_wrapper.h/.cpp` | 追加受控初始化/关闭入口，保持原 capability 路径与用户修改 |
| `demo/jni/Android.mk` | 明确独立 C++20 material runtime 模块、源根参数与 OpenSSL 链接 |

## 2. 跨任务接口契约（任务 0 批准后冻结）

### 2.1 标识与数据

`build_id`、`region_id`、`request_hash`、`package_hash` 为 SHA-256 的 64 字符小写十六进制。`session_id` 为 32 字节随机值的同格式。`generation` 为无符号 64 位整数，JSON 用十进制字符串；lease 时间内部用纳秒整数。区域可读名称单独保存，不作为唯一身份。

`CanonicalRegion`：

```text
format_version=1, isa_version, target_triple, region_name, region_id,
mode, canonical_bc（base64）, instruction_offsets（递增 uint32 列表）,
logical_opcodes（与 offsets 等长）, opcode_count,
engine_abi_hash, register_counts, call_abi_hash, layout_hash,
static_decode_descriptor（仅登记包）, region_content_hash
```

`canonical_bc` 是现有编译期编码下的字节码，导出真实逻辑 opcode 与对应位置；不是靠扫描字节猜 opcode。服务端仅替换 opcode 字节，长度和分支位置不变。其他布局及语义编码由构建描述固定，编译器生成的引擎保持匹配。相同 logical opcode 在所有记录位置必须对应相同的构建 physical opcode；此约束由关闭旧 keyedDispatch 保证并由导出器独立验证。

`MaterialBinding`：`build_id, region_id, session_id, generation, request_hash, mode, lease_ms, package_hash, engine_abi_hash`。

`ExecutionPackage`：`binding, encoded_bc, decode_map[256], static_decode_descriptor`。随机映射为 logical opcode→本代 byte，逆映射为本代 byte→构建引擎的 physical opcode；其余 byte 标记无效。混搭包的完整性由认证的 package_hash 覆盖。`static_decode_descriptor` 包含 `decode_salt` 及构建的 ISA/layout/operand 编码摘要；只在秘密登记包和经过认证加密的响应内传递。首版包在认证后存储为本代编码字节码，明确不宣称运行内存全程密文。

基础阶段只要求运行期 opcode 表示随机化；语义操作数布局仍按构建固定。它不是原 v1 所称“每次完整 native handler 布局变化”，该能力由动态执行专项承担，报告必须区分。

### 2.2 C ABI（只使用固定宽度类型）

```c
typedef struct XovmMaterialHandle XovmMaterialHandle;
typedef struct {
    uint32_t abi_version;
    uint32_t bytecode_size;
    const uint8_t *bytecode;
    const uint16_t *decode_map; /* 256项；0xffff表示无效 */
    uint32_t decode_salt;
    uint32_t reserved;
    uint64_t generation;
} XovmMaterialView;

typedef struct {
    uint32_t abi_version;
    uint32_t mode; /* 1=session，2=lease，3=operation */
    uint8_t build_id[32];
    uint8_t region_id[32];
    uint8_t engine_abi_hash[32];
} XovmRegionDescriptor;

XovmMaterialHandle *__xovm_material_acquire(const XovmRegionDescriptor *region);
void __xovm_material_view(const XovmMaterialHandle *handle, XovmMaterialView *out);
void __xovm_material_release(XovmMaterialHandle *handle);
```

acquire 成功返回固定本代的非空句柄；失败走 `[[noreturn]]` 同步 fault。view 校验句柄属于本进程 registry，不把任意非空地址当成能力。生产库不导出“直接插入未认证包”的 API。它不是抵抗任意内存修改的硬件能力。

### 2.3 云端 JS 接口

| 模块 | 函数签名 | 返回值 |
| --- | --- | --- |
| package.mjs | `makePackage(region, binding, randomBytes)` | ExecutionPackage |
| codec.mjs | `encodeCanonical(value)` | Buffer |
| codec.mjs | `decodeCanonical(bytes)` | 已校验对象，错误抛异常 |
| service.mjs | `issueMaterial(request, auth, store, clock, randomBytes)` | Promise，返回认证响应字节 |
| store.mjs | `transaction(buildId, regionId, sessionId, callback)` | Promise，提交成功才返回 callback 结果 |

transaction 对象提供 `getBuild()`、`getRegion()`、`getSession()`、`saveSession(session)`、`saveReply(requestId, requestHash, responseBytes)`。构建登记另用 `registerBuild(publicManifest, privateRegistration)` 和 `enableBuild(buildId, finalArtifactHash)`；其认证入口不得开放给普通运行客户端。

`auth` 由可信宿主构造：`subject_id, software_id, device_binding, lease_valid, revoked`；不得从请求正文复制。存储原子性针对一个构建/区域/会话的 generation 与 request_id→响应绑定，跨实例部署必须线性化。默认内存实现仅测试；没有通过部署审核的生产适配器，服务拒绝启动生产模式。

### 2.4 测试入口

`utils/cloud_material_support.py` 提供：

| 函数签名 | 返回值与职责 |
| --- | --- |
| `build_material_harness(work, *, defines=(), sources=())` | Path；构建测试 harness 与实际 runtime 源，sources 追加可选模块 |
| `run_material_case(exe, name, *, timeout=15)` | dict；运行具名用例并解析非秘密 JSON 结果 |
| `build_cloud_fixture(work, *, mode, config=(), source=None)` | CloudFixture 数据类，字段 exe/public_manifest/private_registration/report/work |
| `issue_fixture_package(work, fixture, *, generation, mode)` | Path；真实重编码并由临时测试凭据认证的响应文件 |
| `run_cloud_fixture(fixture, packages=(), *, scenario="normal")` | dict；实际 native 进程的 value/exit_signal/side_effects/generation |

这些接口的实现分别属于任务 1、8，测试 helper 必须完成构建、执行、超时、stderr 处理与断言，不能以预设 JSON 冒充结果。

---

### Task 0: 协议子规格与部署边界审核

**Files:**
- Create: `docs/superpowers/specs/2026-10-18-cloud-vm-protocol-design.md`
- Modify: 本计划的契约段（仅在专项审核要求修改时同步）

**Interfaces:** 消费已批准总规格；产出后续任务使用的 wire format、算法套件、状态转移及部署适配契约。

- [ ] **Step 1: 写出专项规格的具体候选协议。** 采用 Node/OpenSSL 双方已有的 X25519 临时协商、Ed25519 服务端 transcript 签名、HKDF-SHA256 分用途派生、AES-256-GCM。双方临时公钥、客户端 request hash、构建/区域/会话、服务端 key id 和有效期全部进入认证 transcript。每次材料请求使用新的临时密钥；拒绝 all-zero shared secret；协商和签名密钥分离。
- [ ] **Step 2: 固定消息格式。** 标识限制 ASCII；对象键按 ASCII 排序，UTF-8 无多余空白；解码后重新规范化必须逐字节等于输入，以拒绝重复键、数字歧义和非规范表示。u64 为十进制字符串，不用 JS Number。限制原始响应 16 MiB、bytecode 8 MiB、region 名 128 字节；先验长度再分配。nonce 唯一性、HKDF label、AEAD AAD、签名输入用逐字节示例说明。
- [ ] **Step 3: 固定加密覆盖。** 签名认证服务端 ephemeral key 及 payload hash，AAD 认证完整 binding；解密明文先验证格式和 package hash 再产生 VerifiedPackage。静态签名 key id 的轮换必须由现有受信任根授权，不能因响应带了新公钥就信任。
- [ ] **Step 4: 明确授权与重试。** 可信 auth 来自已有登录/租约宿主，非正文 device_id。相同 request_id 和相同 request hash 重试只能得到同一响应；同 ID 不同 hash 拒绝。客户端保存该请求原始 t0；晚到旧响应不得用新的 t0 计算期限。登记、吊销与 generation 分配使用事务。
- [ ] **Step 5: 用户审核专项规格。** 明确现有云平台是否提供可信授权上下文、持久事务和保密配置注入。缺任一项则停在本地参考服务，不擅自选择云供应商、不把 Map 当生产持久层。不进入任务 1/5 的协议产品实现，直到此子规格获批。

本任务是文档审核，无虚构的代码测试或构建通过结论。批准后将协议测试向量作为任务 1/5 的实际产物。

### Task 1: 严格执行包格式与无凭据测试桥

**Files:**
- Create: `cloud/material_v2/codec.mjs`
- Create: `tools/cloud-material/format.mjs`
- Create: `runtime/cloud_material/material_abi.h`, `material_package.h`, `material_package.cpp`
- Create: `utils/cloud_material_support.py`, `utils/fixtures/cloud_material/package_harness.cpp`
- Create: `utils/test_cloud_material_package.py`, `cloud/material_v2/test/codec.test.mjs`

**Interfaces:** 按 §2 定义格式；C++ `parseExecutionPackage(bytes, expectedBinding)` 返回严格校验的内容或结构化错误，不执行密码认证。VerifiedPackage 由任务 5 创建。

- [ ] **Step 1: 先写跨语言拒绝用例。** Node 测试使用实际字节输入，C++ harness 从 stdin 读受限长度数据，stdout 只输出 verdict 和非秘密摘要。

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import {decodeCanonical, encodeCanonical} from '../codec.mjs';
test('拒绝重复键和不安全的generation表示', () => {
  assert.throws(() => decodeCanonical(Buffer.from('{"a":1,"a":2}')));
  assert.throws(() => decodeCanonical(Buffer.from('{"generation":9007199254740993}')));
  const v = {generation: '18446744073709551615'};
  assert.deepEqual(decodeCanonical(encodeCanonical(v)), v);
});
```

- [ ] **Step 2: 运行红测。**

```bash
node --test cloud/material_v2/test/codec.test.mjs
python -m pytest -q utils/test_cloud_material_package.py
```

Expected：缺少实际 codec/package 模块而失败；不是缺 Node、NDK 或 OpenSSL。依赖缺失先报告环境，不当作有效红测。

- [ ] **Step 3: 实现 codec 与 C++ parser。** 使用现有 `nlohmann/json.hpp`，但对 canonical round-trip、类型、范围、base64 canonical、重复 key 保持与 Node 一致。解析 map 时限制 256 项，每项为构建 physical opcode 或 0xffff；bytecode 长度与声明精确一致，拒绝截断/尾随数据和格式版本漂移。下面的拒绝逻辑同时用于 Node 验证入口：

```js
export function readU64(text) {
  if (typeof text !== 'string' || !/^(0|[1-9][0-9]*)$/.test(text)) {
    throw new Error('invalid_u64');
  }
  const n = BigInt(text);
  if (n > 0xffffffffffffffffn) throw new Error('u64_overflow');
  return n;
}
```

- [ ] **Step 4: 实现原生测试桥。** `build_material_harness` 使用 `XOLLVM_PROJECT_ROOT` 找 demo OpenSSL include/static lib，使用 NDK clang++、C++20、`-static-libstdc++`；构建源仅为本任务 runtime 源和 fixture。`run_material_case` 以 case 名启动子进程并读取 JSON，失败含 stderr 且不回显输入包。加入大包、超范围 map、零长度、未知 binding 字段和错误 ABI 各自用例。
- [ ] **Step 5: 重跑上述命令。** 全部格式用例通过、Node/C++ 对同一输入 verdict 一致；记录批准子协议的格式版本。若用户要求提交，仅提交本任务文件，消息 `feat: 定义云 VM 配对执行包格式`。

### Task 2: 新云模式配置与强制失败边界

**Files:**
- Modify: `include/llvm/Transforms/Obfuscator/ObfuscationConfig.h`, `VMPass.cpp`
- Modify: `VMPass_Requirements.cpp`, `VMPass_Plan.cpp`, `ObfuscationPipeline.cpp`
- Modify: `ObfuscationOptions.cpp`, `include/llvm/Transforms/Obfuscator/ObfuscationOptions.h`
- Test: `utils/test_cloud_material_config.py`, `utils/VMRequirementsTest.cpp`

**Interfaces:** 新增 `cloudMaterial=off/session/lease/operation`、`materialRegion=<ASCII名称>`；新增 CLI `-obf-material-export-dir`，路径不放注解。`off` 默认，legacy cloudDispatch 同开报错。operation 在基础阶段显式报未实现。

模式1/2分别对受选函数使用 `cloudMaterial=session/lease`；模式3在同一模块的不同区域使用不同值。不是一个全局状态变量控制所有区域。基础阶段 `operation` 识别后报明确未实现，后续 C 专项扩展该值而不改变 A/B 含义。

- [ ] **Step 1: 写错误配置红测。**

```python
import subprocess
import pytest
from vm_hardening_support import annotation, tools

@pytest.mark.parametrize('spec,diagnostic', [
    ('vm(cloudMaterial=lease)', 'materialRegion'),
    ('vm(cloudMaterial=lease,materialRegion=auth,cloudDispatch=1)', 'cloudDispatch'),
    ('vm(cloudMaterial=operation,materialRegion=pay)', 'operation material not implemented'),
])
def test_cloud_material_rejects_invalid_request(tmp_path, spec, diagnostic):
    path = tmp_path / 'request.ll'
    path.write_text('target triple = "aarch64-linux-android26"\n'
                    'define i32 @f(i32 %x) { ret i32 %x }\n' + annotation(['f'], spec))
    p = subprocess.run([str(tools().opt), '-passes=obfuscation', '-disable-output', str(path)],
                       capture_output=True, text=True)
    assert p.returncode != 0
    assert diagnostic in p.stderr
```

- [ ] **Step 2: 运行红测。** `python -m pytest -q utils/test_cloud_material_config.py`，当前未知 key 被忽略应导致断言失败。
- [ ] **Step 3: 实现配置和 strict 行为。** enum `CloudMaterialMode { Off, Session, Lease, Operation }`；新模式加入引擎 key 和 witness。任何已请求新云模式的 unsupported IR、门限、预算回滚和导出失败均编译错误，不只 sensitive=1 才拒绝。引擎不能与 legacy/plain cloud 混组。
- [ ] **Step 4: 明确基础格式的组合。** 新模式强制 constInStream；顶层 opcode 使用任务 4 的运行期 map，禁止叠加旧 encDispatch/keyedDispatch；构建时 reg/operand/semantic 编码仍可固定并登记。legacy AES/whitebox/强字节码加密路径被新版材料路径替代，报告明确 `replaced_by_cloud_material`，不得仍声称 lazy/whitebox 生效；显式冲突请求报错。native JIT 和 C 在基础阶段报未实现；不能把默认 max 中的选项悄悄忽略。

新模式从配置解析起走独立的材料归一化路径：不要把它伪装为 `encBytecode=0` 再触发旧逻辑关闭 constInStream/hardened。新增 witness `bytecodeSource=cloud_material`；本阶段组合 `preset=max`、显式白盒/lazy/旧 encDispatch/keyedDispatch 及 nestedVM 均明确拒绝，直到各项适配有测试。默认选项只在 effective 中明确标为被新路径取代。普通 `cloudMaterial=lease,materialRegion=auth` 必须能工作。
- [ ] **Step 5: 增量构建并验证。**

```bash
cmake --build "/data/user/0/com.termux/files/home/xollvm-android/build-sensitive" --parallel 6 --target opt clang VMRequirementsTests
python -m pytest -q utils/test_cloud_material_config.py utils/test_vm_max_config.py
"/data/user/0/com.termux/files/home/xollvm-android/build-sensitive/tools/Obfuscator/VMRequirementsTests"
```

检查同名不同模式区域的 engine key、ARM32 拒绝、budget rollback fatal；随后仅按用户要求提交 `feat: 增加严格云材料 VM 配置`。

### Task 3: 成功提交后导出规范区域，拆分公开与秘密产物

**Files:**
- Create: `include/llvm/Transforms/Obfuscator/VMPass_Material.h`, `VMPass_Material.cpp`
- Modify: `VMPass_Emitter.h`, `VMPass_Emitter.cpp`, `VMPass_Verifier.cpp`, `VMPass_Plan.cpp`, `CMakeLists.txt`
- Create: `tools/cloud-material/export.mjs`
- Test: `utils/test_cloud_material_export.py`, `cloud/material_v2/test/export.test.mjs`

**Interfaces:** `exportCanonicalRegion(const BytecodeEmitter&, const VMPassConfig&, const VMOpcodeMap&) -> llvm::Expected<llvm::json::Object>`；导出 §2.1；instruction_offsets 来源于现有私有 `InstructionIPs` 的只读快照。导出事务只在最终 committed 后发布。

- [ ] **Step 1: 写导出缺失与失败不留包红测。** 从 `transform` 生成带 `constInStream` 的算术、浮点、CALL、SWITCH fixture，验证导出包的 opcode offsets 可独立逐条解码；另用 budgetMax=1 触发失败，要求私有输出目录无已发布区域。

```python
def test_budget_failure_does_not_publish_material(tmp_path):
    import subprocess
    from vm_hardening_support import annotation, tools
    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    source = tmp_path / 'input.ll'
    source.write_text('target triple = "aarch64-linux-android26"\n'
                     'define i32 @f(i32 %x) { %r = add i32 %x, 7\n ret i32 %r }\n' +
                     annotation(['f'], 'vm(cloudMaterial=lease,materialRegion=auth,budgetMax=1)'))
    p = subprocess.run([str(tools().opt), '-passes=obfuscation',
                        f'-obf-material-export-dir={private}', '-disable-output', str(source)],
                       capture_output=True, text=True)
    assert p.returncode != 0
    assert not list(private.glob('*.region.json'))
```

- [ ] **Step 2: 运行红测。** `python -m pytest -q utils/test_cloud_material_export.py`。
- [ ] **Step 3: 导出真实发射记录。** const prologue 插入后的偏移必须修正；logical opcode 与 `E.BC` 的构建 physical opcode 一一匹配；变长尾不被当成 opcode。只导出编译器所需公开 callee ABI 摘要，不上传主机/目标绝对指针。`region_id` 对规范区域身份和 ABI 内容做哈希，而不是只 hash 名称。
- [ ] **Step 4: 实现私有文件事务。** 每次编译调用私有 staging 目录使用 0700、文件 0600；拒绝符号链接/覆盖冲突；从 coordinator 最终预算校验之后原子发布，任一失败不发布 manifest。多 TU 文件名使用 module content hash，重复相同内容幂等，不同内容同 region 名拒绝并列出不含秘密的身份。
- [ ] **Step 5: 实现聚合器。** `node tools/cloud-material/export.mjs --input-dir <绝对目录> --output-dir <新的绝对目录>` 生成 `public-manifest.json` 与独立 `registration.private.json`。公开摘要覆盖私有内容的 hash 而非内容，防同布局不同业务碰撞；build_id 计算时排除自身与最终 seal。输出不打印 bytecode/密钥；临时文件模式与失败行为写测试。
- [ ] **Step 6: 验证。**

```bash
cmake --build "/data/user/0/com.termux/files/home/xollvm-android/build-sensitive" --parallel 6 --target opt
python -m pytest -q utils/test_cloud_material_export.py
node --test cloud/material_v2/test/export.test.mjs
```

同 obf seed 的两次生产材料生成不能重用密码秘密；相同规范输入的内容身份一致。用户要求时提交 `feat: 导出云 VM 构建登记包`。

### Task 3B: 公开区域描述符与最小后链接回填

**Files:**
- Create: `tools/xollvm-elf-hardener/MaterialManifest.cpp`
- Modify: `tools/xollvm-elf-hardener/xollvm-elf-hardener.cpp`, `tools/xollvm-elf-hardener/CMakeLists.txt`
- Create: `utils/test_cloud_material_manifest.py`

**Interfaces:** 首次实现 `materials --input ELF --manifest PUBLIC_JSON --output ELF`。公开描述符采用 §2.2 XovmRegionDescriptor 的固定字段，编译器保留到 `.rodata.xovm.material`，后链接回填 build_id。包装 section 另有版本化记录头与大小，必须在任务0冻结，不能在解析器靠结构体 padding 猜偏移。

- [ ] **Step 1: 编写独立小 ELF fixture。** 使用 C 的 XovmRegionDescriptor，初始化 build_id 为全零和一个已知 region_id，不需要材料 wrapper 就能测试工具。通过 `utils/vm_hardening_support.py` 的 NDK 编译器链接，用不含秘密的 public manifest 配对。

```python
def test_material_descriptor_requires_matching_public_region(manifest_fixture):
    f = manifest_fixture
    p = f.finalize(f.wrong_region_manifest)
    assert p.returncode != 0
    assert f.output.exists() is False
    assert f.finalize(f.correct_manifest).returncode == 0
    assert f.read_descriptor()['build_id'] == f.expected_build_id
```

`manifest_fixture` 在本任务测试文件中实现完整 compile/finalize/read_descriptor 操作；read_descriptor 独立按固定字节格式读取，不通过被测工具的同一输出推断正确。
- [ ] **Step 2: 红测。** `python -m pytest -q utils/test_cloud_material_manifest.py`，当前工具不识别 materials 子命令而失败。
- [ ] **Step 3: 实现只读验证后原子回填。** 先校验 AArch64 ELF64LE、section 文件边界、记录尺寸、全零 pending build_id 或已完成且相同 ID、区域唯一性、ABI hash 和公开清单摘要。工具只读取公开清单，拒绝含私有 bytecode 字段的输入；未知/重复/不匹配区域全失败。已完成同一 ID 幂等，不再次生成不同记录。
- [ ] **Step 4: 构建并验证。**

```bash
cmake --build "/data/user/0/com.termux/files/home/xollvm-android/build-sensitive" --parallel 6 --target xollvm-elf-hardener
python -m pytest -q utils/test_cloud_material_manifest.py
```

本任务先交付独立后链接能力，任务8依赖它完成真实 fixture 的身份回填；任务9再集成正式链接、strip 与发布事务，避免循环依赖。用户要求时提交 `feat: 回填云材料公开区域描述符`。

### Task 4: 服务端本代重编码与真实配对验证

**Files:**
- Create: `cloud/material_v2/package.mjs`, `cloud/material_v2/test/package.test.mjs`
- Modify: `tools/cloud-material/format.mjs`
- Test: `utils/test_cloud_material_reencode.py`

**Interfaces:** `makePackage(region, binding, randomBytes)` 返回 §2.1 ExecutionPackage；randomBytes 是生产 `crypto.randomBytes` 或仅测试注入的确定生成器。返回值给协议加密，不能写进公开登记清单。

- [ ] **Step 1: 写有真实字节关系的测试。**

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {makePackage} from '../package.mjs';
test('只改opcode位置，逆映射恢复构建字节', () => {
  const region = {
    canonical_bc: Buffer.from([0, 7, 1, 9]).toString('base64'),
    instruction_offsets: [0, 2], logical_opcodes: [0, 1], opcode_count: 2,
    static_decode_descriptor: {decode_salt: 13}, engine_abi_hash: 'a'.repeat(64)
  };
  const binding = {build_id:'b'.repeat(64), region_id:'c'.repeat(64),
    session_id:'d'.repeat(64), generation:'1', request_hash:'e'.repeat(64),
    mode:'lease', lease_ms:120000, engine_abi_hash:'a'.repeat(64)};
  const pkg = makePackage(region, binding, randomBytes);
  const code = Buffer.from(pkg.encoded_bc, 'base64');
  assert.equal(pkg.decode_map[code[0]], 0);
  assert.equal(pkg.decode_map[code[2]], 1);
  assert.equal(code[1], 7);
  assert.equal(code[3], 9);
});
```

- [ ] **Step 2: 运行红测。** `node --test cloud/material_v2/test/package.test.mjs`。
- [ ] **Step 3: 实现无偏置 Fisher–Yates。** 使用拒绝采样取得区间随机整数，在 256 byte 域选择互异编码；建立 logical→byte 与 byte→build physical map。只写编译器导出的 instruction offsets；先检查 offsets 严格递增、范围、logical domain 和规范内容摘要。未知 byte→0xffff。
- [ ] **Step 4: 绑定并哈希完整 package 内容。** 覆盖 encoded_bc、map、decode descriptor、ABI 与 binding（计算 hash 时排除 package_hash 自身）。任务 5 将该 hash 纳入认证。测试互换两包 map/bytecode、篡改尾部/偏移、logical 重复关系错误，必须拒绝；多次包不同不能仅检查 nonce 不同。
- [ ] **Step 5: 跨语言还原验收。** `utils/test_cloud_material_reencode.py` 调用真实编译导出、Node 生成、C++ parser 和 verifier。逆映射恢复后逐字节等于构建字节码，并检查指令边界、分支及 CALL ABI；不是只做 encrypt/decrypt 自循环。

```bash
node --test cloud/material_v2/test/package.test.mjs
python -m pytest -q utils/test_cloud_material_reencode.py
```

用户要求时提交 `feat: 生成与构建匹配的会话执行包`。

### Task 5: 认证协议、构建登记与续期服务

**Files:**
- Create: `cloud/material_v2/protocol.mjs`, `store.mjs`, `service.mjs`
- Create: `runtime/cloud_material/material_protocol.h`, `material_protocol.cpp`
- Create: `cloud/material_v2/test/protocol.test.mjs`, `service.test.mjs`
- Test: `utils/test_cloud_material_protocol.py`

**Interfaces:** 按任务 0 获批 wire format；`authenticateResponse(response, pendingRequest) -> VerifiedPackage`，VerifiedPackage 私有构造且只能由认证路径创建。`issueMaterial` 消费可信 auth 与事务 store。测试 bridge 可签发临时材料，但该入口不链接生产库。

- [ ] **Step 1: 写身份错配和独立密码向量测试。** Node/OpenSSL 对固定的公开测试 ephemeral keys、签名和 AEAD 向量互通；错误签名、错误 AAD、截断 tag、all-zero ECDH、request hash 替换均失败。不得引用用户真实 JS 配置。

```python
import pytest
from cloud_material_support import build_material_harness, run_material_case

@pytest.mark.parametrize('case', [
    'wrong_request_hash', 'wrong_ephemeral_key', 'wrong_region',
    'bad_tag', 'truncated_envelope', 'zero_shared_secret', 'unknown_key_id',
])
def test_authentication_rejects_mismatched_material(tmp_path, case):
    exe = build_material_harness(tmp_path, sources=('material_protocol.cpp',))
    result = run_material_case(exe, case)
    assert result['accepted'] is False
    assert result['published_generations'] == 0
```

- [ ] **Step 2: 运行红测。** `python -m pytest -q utils/test_cloud_material_protocol.py` 与 `node --test cloud/material_v2/test/protocol.test.mjs cloud/material_v2/test/service.test.mjs`。
- [ ] **Step 3: 实现协议和 secret 生命周期。** OpenSSL EVP 原语与 Node crypto 使用相同字节定义；认证后校验 package_hash 及任务 1 的完整结构。清理临时 private/shared/KDF buffer，避免字符串日志和 core 输出含真实材料；不承诺碎片无捕获点。认证来源不能由一个 public bool 标志伪造。
- [ ] **Step 4: 实现登记与事务接口。** pending→validated→enabled 原子启用；对登记文件 content hash 重算，不信任上传声明。lease_valid/revoked/software 由 trusted auth 判定；一个会话有多个区域各自 generation。请求幂等映射与 generation 递增同事务保存；跨会话 key 不可复用。测试并发两次续期、吊销穿插、相同 ID 不同请求、响应丢失重试。
- [ ] **Step 5: 封闭生产入口。** store 未提供跨实例事务/持久性或 trusted auth 适配器时返回启动错误；不能用内存 Map 给出 production ready。生产部署配置从环境或托管密钥读取，只有公钥/版本进入客户端。编写 adapter 合同测试，部署未具备条件时保留明确阻塞状态。
- [ ] **Step 6: 重跑协议测试。** 检查独立已知答案、跨语言一致及拒绝路径；用户要求时提交 `feat: 认证云 VM 材料与事务化续期`。

### Task 6: 分代材料库、单调租约与活跃调用

**Files:**
- Create: `runtime/cloud_material/material_store.h`, `material_store.cpp`, `material_runtime.cpp`
- Create: `utils/fixtures/cloud_material/lease_harness.cpp`
- Test: `utils/test_cloud_material_lease.py`, `utils/test_cloud_material_lifecycle.py`

**Interfaces:** C++ `MaterialStore::publish(VerifiedPackage, RequestTiming)`、`acquire(region, nowNs) -> PinnedMaterial`、`release`；RequestTiming 保留原请求 `sent_boot_ns/received_boot_ns`。接口不得接受未认证包。生产时钟 `CLOCK_BOOTTIME`，测试可注入 FakeClock。

- [ ] **Step 1: 写边界和保留调用测试。**

```python
from cloud_material_support import build_material_harness, run_material_case

def test_expiry_blocks_new_call_but_preserves_pinned_call(tmp_path):
    exe = build_material_harness(tmp_path, sources=('material_store.cpp',))
    r = run_material_case(exe, 'pin_at_119_expire_at_120')
    assert r['old_call_completed'] is True
    assert r['new_call_acquired'] is False
    assert r['old_bytes_live_until_release'] is True
    assert r['old_bytes_cleared_after_release'] is True

def test_late_retry_keeps_original_deadline(tmp_path):
    exe = build_material_harness(tmp_path, sources=('material_store.cpp',))
    r = run_material_case(exe, 'same_request_late_retry')
    assert r['deadline_ns'] == r['original_sent_ns'] + 120_000_000_000
    assert r['accepted_after_deadline'] is False
```

- [ ] **Step 2: 运行红测。** `python -m pytest -q utils/test_cloud_material_lease.py utils/test_cloud_material_lifecycle.py`。
- [ ] **Step 3: 实现期限计算。**

```cpp
// 先做溢出与D范围检查；生产时钟由CLOCK_BOOTTIME提供。
deadline = checkedAdd(sentBootNs, leaseNs);
renewAt = checkedAdd(sentBootNs, leaseNs > tenSeconds ? leaseNs - tenSeconds : 0);
// now == deadline 已过期，不能使用小于等于判断延长一次调用。
if (nowBootNs >= deadline) {
    return AcquireError::Expired;
}
```

固定 120 秒时 renewAt=110 秒。重试沿用请求 t0；睡眠/系统日期变更不改变 deadline。短租约提前续期；A 不设置 B 的期限。
- [ ] **Step 4: 实现不可变代与线性化 acquire。** 单锁内验证当前 generation 未过期并建立引用；锁外执行。publish 只接收更高且匹配同会话区域的新代；旧代置 retired、拒绝新获取、引用清零才安全清理。引入可注入零化观察器仅测试，不导出生产 bypass。候选在锁外构造/认证。
- [ ] **Step 5: 生命周期回归。** FakeClock 跳到 120/180 秒，验证空闲不触发故障；两线程一个 pin 旧代一个发布新代，结果各自一致；递归新入口不能继承过期代；shutdown 先阻止新获取，再回收预取/引用。fork 后 PID/会话校验拒绝旧句柄，子进程不得触碰继承的锁和网络对象后再声称重连；首版规定子进程 exec/reinitialize 支持条件并测试明确拒绝。
- [ ] **Step 6: 运行上述测试及现有生命周期回归。**

```bash
python -m pytest -q utils/test_cloud_material_lease.py utils/test_cloud_material_lifecycle.py utils/test_zone_runtime_concurrency.py
```

测试必须实际阻塞/释放线程，不能只断言配置文本。用户要求时提交 `feat: 实现调用固定的云材料租约`。

### Task 7: demo 网络适配与生产 runtime 构建

**Files:**
- Create（集成仓库）: `demo/jni/zone_runtime/material_transport.h`, `material_transport.cpp`
- Modify（集成仓库）: `demo/jni/zone_runtime/zone_wrapper.h`, `zone_wrapper.cpp`, `demo/jni/Android.mk`
- Test（编译器仓库）: `utils/test_cloud_material_transport.py`

**Interfaces:** Transport `requestRegion(region, PendingRequest) -> authenticated response bytes`；zone 初始化建立可信 auth 与 service 会话，C ABI 仍由任务 6 提供。runtime 核心源由 `XOLLVM_MATERIAL_SOURCE_ROOT` 指向编译器仓库。

- [ ] **Step 1: 写无网络锁与退出竞态红测。** fake Zone helper 卡住一次 material 请求，主线程继续取得尚有效的当前代并结束调用；shutdown 标记关闭且请求完成后不能发布旧会话结果。

```python
def test_blocked_refresh_does_not_lock_current_generation(transport_binary):
    from cloud_material_support import run_material_case
    r = run_material_case(transport_binary, 'refresh_blocked_current_call_finishes')
    assert r['call_finished_before_network_release'] is True
    assert r['published_after_shutdown'] == 0
```

- [ ] **Step 2: 运行红测。** `python -m pytest -q utils/test_cloud_material_transport.py`。
- [ ] **Step 3: 实现薄适配。** zone state 锁内快照软件/设备/会话及 SDK 生命周期引用，锁外网络；返回时重新验证会话 epoch，再交任务 5 认证。不能照搬旧 dispatch refresh 在整个网络请求期间持有状态锁的模式。SDK 若不支持并发，使用独立请求队列而非材料库锁。
- [ ] **Step 4: 实现有界预取。** 首次110秒触发，截止前小范围抖动退避；请求/响应体有上限、超时可取消、session close 中断等待。没有有效材料的真实入口允许一次有界同步刷新；请求失败才同步故障。后台只记录状态。
- [ ] **Step 5: 独立 runtime NDK 模块。** C++20，完整静态 libcrypto 依赖与 `-static-libstdc++`；不要把网络/密码 bootstrap 也注解成需要本协议授权的云 VM，避免启动循环依赖。自动扫描源文件时排除重复 material 模块源。保留已有 capability_client.cpp 用户修改。
- [ ] **Step 6: 验证。**

```bash
python -m pytest -q utils/test_cloud_material_transport.py utils/test_zone_runtime_concurrency.py
```

真实 NDK 构建在集成仓库 `demo` 工作目录运行 `bash "/data/user/0/com.termux/files/home/android-ndk-r30-ollvm-r23-beta3/ndk-build" -j2 V=0`。先确认构建目录存在及普通用户属主，产物不提交。用户要求提交时两个仓库分别精确 stage，消息 `feat: 接入云材料运行时网络适配`。

### Task 8: 生成真正消费云材料的 VM wrapper 和分发

**Files:**
- Modify: `VMPass_Material.cpp`, `VMPass_Impl.cpp`, `VMPass_Crypto.cpp`, `VMPass_Wrapper.cpp`
- Modify: `VMPass_Impl.h`, `VMPass_Dispatch.cpp`, `VMPass_Requirements.cpp`, `VMPass_Plan.cpp`
- Modify: `utils/cloud_material_support.py`
- Create: `utils/test_cloud_material_native.py`, `utils/fixtures/cloud_material/native.c`

**Interfaces:** 使用 §2 C ABI。新增材料引擎参数 `ptr material_decode_map`，按 engine key 独立签名；旧引擎参数不改变。wrapper 从 view 取 BC、size、decode_salt、map；函数固定句柄直到正常返回。

该任务的 native fixture 使用任务3B的 `materials` 命令，先回填真实 build_id，再执行现有 targets/audit/seal/verify；不能为方便测试而让生产 acquire 接受全零 build_id。

- [ ] **Step 1: 编写真实结果与无材料故障红测。** `build_cloud_fixture` 使用真实 opt/NDK/native runtime，导出区域后通过本地 Node 临时密钥服务签发包。返回 `exe/public_manifest/private_registration/report/work`。`issue_fixture_package` 使用真实 makePackage+协议，不用伪造指针；`run_cloud_fixture` 在独立进程执行并返回 value、exit_signal、side_effects、generation。

```python
from cloud_material_support import build_cloud_fixture, issue_fixture_package, run_cloud_fixture

def test_valid_package_executes_and_missing_package_has_no_side_effect(tmp_path):
    f = build_cloud_fixture(tmp_path, mode='lease')
    pkg = issue_fixture_package(tmp_path, f, generation=1, mode='lease')
    ok = run_cloud_fixture(f, [pkg])
    assert ok['value'] == 11299
    missing = run_cloud_fixture(f)
    assert missing['exit_signal'] == 'SIGTRAP'
    assert missing['side_effects'] == 0
```

fixture 包含 `(703 * 17 + 23) ^ 0x5a ^ 703`，结果为 11299，与当前生产 fixture 对齐，并在保护体中经外部写入可观察 pipe 产生副作用；缺材料时不能到达写入。测试实现计算参考值，避免仅照搬预期常量造成误判。
- [ ] **Step 2: 运行红测。** `python -m pytest -q utils/test_cloud_material_native.py`。
- [ ] **Step 3: 接入 commit。** 新模式不执行旧 buildBytecodeGlobal/buildEncryptCtor 白盒或静态密钥路径。导出的规范内容仅在私有记录中；客户端 public descriptor 保存区域与 ABI。constInStream 的整数/浮点常量序列进入远端载荷，wrapper 不再保留等价计算。参数、公开 callee 和全局指针初始化保留，但不得当成业务字节码副本。
- [ ] **Step 4: wrapper 首先 acquire/view。** 在任何保护业务调用/写入之前取得句柄，按 view 初始化引擎参数。engine call 不可 tail-call 越过 release；从 RetStorage 取值后 release，覆盖 void/i32/i64/ptr/f64 多返回。未支持 EH/longjmp 编译失败；ordinary callee 的异常不允许穿过该边界。
- [ ] **Step 5: 两条分发使用动态 map。** 在读取 opcode 后以原 byte 索引256项 map，取得构建 physical opcode，再按已有 handler/variant 机制分发；无效映射同步 trap。不要对每个 operand byte 套 opcode map；CALL/SWITCH 变长尾保持原格式。所有 loadBC 读取来自本代 bytecode，不重建 legacy 固定 offset。
- [ ] **Step 6: 跨代与组合结果。** 生成两个不同本代编码，分别取得相同业务输出；互换 map 后拒绝；不同区域、central/threaded、多返回与长调用轮换一致。嵌套 helper 首版使用明确继承外层材料的策略，无法覆盖则显式拒绝 nestedVM，witness 中不得声称已支持。

```bash
cmake --build "/data/user/0/com.termux/files/home/xollvm-android/build-sensitive" --parallel 6 --target opt clang VMRequirementsTests
python -m pytest -q utils/test_cloud_material_native.py utils/test_vm_pipeline_lifecycle.py utils/test_vm_max_config.py
"/data/user/0/com.termux/files/home/xollvm-android/build-sensitive/tools/Obfuscator/VMRequirementsTests"
```

用户要求时提交 `feat: 让 VM 实际依赖配对云执行包`。

### Task 9: 最终 ELF 身份、原生回退审计与发布事务

**Files:**
- Modify: `tools/xollvm-elf-hardener/MaterialManifest.cpp`（任务3B已创建）
- Modify: `tools/xollvm-elf-hardener/xollvm-elf-hardener.cpp`, `tools/xollvm-elf-hardener/CMakeLists.txt`, `tools/xollvm-link`
- Modify: `tools/cloud-material/export.mjs`, `ObfReport.cpp`, `VMPass_Requirements.cpp`
- Test: `utils/test_cloud_material_delivery.py`

**Interfaces:** 集成任务3B已有的 `materials --input <ELF> --manifest <公开清单> --output <ELF>`；回填 descriptor build_id/region identity，禁止接受私有包。`verify` 自动验证存在的 material manifest。link 顺序 `link → materials → targets → audit → seal → verify → 原子替换`。

- [ ] **Step 1: 写最终产物负例。** 未回填 build_id 的 ELF、新模式 wrapper 仍保留本地 bytecode、丢失一个区域、同名不同 ABI、strip 后再 seal 及 seal 后修改各有独立断言。

```python
def test_link_failure_keeps_previous_delivery(delivery_fixture):
    f = delivery_fixture
    before = f.output.read_bytes()
    result = f.link_with_manifest(f.manifest_with_wrong_region)
    assert result.returncode != 0
    assert f.output.read_bytes() == before
    assert not f.cloud_store.build_enabled(f.requested_build_id)
```

`delivery_fixture` 在本任务测试文件中创建独立临时 linker 输入、公开/私有 manifest 和任务 5 的测试 store；不连接线上服务。
- [ ] **Step 2: 运行红测。** `python -m pytest -q utils/test_cloud_material_delivery.py`。
- [ ] **Step 3: 实现身份与顺序。** build_id 由公开内容清单计算，自身和最终 seal 摘要排除；最终 ELF SHA-256 在 verify 后登记到云端授权构建记录，不回写形成循环。所有命令使用 argv 数组，拒绝相对越界 secret path、符号链接替换及已存在不匹配输出。
- [ ] **Step 4: 原生回退结构审计。** 检查所有声明保护区域的 wrapper 都引用正确 descriptor 和 material ABI、原始函数体已替换；检查离线 key/白盒/bytecode 保留链。静态扫描只作证据之一，配合无材料真实运行和任务 10 补丁试验。最终 strip 与 codegen 后重复检查真实引用，不能只看 IR 名字。
- [ ] **Step 5: 两段发布。** 秘密登记 pending，产物 verify 后以匹配最终摘要启用，启用成功才发布新交付文件。任一步失败保留旧交付，不能自动泄漏私有登记文件到输出目录。witness 分开 compiler_committed、material_finalized、server_enabled；离线构建不能伪造 server_enabled。
- [ ] **Step 6: 验证。**

```bash
cmake --build "/data/user/0/com.termux/files/home/xollvm-android/build-sensitive" --parallel 6 --target xollvm-elf-hardener
python -m pytest -q utils/test_cloud_material_delivery.py utils/test_vm_target_encoding.py
```

目标编码回归文件已核对为 `utils/test_vm_target_encoding.py`。用户要求时提交 `feat: 校验云材料最终产物与构建登记身份`。

### Task 10: 端到端验收、补丁证据与交付边界

**Files:**
- Create: `utils/test_cloud_material_acceptance.py`, `utils/cloud_material_acceptance.py`
- Modify: `utils/production_acceptance.py`（仅新增可显式选择的入口，不替换旧验收）
- Modify: `docs/obf_annotations.h`, `docs/项目功能与命令总览.md`
- Create: `cloud/material_v2/README.md`（与该服务交付直接相关的启动/配置说明，无凭据）

**Interfaces:** 新 CLI `python utils/cloud_material_acceptance.py offline|live --project PATH --tools PATH --output PATH`；报告包含工具/构建 hash、阶段、case、expected/actual、状态与证据文件。live 凭据只经环境，不在命令或 JSON 中。

- [ ] **Step 1: 写会拒绝虚假通过的验收测试。**

```python
def test_crash_without_material_fault_evidence_is_not_success():
    from cloud_material_acceptance import validate_case, AcceptanceError
    import pytest
    with pytest.raises(AcceptanceError):
        validate_case({'case':'expired_new_call','exit_signal':'SIGTRAP',
                       'side_effects':0,'fault_origin':'unrelated'})
```

`validate_case(row)` 同时检查 acquire fault 同线程调用现场、区域与代身份、业务副作用和期望结果；不能仅匹配 stderr 文本。
- [ ] **Step 2: 运行红测。** `python -m pytest -q utils/test_cloud_material_acceptance.py`。
- [ ] **Step 3: 实现功能矩阵。** A 正常/重启、B 110预取/120新调用拒绝/119调用完成/睡眠/晚响应/恢复，mixed A继续而B拒绝，C明确拒绝未实现；每组真实 native 差分结果。FakeClock 测精确边界；live 另测真实120秒，不用 FakeClock 冒充联网证明。
- [ ] **Step 4: 实现补丁矩阵。** 在测试副本中分别固定 acquire 结果为0/1、绕过认证、混搭配对数据、冻结时钟、重放完整合法旧代、截取明文载荷。固定值必须不能恢复正确结果；重放若能成功必须记录 `RECOVERED`，不能转成通过或删除用例。每条有未修改对照及合法材料正对照。
- [ ] **Step 5: 保持结果分层。** 功能通过、协议通过、攻击恢复、预算内未恢复、工具错误分别统计。部署适配器缺失/未批准、没有卡密时 live 标记 `BLOCKED`，不计 PASS。C/JIT 未完成单独列状态，基础版本不得宣传三个模式已全部完成。
- [ ] **Step 6: 全套验证及证据。** 输出路径先确认不存在，使用独立目录：

```bash
ls "/data/data/com.termux/files/usr/tmp/opencode"
PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -rs -o tmp_path_retention_policy=failed --basetemp="/data/data/com.termux/files/usr/tmp/opencode/cloud-material-foundation-pytest-001" --junitxml="/data/data/com.termux/files/usr/tmp/opencode/cloud-material-foundation-pytest-001.junit.xml"
node --test cloud/material_v2/test/codec.test.mjs cloud/material_v2/test/export.test.mjs cloud/material_v2/test/package.test.mjs cloud/material_v2/test/protocol.test.mjs cloud/material_v2/test/service.test.mjs
python utils/cloud_material_acceptance.py offline --project "/data/user/0/com.termux/files/home/xollvm-android" --tools "/data/user/0/com.termux/files/home/xollvm-android/build-sensitive/bin" --output "/data/data/com.termux/files/usr/tmp/opencode/cloud-material-foundation-offline-001"
python utils/production_acceptance.py arm32 --project "/data/user/0/com.termux/files/home/xollvm-android" --tools "/data/user/0/com.termux/files/home/xollvm-android/build-sensitive/bin" --ndk "/data/user/0/com.termux/files/home/android-ndk-r30-ollvm-r23-beta3" --output "/data/data/com.termux/files/usr/tmp/opencode/cloud-material-foundation-arm32-001"
```

live 仅在任务0部署条件满足且环境已有卡密时执行：

```bash
python utils/cloud_material_acceptance.py live --project "/data/user/0/com.termux/files/home/xollvm-android" --tools "/data/user/0/com.termux/files/home/xollvm-android/build-sensitive/bin" --output "/data/data/com.termux/files/usr/tmp/opencode/cloud-material-foundation-live-001"
```

- [ ] **Step 7: 更新使用说明与交付记录。** 列出支持/拒绝的明确配置、初始化、构建登记、120/110计时起点、活跃旧调用限制、退出和真实云前置条件。只报告已跑结果；用户要求时提交 `test: 验收云 VM 材料依赖与租约边界`。

---

## 3. 规格覆盖与基础阶段停止条件

| 总规格章节 | 对应任务/后续关口 |
| --- | --- |
| 1–4 目标、模式、组件 | 契约、任务2/6/10 |
| 5 构建秘密登记与身份 | 任务3/3B/5/9 |
| 6 配对执行包与真实依赖 | 任务3/4/8 |
| 7 协议 | 任务0专项审核、任务1/5/7 |
| 8 租约时间 | 任务6/7/10 |
| 9 生命周期 | 任务6/8 |
| 10 C 级 | 任务2明确拒绝、任务10报告边界；具体业务专项规格后实施 |
| 11 动态 handler/chaff | 保留专项可行性与设计审核，基础阶段不宣称已实现 |
| 12 交付与兼容 | 任务2/9/10 |
| 13 验收 | 任务10，旧模式回归与真实云分开统计 |

基础阶段结束必须同时有：实际 A/B native 输出、编译/登记/执行配对、无本地完整回退、租约与并发测试、协议负例、最终 ELF 证据和捕获重放结果。仅完成协议模块或仅出现 SIGTRAP 不算基础阶段交付。

生产部署缺乏可信宿主或持久事务时停止在“离线参考实现已验证、生产部署阻塞”，不擅自换基础设施。整体三模式项目在 C 专项和动态执行专项验收前保持未完成状态。

## 4. 执行方式与下一阶段

本计划需用户审核并选择内联执行或分任务代理执行；此前不修改产品代码。任务0是首个执行项，专项规格批准前不实现其密码协议。用户未要求新的 Git 提交时只保留工作区修改。

基础阶段通过后按顺序进入 C 级具体操作规格、native handler 动态执行可行性规格及各自实施计划。每个阶段独立呈现实际能力与攻击结果，不把阶段批准扩展成未写出的后续方案批准。
