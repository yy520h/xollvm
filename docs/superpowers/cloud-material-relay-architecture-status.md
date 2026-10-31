# XOVM2 Cloud Material Relay 架构状态

更新时间：2026-10-25

关联设计：

- `docs/superpowers/specs/2026-10-22-cloud-material-relay-design.md`
- `docs/superpowers/plans/2026-10-22-cloud-material-relay-cpp-plan.md`
- `.superpowers/sdd/2026-10-22-cloud-material-relay-cpp-plan/progress.md`

## 结论

当前架构已经完成了**本地可验证的 C++ relay backend 主体闭环**，包括：

- 固定 XOVM2 协议和 canonical request 校验
- SQLite 管理面与 immutable build snapshot
- 内存授权策略、session/replay/idempotency 状态
- checksummed application WAL、checkpoint、恢复和单写者锁
- loopback HTTP transport、固定 route、独立 relay/admin credential
- startup readiness 和 fail-closed
- provider registry 和 linked provider hook
- admin import/enable/revoke
- 本地 test-only provider 进程验收
- WAL 重启后的 exact response replay

但是，架构还没有达到“生产可部署完成”。当前准确状态是：

> **核心架构和接口已闭环；生产适配器、真实密钥、真实材料签发、TLS/deployment 和 live acceptance 尚未完成。**

不能把当前 test provider fixture、Node reference backend 或本地 HTTPS proxy 视为生产实现。

## 完成度矩阵

| 架构部分 | 当前状态 | 说明 |
|---|---|---|
| Zeno 双模式分流 | 已有实现，未在本 worktree 重复修改 | 父工作区已有 `capability_v1`/`xovm2_relay` 显式分流和固定 HTTPS `/v2/relay` 测试 |
| XOVM2 canonical protocol | 已完成 | 保留原始 canonical bytes，拒绝重复 key、非 canonical JSON、非法 base64、错误 suite/type |
| C++ relay HTTP boundary | 已完成本地实现 | 仅 loopback，固定 route，body/header/response limit，独立 relay/admin auth，TLS 由 proxy 终止 |
| SQLite admin repository | 已完成本地实现 | import、enable、revoke、事务、schema 检查、sidecar/hash 校验 |
| Immutable build snapshot | 已完成本地实现 | startup/admin refresh 时从 SQLite 加载，runtime request 不查询 SQLite |
| Snapshot revoke ordering | 已完成本地实现 | durable revoke 后阻断 issuance，发布新 snapshot，刷新 policy；失败时 fail closed |
| Anonymous policy | 接口和本地逻辑完成 | 当前真实 provider 尚未提供；test fixture 只生成简单规则 |
| Session/replay/idempotency | 已完成本地实现 | session control、nonce/key replay fence、exact retry、generation/counter 约束 |
| Application WAL | 已完成本地实现 | checksummed frame、fdatasync boundary、恢复、corruption handling |
| Checkpoint/recovery | 已完成本地实现 | atomic rename、directory fsync、WAL retirement、sequence continuity、fault hooks |
| Provider registry | 已完成接口设计 | provider 名称只做选择；实际实现通过 in-process resolver/weak linked hook 注入 |
| Runtime admin API | 已完成本地实现 | `/import`、`/{id}/enable`、`/{id}/revoke`，closed schema 和权限边界 |
| Trust route | transport 已完成 | 真实 trust bundle provider 尚未接入 |
| `session.open` 进程验收 | 已完成 test-only fixture | 真实 backend 进程完成 admin -> enable -> relay -> revoke 流程，Node 端验证加密响应 |
| restart exact replay | 已完成 test-only fixture | 同一 SQLite/WAL 目录重启后，相同请求返回完全相同 HTTP response |
| `material.issue` 进程验收 | 已完成 test-only fixture | fixture 从 immutable snapshot 构造 package，真实进程完成 session -> issue -> revoke 流程 |
| 客户端解密/材料包端到端验收 | 已完成 fixture 验收 | Node 客户端验证 trust bundle、Ed25519 签名、X25519/AEAD、binding、generation 和 package parser |
| 真实生产 provider | 未完成 | 尚无真实 trusted time、signing key、CSPRNG、policy、trust root 等 adapter |
| 真实 TLS/mTLS/CA | 未完成 | 只有本地 reverse-proxy fixture，没有生产证书链和 hostname/mTLS 验证 |
| 真实部署 | 未完成 | 没有 service manager、非 root 账号、secret provisioning、监控和备份演练 |
| live production acceptance | 未完成 | 尚未部署，也没有真实 endpoint/credentials/live test |

## 已完成的架构闭环

### 1. 请求路径

当前 request path 已符合设计的主要约束：

```text
Zeno xovm2_relay
  -> fixed HTTPS /v2/relay
  -> loopback C++ HTTP server
  -> relay credential check
  -> canonical envelope/request validation
  -> immutable BuildSnapshot authorization
  -> AnonymousPolicy authorization
  -> SessionState transaction
  -> application WAL append + sync
  -> exact response publication
```

请求期不从 SQLite 读取 registration/verifier 数据。SQLite 只在 startup 和 admin refresh 阶段参与 snapshot 构建。

### 2. 管理路径

当前管理路径为：

```text
admin credential
  -> closed JSON admin request
  -> provider admin authorization
  -> registration/artifact evidence validation
  -> SQLite durable mutation
  -> complete BuildSnapshot reload
  -> atomic snapshot publication
  -> policy rebuild
```

enable/revoke 后 policy 会根据新 snapshot 原子替换。revoke 后旧 policy rule 不会继续保留。

### 3. 状态和恢复路径

当前状态路径为：

```text
SessionState draft
  -> WAL frame
  -> checksum validation
  -> fdatasync
  -> in-memory state publication
  -> exact response return
```

重启时：

```text
process lock
  -> checkpoint recovery
  -> WAL replay
  -> SessionState restore
  -> provider/snapshot validation
  -> listener start
  -> healthz ready
```

当前本地进程测试已经证明 committed response 可以在重启后按相同请求 exact replay。

## 仍缺少的代码工作

### 1. 完整 `material.issue` provider fixture

这一项已完成 test-only fixture；生产 provider 仍然缺失，见后面的真实环境部分。

需要补充 test-only linked provider 的 `build_payload`，使真实进程能够：

- 根据 build/region 从 immutable snapshot 读取验证后的 registration/sidecar
- 构造符合 XOVM2 package schema 的 payload
- 绑定 `build_id`
- 绑定 `region_id`
- 绑定 `session_id`
- 绑定 `request_hash`
- 绑定 generation/counter
- 返回 `ProtocolService::IssuedPayload`
- 经过现有 X25519/AEAD/Ed25519 response sealing

测试客户端现在会解密 response，并用现有 material package parser 验证 package；同一 SQLite/WAL 目录重启后，`material.issue` 也会 exact replay。

### 2. 独立的完整 acceptance harness

当前 `utils/test_cloud_material_backend_provider_fixture.py` 已覆盖 session.open、material.issue、Node 客户端验收、revoke 和两类 response 的 restart replay，但还不是完整的 Task 7 acceptance harness。

还应补充进程级测试：

- append 失败
- sync 失败
- checkpoint 写入失败
- checkpoint rename 失败
- directory fsync 失败
- covered WAL retirement 失败
- counter/generation continuity
- nonce/key replay fence
- checkpoint restore 后继续写 WAL
- response loss 后 retry

已有很多 C++ fault-injection 单元测试，但还没有全部提升到真实进程编排层。

### 3. Admin malformed-input 和并发回归

还可以补充：

- duplicate JSON key
- non-object JSON
- invalid padding/base64 boundary
- empty/non-canonical sidecar
- oversize field
- import same identity/same content idempotency
- import same build/different content conflict
- enable/revoke concurrent race
- policy refresh failure 后 durable DB 与 fail-closed snapshot 的重建行为

这些不是当前架构的主缺陷，但属于生产前应完成的防回归覆盖。

### 4. C++ provider contract 的真实 payload 约束

`RuntimeProviderBundle` 已定义 provider role 和 capability，但生产前还应进一步固定：

- `build_payload` 输出字段的完整 schema
- trust bundle payload schema
- admin evidence 的证据格式
- trusted time 的错误和有效区间语义
- signing metadata 的 `not_after`、bundle validity、trust epoch 规则
- provider callback 抛异常时的统一错误语义

当前接口已能 fail closed，但部分 payload 语义仍依赖外部 adapter contract。

## 必须由真实环境补齐的部分

### 1. Trusted time

需要实际 provider，而不是 fixture 中固定的 `1000`：

- 可信时间来源
- 时间失效和回退处理
- monotonic/expiry 窗口证明
- 时间与 signing bundle 有效期的一致性

### 2. Signing key 和 CSPRNG

需要真实：

- Ed25519 private key provider
- X25519 ephemeral random source
- key id
- trust epoch
- key not-after
- bundle-valid-until
- key rotation
- retired/revoked key 行为

私钥不能进入 SQLite、source control、container layer、日志或 relay response。

### 3. Registration/artifact validation

需要把真实发布工具链接入 provider：

- public manifest/private registration membership
- verifier sidecar 完整性
- build/software/region identity
- final artifact hash
- ELF/material section 和 verifier 证明
- artifact evidence 的生成和验证

当前 fixture 的 `validate_pair` 和 `validate_final_artifact` 是测试逻辑，不能作为生产验证器。

### 4. Anonymous policy 和 admin authorization

生产需要明确：

- 哪些 build 可 anonymous session
- 哪些 region 可 issue
- session/lease lifetime
- rate/budget
- publisher/revoker identity
- admin scope
- software/build ownership
- revoke 和 rotation 流程

当前 fixture 的 admin authorization 是无条件授权，不能用于生产。

### 5. Material payload builder

生产必须提供真实 material builder/issuer。没有它，C++ backend 只能完成 session control，不能完成最终材料发放。

这也是当前从“协议 backend 可运行”到“产品功能可用”的关键缺口。

### 6. Trust bundle

需要真实 trust bundle provider：

- public key
- key id
- trust epoch
- validity window
- revoked key list/state
- bundle signature
- public software route
- client bootstrap path

当前 `/v2/trust/fixture.software` 只返回测试 bytes。

### 7. TLS、mTLS 和 reverse proxy

当前 C++ backend 按设计只监听 `127.0.0.1`，TLS 由 trusted reverse proxy 终止。

生产还需要：

- CA chain
- backend/proxy certificate
- hostname verification
- mTLS client certificate（如部署要求）
- proxy 到 backend 的身份认证
- fixed path forwarding
- redirect/compression policy
- certificate rotation

本地 HTTPS fixture 只能证明 transport contract，不能证明生产证书配置。

### 8. 部署和运维

还需要 operator 执行并验收：

- dedicated non-root service account
- binary/read-only migration 权限
- SQLite/WAL/state 目录权限
- secret provisioning
- secret rotation
- service manager 配置
- health/readiness monitoring
- redacted error/logging policy
- disk-full response
- SQLite/WAL/checkpoint backup
- isolated restore drill
- single-instance lock 运行规则

当前只提供 `runtime/cloud_material_backend/deploy/README.md`，没有部署脚本或 service-manager unit。

## 当前验证证据

已完成的本地验证：

- Native CTest：`12/12`
- ASan/UBSan CTest：`12/12`
- Node material suite：`113/113`
- Provider-backed process acceptance：通过
- Provider-backed `material.issue` client authentication/package acceptance：通过
- Provider-backed `session.open` client authentication acceptance：通过
- Revoke 后新 `material.issue` 请求拒绝：通过
- Restart exact replay acceptance：通过
- `git diff --check`：通过

尚未获得有效结果的验证：

- 依赖 LLVM/NDK 工具链的完整 Python regression suite
- 真实 provider adapter 验收
- 真实 material.issue 客户端端到端验收
- 真实 CA/mTLS
- 真实备份恢复和 disk-full 演练
- live deployment/live endpoint 验收

Python 测试之前因当前环境缺少 `XOLLVM_OPT`、完整 `XOLLVM_PROJECT_ROOT` 工具链和 `build-sensitive/bin/opt` 而失败。这属于测试环境未准备好，不能被记录为代码通过，也不能被误报为代码失败。

## 推荐完成顺序

1. 将 append/sync/checkpoint/restart 故障注入扩展到进程 acceptance harness。
2. 固定并评审真实 provider contract，尤其是 material payload、trust bundle、trusted time 和 admin evidence。
3. 接入真实 provider，但保持未配置 provider 时默认 binary fail closed。
4. 完成生产 signing/CSPRNG/trusted time/registration/artifact/policy/admin/trust adapters。
5. 配置 CA/mTLS/reverse proxy 和非 root service manager。
6. 准备真实 secrets、备份恢复、rotation、disk-full 和监控演练。
7. 部署后再执行 live acceptance；在此之前不要宣称 production ready。

## 最终判断

如果“架构完成”指的是**组件边界、数据流、状态持久化、fail-closed 规则和本地测试骨架已经确定并能运行**，答案是：**基本完成**。

如果“架构完成”指的是**真实生产系统可以部署并发放真实 material**，答案是：**还没有**。

当前最大的两个缺口是：

1. 真实 `material.issue` payload builder/issuer；
2. 真实 provider、密钥、TLS 和部署环境。
