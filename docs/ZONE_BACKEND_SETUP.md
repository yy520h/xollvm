# Zone 后台配置

第一阶段只支持“卡密登录后调用云算法”的模式。云算法不能配置成免登录模式，否则它不再绑定当前卡密会话。

## 软件配置

后台「软件管理」中的配置必须与编译参数一致：

| 后台/客户端字段 | 含义 | 当前要求 |
|---|---|---|
| `SoftwareId` | 软件 ID | 与 `-obf-zone-software-id` 相同 |
| `SoftwareVer` | 软件版本 | 与 `-obf-zone-version` 相同 |
| 加密类型 | SDK 请求加密 | `AES` |
| 通讯协议 | SDK 通讯协议 | `HTTP`，与当前 wrapper 一致 |
| 登录类型 | 授权方式 | `Card` |
| 网络区域 | 节点区域 | 中国境内、境外或全球，需与目标环境匹配 |
| EncryptKey/IV | SDK 客户端请求加密参数 | 分别传给 `-obf-zone-encrypt-key` 和 `-obf-zone-encrypt-iv` |

卡密不放在后台算法参数和编译参数中，由程序运行时输入。

## 云算法配置

后台「云算法」新增或编辑一个算法，名称必须与：

```text
-obf-zone-algorithm=<AlgorithmName>
```

完全一致。当前推荐配置：

| 配置项 | 第一阶段建议值 |
|---|---|
| `AlgorithmName` | `attest`，或你在后台实际创建的名称 |
| `Mode` | `1`，Token 授权获取 |
| `AlgorithmReqType` | Node.js 12.16 |
| `Timeout` | 30 秒以内，后台允许范围为 1 到 3600 秒 |
| `Network` | 与目标用户网络区域匹配 |
| `Cost_Type` | 按你的后台计费策略设置；未购买/未配置时不要启用收费调用 |
| `ReqArguments` | 可留空，由客户端显式传入挑战 JSON；或配置固定默认 JSON |

`Mode=1` 很重要：它要求先完成卡密登录，云算法请求会携带有效登录 token。不要使用 `Mode=0` 作为第一阶段授权校验。

Node.js 12.16 云函数入口使用 `attest.attest`。Zone 运行器传入 `event` 和 `context`，函数返回普通 JSON 字符串：

```javascript
const crypto = require('crypto');

function attest(event, context) {
  const nonce = String(event.nonce || '');
  const guardHash = String(event.guard_hash || '');
  if (!/^[0-9a-fA-F]{64}$/.test(nonce) ||
      !/^[0-9a-fA-F]{64}$/.test(guardHash)) {
    return JSON.stringify({ ok: 0 });
  }

  const ts = Math.floor(Date.now() / 1000);
  const privateSeed = process.env.ATTEST_PRIVATE_SEED || 'CHANGE_ME';
  const message = nonce + '|' + guardHash + '|' + String(ts);
  const digest = crypto.createHash('sha256')
    .update(privateSeed + '|' + message)
    .digest('hex');

  return JSON.stringify({
    ok: 1,
    ts: ts,
    sig: digest.padEnd(128, '0').slice(0, 128),
    pub: crypto.createHash('sha256')
      .update(privateSeed)
      .digest('hex').padEnd(128, '0').slice(0, 128)
  });
}

module.exports = { attest };
```

后台入口填写：

```text
ReqHandler: attest.attest
```

## 云代码输入

客户端通过 SDK 的 `GetAntiAlgorithmValue` 传入 JSON：

```json
{
  "nonce": "64位十六进制随机数",
  "guard_hash": "64位十六进制本地摘要"
}
```

云端函数从 `event` 中读取这些字段，并返回计算结果。xollvm wrapper 的第一版调用默认后台参数，因此可以把默认参数写入后台 `ReqArguments`。后续需要绑定构建 ID、随机数、时间窗口时，再扩展 wrapper 传入动态 JSON：

```json
{
  "build_id": "后台登记的构建标识",
  "checkpoint": "main",
  "nonce": "本次运行随机数",
  "monotonic_ms": 123456
}
```

## 真实登录检查

项目内置了 `xollvm_zone_live_check`。它默认不会联网，只有显式设置 `XOLLVM_ZONE_LIVE=1` 才会请求 Zone：

```bash
export XOLLVM_ZONE_LIVE=1
export XOLLVM_ZONE_CARD='运行时卡密'
export XOLLVM_ZONE_SOFTWARE_ID='后台软件 ID'
export XOLLVM_ZONE_VERSION='1.0.0'
export XOLLVM_ZONE_ENCRYPT_KEY='客户端 AES Key'
export XOLLVM_ZONE_ENCRYPT_IV='客户端 AES IV'
export XOLLVM_ZONE_ALGORITHM='后台 AlgorithmName'
build-zone-sdk-internal/bin/xollvm_zone_live_check
```

程序会依次执行：

```text
ZoneHelper 初始化
  -> LoginC(card)
  -> HeartBeat()
  -> GetAntiAlgorithmValue(AlgorithmName)
  -> xollvm_zone_require("main")
```

不要把上述环境变量写入仓库、脚本或构建日志。真实请求会消耗网络验证次数，并可能消耗后台云算法点数。

## 第二阶段无状态 capability_v1

第二阶段新增独立的 `capability_v1` 云函数，不改变第一阶段 `attest`、卡密登录、心跳或 `70037` 流程。它要求先完成第一阶段登录，并由客户端提交以下 canonical 字段：

```text
protocol, software_id, version, build_id, device_id, operation,
state, client_nonce, request_id, client_time, code_manifest, payload
```

字段按上述顺序使用 `name:length:value` 加换行编码，`length` 是 UTF-8 字节数。响应签名覆盖不含 `signature` 字段的 canonical 响应，签名格式为 Ed25519 的 base64 编码。

云函数入口和环境变量：

```text
ReqHandler: capability_v1.capability_v1
CAPABILITY_K_SERVER             云端长期 HMAC 密钥
CAPABILITY_SIGNING_PRIVATE_KEY  云端 Ed25519 私钥（PEM）
CAPABILITY_KEY_ID                当前公钥版本标识
```

可选配置为 `CAPABILITY_BUCKET_SECONDS`、`CAPABILITY_VALID_SECONDS` 和 `CAPABILITY_POLICY_VERSION`。这些秘密只配置在云函数环境中，不能进入客户端、LLVM IR、目标文件、日志或仓库。客户端只内置对应的公钥和非秘密协议/构建标识；`key_id` 用于受限的公钥轮换窗口。

无状态函数不保存请求、session 或消费记录。因此相同的完整请求在有效期内可能被重新计算；严格的一次性消费、全局 replay 拒绝和即时撤销需要额外的 Redis/KV、数据库、云端撤销服务或硬件单调计数器，不能由本函数单独宣称提供。

如果云算法平台只支持执行代码、不支持配置环境变量，可以直接在 `capability_v1.js` 顶部的 `CODE_CONFIG` 中填写 `kServer`、`signingPrivateKey` 和 `keyId`。这些值只保留在云算法源码中，不能复制到客户端、`Android.mk`、LLVM IR 或仓库。源码中的 `REPLACE_WITH_...` 占位符必须在云平台编辑器中替换后才能工作。

编译器 capability 配置也是显式 opt-in，仅允许非秘密元数据：

```text
-obf-zone-capability-operation=<operation>
-obf-zone-capability-public-key=<server public key>
-obf-zone-capability-build-id=<registered build id>
-obf-zone-capability-code-manifest=<build manifest digest>
-obf-zone-capability-valid-seconds=<window>
```

未提供完整 capability 配置时，现有 Zone 第一阶段行为保持不变。`K_server`、签名私钥、卡密和 token 没有对应的 compiler flag，不能写入 `Android.mk`、LLVM IR、图报告或目标文件。当前 demo contract 默认不启用 capability，也不会在测试中调用真实收费云算法。
