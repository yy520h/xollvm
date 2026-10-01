# VM 云值驱动 dispatch 设计（数据流绑定型保护）

## 目标

让所有经 VM 化的函数在缺少当前云算法返回值时无法正确执行，且不由本地代码做任何“授权真假”判断。云返回值直接作为 VM 解释器派生 opcode/handler 选择的输入，值缺失、过期或被篡改时，VM 解码出非法指令并自然触发越界访问或非法跳转，而不是被本地分支检测后拒绝。

核心原则：**判断不存在，值错就等于执行错。**

本设计刻意不依赖“本地验签后返回布尔”的模型，因为布尔判断可被 NOP 或强制返回。授权强度来自数据流依赖：VM 解释器本身的正确运行需要云值，删掉云值或伪造云值会导致 VM 崩溃。

## 设计定位

本设计是 Zone 授权体系的目标执行模式，取代此前的“本地验签 + fail-closed 门禁”方案。此前的两份设计文档（卡密第一阶段、无状态 capability 第二阶段）已废弃，不再作为实现依据。

本设计沿用 Zone 的卡密登录、心跳、租约和 Zone 生命周期，但授权语义完全改变：

- 不使用本地验签后返回布尔/整数的授权门。
- 不使用 `xollvm_zone_require` 式的“通过则执行、失败则拒绝”语义。
- 云算法返回值不经过本地合法性判断，而是直接作为 VM dispatch 派生输入。
- 失败不是被检测后拒绝，而是 VM 解码出非法指令、自然崩溃。

授权强度的来源是数据流依赖，不是本地判断：VM 解释器本身需要云值才能正确运行。

## 威胁模型与目标

针对拥有 root、调试器、内存修改能力的攻击者。

可以抵抗：

- 删除授权调用或云请求：VM 缺少派生输入，非法指令导致崩溃。
- 用固定常量替换本地布尔判断：本设计没有可替换的布尔判断。
- 简单的控制流补丁：正确执行依赖云值进入数据流，而不是依赖跳转结果。
- 跨窗口重放：云值随服务器时间漂移，窗口外派生结果不同。

不能抵抗：

- 完整逆向 VM 字节码、handler 表、opcode 映射与派生算法后，构造合法云值。
- 在正确运行时 dump 出解密后的字节码和 dispatch 状态。
- 伪造 CPU 硬件计数器（超级权限、虚拟化、ptrace 改写）。
- 篡改服务端或 TLS 通道。

本设计的强度来源是“VM 壳不可静态还原”叠加“云值随时间漂移”，不是密码学不可伪造保证。

## 术语

```text
client_tick     客户端 CPU 硬件时间戳（汇编读取，用于上传对比，不参与本地判断）
server_time     服务端权威时间
device_id       硬件级设备标识
nonce           每次新请求生成的随机值
auth_value      云算法返回的派生材料，直接进入 VM dispatch
window          云值有效期，60 秒
prefetch        客户端预取间隔，50 秒
```

## 时间模型

时间基准是服务器时间，客户端时间只用于上传对比。

- 服务器派生值时使用自己的 `server_time`。
- 服务器对比 `server_time` 与请求中携带的 `client_tick`；偏差超过容忍窗口时拒绝请求，不返回值。
- 云值有效期 `window = 60` 秒。
- 客户端预取间隔 `prefetch = 50` 秒。
- 客户端缓存上限 `60` 秒。
- 约束：`window >= prefetch + 网络抖动余量`。

时间不通过本地判断过期。云值必须与本地 CPU tick 耦合，使旧值在窗口外自然派生出错误的 dispatch 结果。

## 请求模型

请求字段在既有无状态协议字段上增加硬件定时器输入：

```json
{
  "protocol": 1,
  "software_id": "...",
  "version": "...",
  "build_id": "...",
  "device_id": "<hardware-id>",
  "operation": "vm_dispatch",
  "state": "state_n",
  "client_nonce": "random-128-bit",
  "request_id": "random-128-bit",
  "client_time": 0,
  "client_tick": 0,
  "code_manifest": "sha256...",
  "payload": "..."
}
```

字段约束：

- `client_nonce` 每次新请求重新生成，至少 128 bit。
- `client_tick` 由汇编从 CPU 架构定时器读取，例如 AArch64 的 `CNTVCT_EL0`。
- `device_id` 使用硬件级标识，不采用客户端可任意声称的软件字符串。
- `client_time` 与 `client_tick` 一起上传；服务器以 `server_time` 与 `client_tick` 的偏差做窗口判断。
- `operation` 固定绑定 VM dispatch 场景，防止跨用途复用。

## 云算法计算

服务端使用长期密钥和请求输入派生 `auth_value`：

```text
window_id    = floor(server_time / window)

auth_message = device_id || client_tick || nonce || window_id
               || code_manifest || operation

auth_value   = KDF(K_server, auth_message)
```

`auth_value` 的每个输入都参与派生。缺少 `device_id`、`client_tick`、`nonce`、`window_id`、`code_manifest` 或 `operation` 中任意一项，都得不到相同结果。

Ed25519 用法（用法 B）：服务端对上述派生材料签名，客户端本地**不验签**，而是把签名材料与本地当前 CPU tick 混合，生成 VM dispatch 扰动。签名保证只有服务端能产出结构正确的 `auth_value`，tick 耦合保证旧签名在窗口外自然失效。

```text
signed_blob  = Sign(server_sign_private_key, auth_message)
dispatch_key = H(signed_blob || client_tick_now)
```

`dispatch_key` 不经过任何本地合法性判断，直接用于 VM。

## VM 集成

云值进入 VM 解释器的 dispatch 路径：

```text
encoded_opcode = bytecode[pc]
real_opcode    = encoded_opcode XOR mask(dispatch_key, pc)
handler        = handler_table[real_opcode]
```

要求：

- `handler_table` 无安全兜底分支。`real_opcode` 越界即越界读取或跳转到非法地址，由硬件触发 SIGSEGV 或指针异常。
- `mask` 依赖 `dispatch_key`，而 `dispatch_key` 依赖当前 `client_tick`，因此 tick 推进会使旧云值派生出的 mask 与新 tick 不匹配，解码出非法 opcode。
- 本地没有任何 `if (auth_value valid)`、`if (window expired)`、`if (signature ok)` 判断。
- 首次初始化同样需要云值。缺值时字节码无法正确解码，VM 启动即异常退出。

VM 不保存长期服务端秘密，只消费本次短期派生材料。

## 生命周期

```text
启动
  -> 卡密登录（沿用第一阶段）
  -> 读取 CPU tick、设备码，生成 nonce
  -> 请求云算法，得到 auth_value
  -> VM 初始化，dispatch 依赖 dispatch_key
  -> 运行
  -> 每 50 秒预取新云值
  -> 旧值缓存最多 60 秒
  -> 超时未取到新值：旧 tick 与新 tick 不匹配，dispatch 解码错误，自然崩溃
```

后台预取线程与 VM 执行解耦：预取失败不阻塞业务热路径，但旧值超过 60 秒后自然失效。

## 失败与网络策略

- 首次无云值：VM 无法正确解码，进程异常退出。这是约定失效路径，不给出友好提示。
- 预取失败：继续使用缓存值，直到超过 60 秒窗口后自然失效。
- 云值过期：不本地判断；tick 耦合使旧值派生出错误 opcode。
- 网络抖动：允许缓存值覆盖，窗口参数已含抖动余量。
- TLS 传输完整性：由传输层保证，防止中间人改值造成随机崩溃。这属于传输保护，不是业务层校验。

## 明确安全边界

可以实现：

- 删除授权或云请求后 VM 无法正确执行。
- 无本地布尔判断可被 NOP 绕过。
- 云值绑定设备、nonce、构建、操作和时间窗口。
- 跨窗口重放因 tick 耦合而失效。
- 首次运行即要求有效云值。

不能单独实现：

- 完整逆向 VM 后的合法值构造。
- 运行时 dump 出已解密字节码后的绕行。
- 超级权限下伪造 CPU 计数器。
- 服务端或 TLS 被攻破时的防护。
- 本地崩溃发生前的可用性保证。

## 测试要求

必须覆盖：

- 缺少 `auth_value` 时 VM 初始化或执行产生非法 opcode / 越界访问，而不是走安全回退。
- `dispatch_key` 在不同 `client_tick` 下不同，同一签名在不同窗口解码结果不同。
- 修改 `device_id`、`nonce`、`code_manifest`、`operation`、`client_tick` 任一项，派生出不同结果。
- 删除本地云请求调用后，VM 无法正确执行。
- `handler_table` 不存在越界兜底分支。
- 本地代码不存在 `auth`/`signature`/`window` 相关布尔判断。
- 缓存 60 秒内的旧值仍受 tick 漂移影响。
- 云值有效期、预取间隔、缓存上限满足 `window >= prefetch + 抖动余量`。
- 第一阶段卡密登录、心跳、Zone 关闭模式不回归。
- `K_server`、服务端私钥不出现在目标 IR、二进制、日志或客户端配置中。

## 配置与接口

新增编译期配置（示意）：

```text
-obf-zone-vm-dispatch-cloud
-obf-zone-vm-dispatch-window=60
-obf-zone-vm-dispatch-prefetch=50
```

新增运行时接口（示意）：

```text
xollvm_zone_vm_dispatch_value()     返回当前 dispatch 派生材料，不返回合法/非法
xollvm_zone_vm_dispatch_refresh()   触发一次预取
```

上述接口不返回布尔授权结果，只返回供 VM 消费的派生材料。

## 阶段完成标准

1. VM 解释器的 dispatch 正确性依赖云派生的 `dispatch_key`，缺少该值即产生非法 opcode。
2. 本地不存在任何针对 `auth_value`、签名或有效期的布尔判断。
3. 云值绑定 `device_id`、`client_tick`、`nonce`、`window_id`、`code_manifest`、`operation`。
4. 60 秒有效期与 50 秒预取间隔在 tick 耦合下自洽，窗口外自然失效。
5. 首次运行缺云值即异常退出，符合约定失效路径。
6. 第一阶段登录、心跳、Zone 关闭和既有 VM 回归通过。
