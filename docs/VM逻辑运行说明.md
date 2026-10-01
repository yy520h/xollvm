# VM 逻辑运行说明

## Wrapper 到 Engine

虚拟化函数原始 body 被替换为 wrapper。wrapper：

1. 分配 `vm.ip`、salt、整数/64 位/浮点/指针 register file；
2. 把参数写入对应 register file；
3. 准备 bytecode、handler table、callee table 和 mask；
4. 间接调用共享 `__vm_engine`；
5. 从 register file 读取返回值。

bytecode 通常先由 constructor 解密到 runtime global，再由 dispatch 按 IP 取指。register index、opcode、target 和 register value 可分别配置加密或随机化。

## Engine dispatch

engine 使用 fetch/decode/indirectbr 模型：

```text
check ip
  -> load bytecode
  -> decode logical opcode
  -> map physical handler
  -> execute handler
  -> update ip/registers
  -> dispatch again
```

handler 根据 VM ISA 处理整数、64 位整数、浮点、内存、控制流、CALL 和返回值。共享 engine 由 coordinator 按兼容配置分组；不同 group 使用不同 engine state。

NestedVM 使用单独的 nest engine；nest handler 把选定的 opcode 调用到纯 helper，helper 再由 plain engine 虚拟化。plain engine 是多个 helper 共享的，因此 inner helper 当前使用完整 handler domain，不能由第一个 helper 的局部需求裁剪，否则后续 float helper 会跳转到缺失的 handler。

## Prepare/commit 的原因

prepare 阶段必须可以失败而不破坏原函数。完整 scratch module clone 解决了临时 `Value*`、CALL callee 和全局引用的生命周期问题。commit 阶段才把 bytecode、wrapper、engine、constructor 写入目标模块。

## Anti-debug 运行逻辑

显式 `antidebug(...)` 会生成目标侧检测：

- TracerPid：读取 `/proc/self/status`；
- ptrace：执行配置的 ptrace 检测；
- timing：使用 `clock_gettime` 比较固定工作区间；
- maps：读取 `/proc/self/maps`；
- integrity：校验 VM bytecode global；
- dynamic：constructor 创建 monitor pthread，循环检测并写入模块状态。

检测状态由模块级 response global 保存。VM wrapper 看到 response 后替换 salt，触发错误 bytecode 路径；非 VM 函数默认返回类型对应的零值。未配置 anti-debug 时不生成这些系统调用、global、constructor 或线程。

## 失败和回滚

unsupported instruction、预算耗尽、平台不支持或 verifier 失败都会产生 skip reason。prepare 失败不会创建目标模块 artifact；commit 失败则由 module pass 返回失败分析，调用方应把该 module 视为未完成产物。
