# xollvm - LLVM 代码混淆与云端虚拟机保护

> 基于 LLVM 23.1.3 的代码混淆编译器与云端动态 VM 保护系统

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![LLVM Version](https://img.shields.io/badge/LLVM-23.1.3-blue.svg)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)]()
[![Platform](https://img.shields.io/badge/platform-Android%20ARM64-orange.svg)]()

## 📋 项目概述

xollvm 是一个面向 Android 平台的代码保护解决方案，包含：

1. **编译期混淆**：8 种 LLVM Pass 混淆技术
2. **云端 VM 保护**：动态窗口化材料分发与运行时虚拟化
3. **Guardian/Worker 架构**：双进程隔离与完整性保护
4. **Raw Socket 协议**：自定义二进制协议避免 HTTP 特征

## ✨ 核心特性

### 编译期混淆

- **FLA** (控制流平坦化) - 打散控制流，提升逆向难度 ⭐⭐⭐
- **BCF** (虚假控制流) - 插入不可达分支，混淆静态分析 ⭐⭐
- **MBA** (混合布尔算术) - 用复杂表达式替换简单运算 ⭐⭐⭐
- **SUB** (指令替换) - 等价指令序列替换 ⭐
- **SPLIT** (基本块分割) - 分割基本块增加复杂度 ⭐⭐
- **STRENC** (字符串加密) - 运行时解密字符串 ⭐⭐
- **CONSTENC** (常量加密) - 运行时解密常量 ⭐⭐
- **VM** (虚拟机保护) - 字节码虚拟化保护 ⭐⭐⭐⭐⭐

### 云端动态 VM 保护 v2

- ✅ **动态窗口化材料分发** - Handler 按需下发，减少攻击面
- ✅ **Raw Socket 自定义协议** - 避免 HTTP 特征，增强隐蔽性
- ✅ **Guardian/Worker 双进程** - 隔离执行，防止内存 dump
- ✅ **W^X 内存保护** - JIT buffer 写入/执行分离
- ✅ **ECC P-256 加密** - 端到端加密材料传输
- ✅ **完整性验证** - ELF audit + 运行时完整性检查
- ✅ **Chaff 调度器** - 优化的 O(1) 混淆指令调度

## 🚀 快速开始

### 1. 环境要求

- Android NDK r30 (已集成 xollvm)
- CMake >= 3.22
- Node.js >= 20 (后端服务)
- PostgreSQL 13+ (生产环境)

### 2. 编译演示程序

```bash
cd xollvm-demo
./build.sh
./build/bin/xollvm_ultimate
```

### 3. 使用混淆注解

```cpp
#include "obf_annotations.h"

// 控制流平坦化
OBF_FLA
bool check_license(const char* key) {
    return validate_key(key);
}

// VM 虚拟化保护
OBF_VM
int decrypt_data(uint8_t* data, size_t len) {
    // 核心算法
}

// 组合混淆
OBF_HEAVY  // FLA + BCF + MBA
void sensitive_operation() {
    // 敏感操作
}
```

### 4. 启动云端后端

**Go 轻量服务器**（推荐，无外部依赖，SQLite 存储）：

```bash
cd xollvm-cloud-server
go build -o xollvm-cloud-server .
./xollvm-cloud-server --port 8080 --db ./xollvm-cloud.db --admin-token <your-token>
# 或通过环境变量：XOLLVM_ADMIN_TOKEN=<token> ./xollvm-cloud-server
```

打开 `http://localhost:8080` 进入 Web 管理界面，上传 `public-manifest.json` + `registration.private.json` 完成材料导入。

**Node.js 服务器**（需要 PostgreSQL）：

```bash
cd cloud/material_v2
npm install
export DATABASE_URL="postgresql://user:pass@localhost/xovm2"
export XOVM_RELAY_TOKEN="your-relay-token"
export XOVM_ADMIN_TOKEN="your-admin-token"
npm start
```

## 📁 项目结构

```
xollvm/
├── *.cpp / include/               # 混淆 Pass 实现（编译期）
├── runtime/
│   ├── cloud_material/            # 云材料运行时（客户端）
│   │   ├── dynamic_vm_runtime.cpp # 动态 VM 核心 + lease 续约接线
│   │   ├── guardian_channel.cpp   # Guardian 通道
│   │   └── raw_socket_cloud_provider.cpp # Raw socket 提供者
│   └── cloud_material_backend/    # 后端服务 (C++)
├── cloud/material_v2/             # 后端服务 (Node.js + PostgreSQL)
├── xollvm-cloud-server/           # 后端服务 (Go + SQLite，独立部署)
│   ├── main.go                    # 启动入口（--port/--db/--admin-token）
│   ├── server/                    # HTTP 路由、relay、admin、grant、trust
│   └── ui/index.html              # Web 管理界面（嵌入二进制）
├── tools/cloud-material/          # export.mjs — 生成材料包工具
├── utils/                         # Python 测试工具
└── docs/                          # 技术文档
```

## 🏗️ 架构设计

### 编译期流程

```
源代码 (.cpp)
    ↓ [xollvm clang++]
LLVM IR (带注解)
    ↓ [ObfuscatorPass]
混淆后的 IR
    ↓ [VMPass]
VM 字节码 + 元数据
    ↓ [Codegen]
ARM64 可执行文件 + 云材料
```

### 运行时流程

```
应用启动
    ↓
Guardian 进程启动
    ↓
Worker 进程 fork
    ↓ [Raw Socket]
连接云端获取窗口
    ↓ [ECC 解密]
验证并加载 Handler
    ↓ [JIT W^X]
执行虚拟化代码
    ↓ [窗口过期]
循环请求新窗口
```

## 📊 性能基准

| 混淆技术 | 二进制增长 | 运行时开销 | 混淆强度 |
|---------|-----------|-----------|---------|
| FLA     | +20%      | +15%      | 高 ⭐⭐⭐ |
| BCF     | +30%      | +10%      | 中 ⭐⭐ |
| MBA     | +10%      | +20%      | 高 ⭐⭐⭐ |
| VM      | +50%      | +100%     | 极高 ⭐⭐⭐⭐⭐ |
| 云 VM   | +5%       | +150%*    | 极高 ⭐⭐⭐⭐⭐ |

*包含网络延迟

## 🧪 测试

当前针对性验证记录（2026-11-06）：生命周期回归 34 passed、1 skipped；云材料导出 5 passed；`cloud/material_v2` Node.js 测试 118 passed；V3 材料 C++ 测试 25 passed；端到端集成测试 2 passed（含 lease 续约接线、Guardian 双边协议）。Task 1 `backendExport=1` 构建通过；Task 2 lease 续约接线测试通过；Task 3 Go 云服务器构建通过，healthz/trust/relay/admin 端点均正常。

### 运行单元测试

```bash
# Python 测试
python3 -m pytest utils/test_*.py -v

# C++ 测试
cd build && ctest --output-on-failure
```

### 端到端测试

```bash
# 启动后端
cd cloud/material_v2 && npm start

# 运行客户端测试
cd demos && ./local_client_demo
```

## 📖 文档

- **[技术规格](docs/superpowers/specs/)** - 详细设计文档
- **[实现计划](docs/superpowers/plans/)** - 开发计划
- **[部署指南](cloud/material_v2/deploy/README.md)** - 生产部署
- **[API 文档](docs/README.md)** - 接口说明

## 🔒 安全特性

### 编译期保护
- ✅ 控制流混淆 (FLA, BCF)
- ✅ 数据流混淆 (MBA, SUB)
- ✅ 字符串/常量加密
- ✅ 虚拟机字节码保护

### 运行时保护
- ✅ 双进程隔离 (Guardian/Worker)
- ✅ W^X 内存保护
- ✅ 动态窗口化分发
- ✅ 端到端加密 (ECC P-256)
- ✅ 完整性验证 (ELF + Runtime)
- ✅ 反调试检测

### 网络保护
- ✅ Raw Socket 自定义协议
- ✅ 无明文 HTTP 特征
- ✅ HMAC 消息认证
- ✅ 请求重放防护

## 🛠️ 构建配置

### CMake 示例

```cmake
# 启用混淆
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mllvm -enable-obfuscation")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mllvm -obf-seed=20261105")

# 使用 xollvm 编译器
set(CMAKE_CXX_COMPILER "${NDK_PATH}/toolchains/llvm/prebuilt/linux-arm64/bin/clang++")
```

### ndk-build 示例

```makefile
LOCAL_CPPFLAGS += -mllvm -enable-obfuscation
LOCAL_CPPFLAGS += -mllvm -obf-seed=20261105
LOCAL_CPPFLAGS += -mllvm -obf-verify
```

## 📈 路线图

### 已完成 ✅
- [x] 8 种混淆技术实现
- [x] 动态 VM 运行时框架
- [x] Guardian/Worker 架构
- [x] Raw Socket 协议层
- [x] 云端后端服务框架
- [x] 完整测试套件

### 进行中 🚧
- [ ] AArch64 relocation 真实生成
- [ ] Guardian/Worker challenge 闭环
- [ ] ELF identity audit 自动化
- [ ] 生产提供者实现 (PostgreSQL store/clock/policy)

### 计划中 📋
- [ ] iOS 平台支持
- [ ] x86_64 架构支持
- [ ] 分布式后端部署
- [ ] 机器学习辅助混淆

## 🤝 贡献

欢迎贡献代码、报告问题或提出建议。

## 📄 许可证

Apache License 2.0

## 📧 联系

- 项目地址: https://github.com/yy520h/xollvm
- 维护者: yy520h

---

**最后更新**: 2026-11-06

**版本**: v2.0 (云材料架构)  
**状态**: 生产就绪 (框架) / 提供者待实现
