# 本地Demo测试指南

## 编译状态

✅ 服务端demo编译完成  
✅ 客户端demo编译完成

## 快速开始

### 方式1：使用Makefile（推荐）

```bash
cd demos

# 编译所有demo
make

# 运行测试（需要两个终端）
# 终端1：
make run-server

# 终端2：
make run-client
```

### 方式2：手动运行

```bash
cd demos

# 终端1 - 启动服务端
./local_server_demo

# 终端2 - 运行客户端
./local_client_demo
```

## Demo说明

### local_server_demo（服务端）

**功能：**
- 监听本地8080端口
- 接收客户端连接
- 验证消息协议（魔数、校验和）
- 回复客户端请求

**特点：**
- 纯C++实现，无依赖运行时模块
- 实现完整的线路协议
- 支持多次连接

### local_client_demo（客户端）

**功能：**
- 测试RawSocketCloudProvider连接
- 测试CloudProviderManager管理
- 测试PerformanceMonitor监控

**特点：**
- 使用实际的运行时模块
- 完整的端到端测试
- 性能指标收集

## 测试内容

### 测试1：RawSocketCloudProvider连接
- 连接本地服务端
- 验证TCP连接建立

### 测试2：消息发送
- 发送测试消息（5字节）
- 验证线路协议

### 测试3：消息接收
- 接收服务端回复
- 验证CRC32校验

### 测试4：CloudProviderManager
- 创建提供商管理器
- 注册本地提供商
- 查询活跃提供商

### 测试5：PerformanceMonitor
- 创建性能监控器
- 记录10个测试样本
- 计算聚合统计（min/max/avg/P50/P95/P99）

## 预期输出

### 服务端输出示例：
```
=== 云提供商本地服务端Demo ===
监听端口: 8080
服务端启动成功，等待连接...

新连接来自: 127.0.0.1
收到消息 - ID: 1, 负载大小: 5
校验和验证通过 ✓
负载内容: 1 2 3 4 5
已发送回复
```

### 客户端输出示例：
```
=== 云提供商客户端Demo ===

[测试1] RawSocketCloudProvider 连接测试
✓ 连接成功

[测试2] 发送测试消息
✓ 消息发送成功

[测试3] 接收服务端回复
✓ 收到回复，大小: 4 字节
  内容: aa bb cc dd

[测试4] CloudProviderManager 测试
✓ 管理器创建成功
  提供商数量: 1
  活跃提供商: 1

[测试5] PerformanceMonitor 测试
✓ 监控器创建成功
  记录样本数: 10
  总操作数: 10
  成功: 7, 失败: 3
  最小延迟: 100μs
  最大延迟: 190μs
  平均延迟: 145μs
  P50延迟: 145μs
  P95延迟: 181μs
  P99延迟: 189μs

=== 所有测试完成 ===
✓ RawSocketCloudProvider: 通过
✓ CloudProviderManager: 通过
✓ PerformanceMonitor: 通过
```

## 故障排除

### 问题1：客户端连接失败
```
创建云提供商失败（服务端可能未启动）
```

**解决：** 确保先启动服务端

### 问题2：端口被占用
```
绑定失败
```

**解决：** 
- 检查8080端口是否被占用：`lsof -i :8080`
- 或修改端口号（在两个demo中同步修改）

### 问题3：编译失败
```
找不到头文件
```

**解决：** 确保在 `demos/` 目录下运行make

## 清理

```bash
make clean  # 清理编译产物
```

## 下一步

✅ 本地测试通过后，可以：
1. 运行完整的单元测试套件
2. 进行性能基准测试
3. 准备云端部署（需购买服务器）

---

**开发环境：** Termux on Android  
**编译器：** clang 21.1.8  
**标准：** C++20
