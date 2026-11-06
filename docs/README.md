# xollvm Android 项目文档总览

本目录包含 xollvm 项目的完整文档。

## 📚 文档结构

### 项目级文档

这些文档位于项目根目录 `/data/user/0/com.termux/files/home/xollvm-android/`：

- **README.md** - 项目总览和快速开始
- **PROJECT_STATUS.md** - 详细的项目状态报告
- **COMPLETION_CHECKLIST.md** - 完成任务清单

### 演示程序文档

位于 `../xollvm-demo/`：

- **README.md** - Demo 项目说明
- **QUICKSTART.md** - 5 分钟快速上手指南
- **BUILD.md** - 详细的构建指南和选项

### 后端服务文档

位于 `../xollvm-backend-server/`：

- **README.md** - 后端服务器使用说明
- **CLOUD_PROTECTION_COMPLETE.md** - 云保护系统完整文档

### NDK 文档

位于 `../android-ndk-r30-ollvm-r23-beta3/`：

- **README.md** - NDK + xollvm 集成说明

### 技术规格和计划

位于本目录 `superpowers/`：

- `specs/` - 技术规格设计文档
- `plans/` - 项目计划文档

## 🎯 快速导航

### 我想开始使用 xollvm

1. 阅读项目总览：[../README.md](../../README.md)
2. 查看快速开始：[../xollvm-demo/QUICKSTART.md](../../xollvm-demo/QUICKSTART.md)
3. 运行示例程序：
   ```bash
   cd ../xollvm-demo
   ./build.sh
   ./build/bin/simple_demo
   ```

### 我想了解项目状态

查看 [PROJECT_STATUS.md](PROJECT_STATUS.md) - 包含：
- 核心组件状态
- 技术实现细节
- 性能分析
- 完整的文档清单

### 我想集成到我的项目

1. 查看 [../xollvm-demo/BUILD.md](../../xollvm-demo/BUILD.md)
2. 查看 [../android-ndk-r30-ollvm-r23-beta3/README.md](../../android-ndk-r30-ollvm-r23-beta3/README.md)
3. 参考 CMake 配置示例

### 我想使用云保护

查看 [../xollvm-backend-server/CLOUD_PROTECTION_COMPLETE.md](../../xollvm-backend-server/CLOUD_PROTECTION_COMPLETE.md)

## 📖 核心概念

### xollvm 混淆编译器

基于 LLVM 23.1.3 的代码混淆编译器，支持 8 种混淆技术：

1. **FLA** (控制流平坦化) - 将控制流转换为平坦的 switch-case 结构
2. **BCF** (虚假控制流) - 插入永远不会执行的代码分支
3. **MBA** (混合布尔算术) - 用复杂的数学表达式替换简单运算
4. **SUB** (指令替换) - 用等价但更复杂的指令序列替换
5. **SPLIT** (基本块分割) - 将基本块分割成更小的片段
6. **STRENC** (字符串加密) - 加密程序中的字符串常量
7. **CONSTENC** (常量加密) - 加密程序中的数字常量
8. **VM** (虚拟机保护) - 将代码转换为自定义虚拟机字节码

### 注解驱动混淆

使用函数注解来标记需要混淆的代码：

```cpp
#define OBF_FLA      __attribute__((annotate("obf:fla")))
#define OBF_BCF      __attribute__((annotate("obf:bcf")))
#define OBF_MBA      __attribute__((annotate("obf:mba")))
// ... 更多注解

// 使用示例
OBF_FLA
bool check_password(const char* password) {
    // 此函数将被控制流平坦化保护
    return validate(password);
}
```

### NDK 集成

xollvm 编译器已集成到 Android NDK r30 中：

```
android-ndk-r30-ollvm-r23-beta3/
└── toolchains/llvm/prebuilt/linux-arm64/bin/
    └── clang-21  ← xollvm clang-23
```

这意味着：
- ✅ 完整的 C/C++ 标准库支持
- ✅ 所有系统头文件可用
- ✅ 链接库自动配置
- ✅ CMake 原生支持

## 🛠️ 技术栈

- **编译器**: LLVM 23.1.3 + xollvm r23-beta3
- **构建系统**: CMake 3.22+
- **目标平台**: Android ARM64 (API 21+)
- **后端服务**: Go 1.21+ (Gin framework)
- **认证**: HMAC-SHA256

## 📊 项目状态

| 组件 | 状态 | 说明 |
|-----|------|------|
| xollvm 编译器 | ✅ 完成 | 已集成到 NDK |
| 演示程序 | ✅ 完成 | 2 个可运行示例 |
| 云保护后端 | ✅ 完成 | Go 服务已测试 |
| 文档 | ✅ 完成 | 7 个详细文档 |
| 构建工具 | ✅ 完成 | CMake + 脚本 |

## 🔗 相关链接

### 内部文档
- [项目总览](../../README.md)
- [项目状态](PROJECT_STATUS.md)
- [完成清单](../../COMPLETION_CHECKLIST.md)
- [Demo 程序](../../xollvm-demo/README.md)
- [后端服务](../../xollvm-backend-server/README.md)
- [NDK 说明](../../android-ndk-r30-ollvm-r23-beta3/README.md)

### 外部资源
- [LLVM 官方网站](https://llvm.org/)
- [Android NDK 文档](https://developer.android.com/ndk)
- [代码混淆技术概述](https://en.wikipedia.org/wiki/Obfuscation_(software))

## 📝 文档维护

所有文档已同步更新至当前项目状态（2024-10-31）：

- ✅ 移除了旧项目 (xollvm-demo-old-backup) 的引用
- ✅ 更新了所有路径从 `xollvm-demo-new` 到 `xollvm-demo`
- ✅ 同步了各目录下的文档
- ✅ 完善了 NDK 集成说明
- ✅ 更新了快速开始指南

## 🎓 学习路径

### 初学者
1. 阅读项目总览
2. 查看快速开始指南
3. 运行简单示例 (simple_demo)
4. 理解混淆注解的使用

### 中级用户
1. 阅读详细构建指南
2. 查看完整示例 (full_demo)
3. 尝试不同的混淆组合
4. 使用 IDA/Ghidra 分析混淆效果

### 高级用户
1. 集成到实际 Android 项目
2. 部署云保护后端服务
3. 优化混淆策略（性能 vs 安全）
4. 自定义混淆参数

## ⚠️ 注意事项

1. **混淆不是万能的** - 应配合其他安全措施使用
2. **性能权衡** - 不同混淆技术有不同的性能开销
3. **选择性混淆** - 只对关键函数应用混淆
4. **测试验证** - 混淆后务必进行充分测试

## 📧 支持

如有问题，请参考：
1. 相关目录下的 README.md
2. 快速开始指南 (QUICKSTART.md)
3. 详细构建指南 (BUILD.md)
4. 项目状态报告 (PROJECT_STATUS.md)

---

**最后更新**: 2024-10-31  
**维护者**: yy520h  
**项目状态**: 生产就绪 ✅
