# Zone Wrapper Link Contract

XOLLVM 只在目标实际启用 `zoneauth` 时注入 `xollvm_zone_*` C ABI 调用，不把官方 Zone SDK 链进 LLVM pass，也不把官方 native `.a` 当作 LLVM bitcode。项目在 `third_party/zone_sdk/` 内置构建所需的 SDK 源码、头文件和静态库。使用项目提供的 `xollvm-zone-clang` 作为最终编译/链接入口时，目标中的 Zone marker 会自动触发 Zone runtime 链接：

- `zone_runtime/zone_wrapper.cpp`
- Zone SDK 的头文件和官方 `.a`
- 依赖模式对应的 curl、zlib、libssl、libcrypto 静态库
- Android 系统需要的网络、线程和动态加载系统库

项目没有预编译的 Zone 主 archive 时，CMake 会直接把内置 SDK 的 `Core/*.cpp` 编译进
`xollvm_zone_sdk`。当前 CMake 默认使用项目内副本，也允许通过
`XOLLVM_ZONE_SDK_ROOT` 覆盖 SDK 根目录：

```bash
cmake -S llvm-project/llvm -B build-zone-sdk -G Ninja \
  -DLLVM_ENABLE_PROJECTS=clang \
  -DLLVM_EXTERNAL_PROJECTS=Obfuscator \
  -DLLVM_EXTERNAL_OBFUSCATOR_SOURCE_DIR="$PWD/xollvm" \
  -DLLVM_OBFUSCATOR_LINK_INTO_TOOLS=ON \
  -DXOLLVM_ZONE_SDK_ROOT="$PWD/xollvm/third_party/zone_sdk"

cmake --build build-zone-sdk --target xollvm_zone_wrapper_link_smoke --parallel 6
build-zone-sdk/bin/xollvm_zone_wrapper_link_smoke
```

`xollvm_zone_wrapper_link_smoke` 只验证最终静态链接和 ABI 符号，不发起网络请求。bundled 模式会在构建阶段把四个第三方 archive 与 SDK runtime 使用统一映射生成私有符号 archive，例如 `xollvm_zone_curl_*`、`xollvm_zone_zlib_*`、`xollvm_zone_ssl_*` 和 `xollvm_zone_crypto_*`。生成后必须通过 archive 审计；未通过审计的 archive 不会进入目标。

Zone 生命周期由 `-mllvm -obf-zone-shutdown-mode=auto|manual` 控制，默认是 `auto`。`auto` 仅在卡密登录成功后注册 `atexit` 和 `SIGINT`、`SIGTERM`、`SIGHUP` 监视，并在退出时按“停止并回收心跳、停止并回收信号监视、调用 `Logout`、销毁 SDK”顺序清理。信号处理器只设置标志，网络请求由监视线程执行。已有生命周期管理的被附加目标使用 `manual`，运行时不会安装退出回调或信号处理器，由目标显式调用 `xollvm_zone_shutdown()`。

在 Termux 构建、MT/root 终端运行 Android host 工具时，clang 和 opt 自身也不能依赖 Termux 的 `libc++_shared.so`。配置本地构建时应显式链接 NDK 静态 libc++，避免不同终端预加载同名但 ABI 不兼容的共享库：

```bash
NDK_HOST="$HOME/android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64"
cmake -S llvm-project/llvm -B build -G Ninja \
  -DCMAKE_EXE_LINKER_FLAGS="-nostdlib++ $NDK_HOST/sysroot/usr/lib/aarch64-linux-android/libc++_static.a $NDK_HOST/sysroot/usr/lib/aarch64-linux-android/libc++abi.a" \
  -DLLVM_ENABLE_PROJECTS="llvm;clang" \
  -DLLVM_TARGETS_TO_BUILD="AArch64;ARM" \
  -DLLVM_EXTERNAL_PROJECTS=Obfuscator \
  -DLLVM_EXTERNAL_OBFUSCATOR_SOURCE_DIR="$PWD/xollvm" \
  -DLLVM_OBFUSCATOR_LINK_INTO_TOOLS=ON
```

构建后用 `readelf -d build/bin/clang-23` 检查动态依赖，输出中不得再出现 `NEEDED libc++_shared.so`。

普通 `clang` 不会自动读取 marker；自动链接必须使用项目提供的 `xollvm-zone-clang` 或等价的链接包装器。没有 marker 的普通目标不会追加 Zone 依赖。Android/MT 环境交付的最终可执行文件仍应按项目规则使用 `-static-libstdc++`；这不等于把第三方静态库作为运行时文件交付。

默认 `XOLLVM_ZONE_LINK_MODE=bundled`。最终链接 wrapper 会逐项分析 `-lcurl`、`-lz`、`-lssl`、`-lcrypto` 或直接 archive 参数：目标库缺失时补对应私有 archive，必需符号或 ABI 检查通过时复用目标库，检查失败时切换私有 archive。不能把四个依赖作为一个整体开关，也不能仅根据“发现同名库”静默跳过内置库。

`external` 模式必须逐项提供实际 archive，并通过 CMake 配置和链接阶段的存在性、必需符号、架构检查：

```bash
cmake -S llvm-project/llvm -B build-zone-external -G Ninja \
  -DXOLLVM_ZONE_LINK_MODE=external \
  -DXOLLVM_ZONE_EXTERNAL_CURL=/absolute/path/libcurl.a \
  -DXOLLVM_ZONE_EXTERNAL_ZLIB=/absolute/path/libz.a \
  -DXOLLVM_ZONE_EXTERNAL_SSL=/absolute/path/libssl.a \
  -DXOLLVM_ZONE_EXTERNAL_CRYPTO=/absolute/path/libcrypto.a
```

bundled 和 external 不能同时进入同一个 Zone 目标；缺少 external archive 或校验失败时配置直接失败。普通 `clang` 不会自动读取 marker，自动链接必须使用项目提供的 wrapper。

链接包装器不会猜测或生成不存在的 archive。使用前必须设置实际构建产物路径：

```bash
export XOLLVM_ZONE_EXTERNAL_CURL=/absolute/path/to/libcurl.a
export XOLLVM_ZONE_EXTERNAL_ZLIB=/absolute/path/to/libz.a
export XOLLVM_ZONE_EXTERNAL_SSL=/absolute/path/to/libssl.a
export XOLLVM_ZONE_EXTERNAL_CRYPTO=/absolute/path/to/libcrypto.a
```

编译器侧需要的参数示例：

```text
-mllvm -obf-zone-enable
-mllvm -obf-zone-software-id=<software-id>
-mllvm -obf-zone-version=1.0.0
-mllvm -obf-zone-encrypt-key=<client-key>
-mllvm -obf-zone-encrypt-iv=<client-iv>
-mllvm -obf-zone-heartbeat-period=120
-mllvm -obf-zone-offline-grace=180
```

卡密不出现在这些参数中。启用后的目标程序通过 wrapper 在运行时读取卡密，并由官方 `ZoneHelper::LoginC`、`HeartBeat` 完成登录和续租。
