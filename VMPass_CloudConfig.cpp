// ============================================================================
// VMPass_CloudConfig.cpp - CloudMaterial 配置实现
// ============================================================================

#include "llvm/Transforms/Obfuscator/VMPass_CloudConfig.h"
#include "llvm/Support/CommandLine.h"
#include <cstdlib>

using namespace llvm;

// ============================================================================
// 命令行选项定义
// ============================================================================

namespace llvm {

cl::opt<bool> CloudProtection(
    "cloud-protection",
    cl::desc("Enable CloudMaterial protection"),
    cl::init(false),
    cl::Hidden);

cl::opt<std::string> CloudAppID(
    "cloud-app-id",
    cl::desc("Application ID for CloudMaterial"),
    cl::init(""),
    cl::Hidden);

cl::opt<std::string> CloudAppVersion(
    "cloud-app-version",
    cl::desc("Application version"),
    cl::init("1.0.0"),
    cl::Hidden);

cl::opt<std::string> CloudBackendMode(
    "cloud-backend-mode",
    cl::desc("Backend mode: direct or zone"),
    cl::init("direct"),
    cl::Hidden);

cl::opt<std::string> CloudOutputDir(
    "cloud-output-dir",
    cl::desc("Output directory for backend package"),
    cl::init("./cloud_output"),
    cl::Hidden);

cl::opt<std::string> CloudHMACSecret(
    "cloud-hmac-secret",
    cl::desc("HMAC secret (leave empty to auto-generate)"),
    cl::init(""),
    cl::Hidden);

cl::opt<bool> CloudEnableTLS(
    "cloud-enable-tls",
    cl::desc("Enable TLS in backend"),
    cl::init(true),
    cl::Hidden);

cl::opt<bool> CloudEnableBackendPackage(
    "cloud-enable-backend-package",
    cl::desc("Generate backend deployment package"),
    cl::init(true),
    cl::Hidden);

cl::opt<std::string> CloudNDKPath(
    "cloud-ndk-path",
    cl::desc("NDK installation path"),
    cl::init(""),
    cl::Hidden);

cl::opt<unsigned> CloudWindowSize(
    "cloud-window-size",
    cl::desc("Window size in bytes"),
    cl::init(2048),
    cl::Hidden);

cl::opt<unsigned> CloudChaffPercentage(
    "cloud-chaff-percentage",
    cl::desc("Chaff window percentage (0-100)"),
    cl::init(30),
    cl::Hidden);

cl::opt<unsigned> CloudShardCount(
    "cloud-shard-count",
    cl::desc("Number of shards per window"),
    cl::init(2),
    cl::Hidden);

} // namespace llvm

// ============================================================================
// 配置构建函数
// ============================================================================

namespace llvm {

CloudMaterialConfig getCloudMaterialConfig() {
    CloudMaterialConfig config;

    config.enable = static_cast<bool>(CloudProtection);
    config.app_id = static_cast<std::string>(CloudAppID);
    config.app_version = static_cast<std::string>(CloudAppVersion);
    config.backend_mode = static_cast<std::string>(CloudBackendMode);
    config.output_dir = static_cast<std::string>(CloudOutputDir);
    config.hmac_secret = static_cast<std::string>(CloudHMACSecret);
    config.enable_tls = static_cast<bool>(CloudEnableTLS);
    config.enable_backend_package = static_cast<bool>(CloudEnableBackendPackage);
    config.ndk_path = static_cast<std::string>(CloudNDKPath);
    config.window_size = static_cast<unsigned>(CloudWindowSize);
    config.chaff_percentage = static_cast<unsigned>(CloudChaffPercentage);
    config.shard_count = static_cast<unsigned>(CloudShardCount);

    // 尝试从环境变量获取 NDK 路径
    if (config.ndk_path.empty()) {
        const char* ndk_env = std::getenv("NDK_ROOT");
        if (ndk_env) {
            config.ndk_path = ndk_env;
        } else {
            ndk_env = std::getenv("ANDROID_NDK_ROOT");
            if (ndk_env) {
                config.ndk_path = ndk_env;
            }
        }
    }

    // 验证必需字段
    if (config.enable && config.app_id.empty()) {
        errs() << "Warning: CloudMaterial enabled but app_id not set. "
               << "Use -cloud-app-id to specify.\n";
    }

    if (config.enable && config.backend_mode != "direct" && config.backend_mode != "zone") {
        errs() << "Warning: Invalid backend mode '" << config.backend_mode
               << "'. Using 'direct'.\n";
        config.backend_mode = "direct";
    }

    return config;
}

} // namespace llvm
