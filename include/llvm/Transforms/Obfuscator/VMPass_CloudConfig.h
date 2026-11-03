// ============================================================================
// VMPass_CloudConfig.h - CloudMaterial 配置扩展
// ============================================================================

#ifndef LLVM_TRANSFORMS_OBFUSCATOR_VMPASS_CLOUDCONFIG_H
#define LLVM_TRANSFORMS_OBFUSCATOR_VMPASS_CLOUDCONFIG_H

#include "llvm/Support/CommandLine.h"
#include <string>

namespace llvm {

// CloudMaterial 配置选项
struct CloudMaterialConfig {
    bool enable = false;
    std::string app_id;
    std::string app_version = "1.0.0";
    std::string backend_mode = "direct";  // "direct" or "zone"
    std::string output_dir = "./cloud_output";
    std::string hmac_secret;              // 空则自动生成
    std::string zone_token;
    bool enable_tls = true;
    bool enable_backend_package = true;
    std::string ndk_path;

    // 窗口配置
    uint32_t window_size = 2048;
    uint32_t chaff_percentage = 30;
    uint32_t shard_count = 2;
};

// 命令行选项声明
extern cl::opt<bool> CloudProtection;
extern cl::opt<std::string> CloudAppID;
extern cl::opt<std::string> CloudAppVersion;
extern cl::opt<std::string> CloudBackendMode;
extern cl::opt<std::string> CloudOutputDir;
extern cl::opt<std::string> CloudHMACSecret;
extern cl::opt<bool> CloudEnableTLS;
extern cl::opt<bool> CloudEnableBackendPackage;
extern cl::opt<std::string> CloudNDKPath;
extern cl::opt<unsigned> CloudWindowSize;
extern cl::opt<unsigned> CloudChaffPercentage;
extern cl::opt<unsigned> CloudShardCount;

// 从命令行选项构建配置
CloudMaterialConfig getCloudMaterialConfig();

} // namespace llvm

#endif // LLVM_TRANSFORMS_OBFUSCATOR_VMPASS_CLOUDCONFIG_H
