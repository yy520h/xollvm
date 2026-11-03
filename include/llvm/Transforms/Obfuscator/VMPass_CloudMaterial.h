// ============================================================================
// VMPass_CloudMaterial.h — 云端动态VM窗口集成
// ============================================================================

#ifndef LLVM_TRANSFORMS_OBFUSCATOR_VMPASS_CLOUDMATERIAL_H
#define LLVM_TRANSFORMS_OBFUSCATOR_VMPASS_CLOUDMATERIAL_H

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include <vector>
#include <string>
#include <array>

namespace llvm {

// 前置声明
struct VMPassConfig;

// ============================================================================
// 窗口元数据
// ============================================================================

struct WindowMetadata {
  uint32_t window_id;
  uint32_t shard_id;
  std::vector<uint8_t> bytecode;
  uint32_t bytecode_size;
  std::array<uint8_t, 32> commitment_hash;  // SHA256承诺
  bool is_chaff;
};

// ============================================================================
// CloudMaterialEmitter - 云端窗口集成器
// ============================================================================

class CloudMaterialEmitter {
public:
  CloudMaterialEmitter() : windowPtr(nullptr) {}

  // 主集成接口
  bool integrateWithVMPass(
    Function& F,
    const std::vector<uint8_t>& vmBytecode,
    const VMPassConfig& config
  );

  // 生成运行时窗口获取调用
  void emitWindowFetchCall(
    IRBuilder<>& Builder,
    Function* F,
    uint32_t window_id,
    uint32_t shard_id,
    const std::array<uint8_t, 32>& commitment
  );

  // 生成Chaff调度器初始化
  void emitChaffSchedulerInit(
    IRBuilder<>& Builder,
    Module* M,
    uint32_t total_windows,
    uint32_t chaff_percentage
  );

  // 生成窗口选择逻辑
  Value* emitWindowSelection(
    IRBuilder<>& Builder,
    Module* M
  );

  // 分割字节码为窗口
  std::vector<WindowMetadata> splitIntoWindows(
    const std::vector<uint8_t>& fullBytecode,
    uint32_t window_size,
    uint32_t chaff_percentage
  );

  // 生成运行时配置文件
  void generateRuntimeConfig(
    const std::vector<WindowMetadata>& windows,
    const std::string& output_path
  );

  // 获取当前窗口指针
  Value* getWindowPtr() const { return windowPtr; }

private:
  Value* windowPtr;  // 当前窗口指针
};

// ============================================================================
// VMPassConfig扩展 - 云端配置项
// ============================================================================

// 在VMPass.h中添加这些字段到VMPassConfig:
//
// struct VMPassConfig {
//   ... existing fields ...
//
//   // 云端窗口配置
//   bool enable_cloud_material = false;
//   uint32_t cloud_window_size = 4096;       // 每个窗口的字节码大小
//   uint32_t cloud_chaff_percentage = 30;    // Chaff窗口比例
//   std::string cloud_config_output;         // 配置输出路径
//   std::string cloud_server_url;            // 云端服务器地址
//   uint16_t cloud_server_port = 9999;       // 服务器端口
// };

} // namespace llvm

#endif // LLVM_TRANSFORMS_OBFUSCATOR_VMPASS_CLOUDMATERIAL_H
