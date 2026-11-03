#pragma once

#include "zone_adapter.h"
#include <cstdint>
#include <vector>
#include <string>

namespace xollvm {
namespace cloud_material {

// CloudMaterial 与 VM 集成接口
//
// 职责：
//   1. 将 VM 字节码窗口化
//   2. 与 VMPass 协同生成窗口元数据
//   3. 运行时动态加载窗口到 VM 执行
//   4. 整合 Zone 授权和 Chaff 混淆

class VMIntegration {
public:
    // VM 字节码窗口元数据
    struct VMWindowMetadata {
        uint32_t window_id;
        uint32_t shard_id;
        uint32_t offset;              // 在完整字节码中的偏移
        uint32_t size;                // 窗口大小（字节）
        std::array<uint8_t, 32> commitment;  // SHA256 commitment
        bool is_chaff;                // 是否为 Chaff 窗口
        uint32_t real_window_id;      // 如果是 Chaff，对应的真实窗口 ID
    };

    // VM 窗口配置
    struct VMWindowConfig {
        uint32_t window_size = 2048;        // 窗口大小（字节）
        uint32_t chaff_percentage = 30;     // Chaff 窗口比例 (0-100)
        bool enable_encryption = true;      // 是否加密窗口数据
        bool use_zone_relay = true;         // 是否使用 Zone 中转
        std::string zone_capability = "vm_windows";  // Zone capability 名称
    };

    static VMIntegration& getInstance();

    // 初始化 VM 集成
    bool initialize(const VMWindowConfig& config);

    // 编译期：将完整 VM 字节码分割为窗口
    // bytecode: 完整的 VM 字节码
    // 返回: 窗口元数据列表（包含真实窗口和 Chaff）
    std::vector<VMWindowMetadata> splitBytecodeIntoWindows(
        const std::vector<uint8_t>& bytecode);

    // 编译期：生成窗口配置文件（供云端部署）
    // metadata: 窗口元数据列表
    // output_path: 输出配置文件路径
    bool generateWindowConfig(
        const std::vector<VMWindowMetadata>& metadata,
        const std::string& output_path);

    // 运行时：获取指定窗口的字节码
    // window_id: 窗口 ID
    // 返回: 窗口字节码数据（已解密）
    std::vector<uint8_t> fetchVMWindow(uint32_t window_id);

    // 运行时：预取多个窗口（性能优化）
    // window_ids: 窗口 ID 列表
    void prefetchVMWindows(const std::vector<uint32_t>& window_ids);

    // 运行时：检查 VM 执行授权（Zone 卡密）
    bool isVMAuthorized() const;

    // 运行时：获取 Chaff 调度器状态
    struct ChaffSchedulerStatus {
        uint32_t total_windows;
        uint32_t real_windows;
        uint32_t chaff_windows;
        uint32_t next_window_id;  // 下一个要执行的窗口 ID（可能是 Chaff）
    };
    ChaffSchedulerStatus getChaffStatus() const;

private:
    VMIntegration();
    ~VMIntegration();
    VMIntegration(const VMIntegration&) = delete;
    VMIntegration& operator=(const VMIntegration&) = delete;

    // 生成窗口 commitment (SHA256)
    std::array<uint8_t, 32> computeCommitment(const std::vector<uint8_t>& data);

    // 生成 Chaff 窗口
    std::vector<VMWindowMetadata> generateChaffWindows(
        const std::vector<VMWindowMetadata>& real_windows,
        uint32_t chaff_percentage);

    // 加密/解密窗口数据
    std::vector<uint8_t> encryptWindow(const std::vector<uint8_t>& data, uint32_t window_id);
    std::vector<uint8_t> decryptWindow(const std::vector<uint8_t>& encrypted, uint32_t window_id);

    VMWindowConfig config_;
    bool initialized_;
    ZoneAdapter* zone_adapter_;

    // 窗口元数据缓存（运行时）
    std::vector<VMWindowMetadata> window_metadata_;
};

// ============================================================================
// 运行时 C API (供 VM 引擎调用)
// ============================================================================

extern "C" {

// 初始化 CloudMaterial VM 集成
// config_json: JSON 格式的配置字符串
// 返回: 0 成功, -1 失败
int xovm_cloudmaterial_init(const char* config_json);

// 获取 VM 窗口数据
// window_id: 窗口 ID
// out_data: 输出缓冲区
// capacity: 缓冲区容量
// out_size: 实际数据大小
// 返回: 0 成功, -1 失败
int xovm_cloudmaterial_fetch_window(
    uint32_t window_id,
    uint8_t* out_data,
    size_t capacity,
    size_t* out_size);

// 检查 VM 授权状态（Zone 卡密）
// 返回: 1 已授权, 0 未授权
int xovm_cloudmaterial_check_auth();

// 获取下一个要执行的窗口 ID（考虑 Chaff 调度）
// 返回: 窗口 ID
uint32_t xovm_cloudmaterial_next_window();

// 清理资源
void xovm_cloudmaterial_cleanup();

} // extern "C"

} // namespace cloud_material
} // namespace xollvm
