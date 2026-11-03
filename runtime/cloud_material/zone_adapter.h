#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <array>

namespace xollvm {
namespace cloud_material {

// CloudMaterial 访问模式
enum class AccessMode {
    ZONE_RELAY,      // 通过 Zone 云算法中转（默认，更安全）
    DIRECT_BACKEND   // 直接访问后端（开发/性能优先）
};

// 窗口请求结构
struct WindowRequest {
    uint32_t window_id;
    uint32_t shard_id;
    std::array<uint8_t, 32> commitment;  // SHA256 期望值
};

// 窗口响应结构
struct WindowResponse {
    bool success;
    std::vector<uint8_t> data;
    uint64_t timestamp;
    std::string error_message;
};

// Zone 中转适配器
//
// 职责：
//   1. 将 CloudMaterial 的窗口请求路由到 Zone capability
//   2. 利用 Zone 的卡密授权和云算法保护
//   3. 支持降级到直接访问模式
class ZoneAdapter {
public:
    static ZoneAdapter& getInstance();

    // 初始化适配器
    // mode: 访问模式（Zone 中转或直接访问）
    // zone_capability_name: Zone capability 名称（Zone 中转模式必需）
    bool initialize(AccessMode mode, const std::string& zone_capability_name = "cloud_material_windows");

    // 获取窗口数据
    // 根据配置的访问模式，通过 Zone 或直接请求后端
    WindowResponse fetchWindow(const WindowRequest& request);

    // 批量获取窗口
    std::vector<WindowResponse> fetchWindowBatch(const std::vector<WindowRequest>& requests);

    // 切换访问模式（运行时可配置）
    void setAccessMode(AccessMode mode);
    AccessMode getAccessMode() const { return mode_; }

    // 检查 Zone 授权状态（仅 Zone 中转模式）
    bool isZoneAuthorized() const;

    // 获取统计信息
    struct Statistics {
        uint64_t total_requests;
        uint64_t zone_relay_requests;
        uint64_t direct_requests;
        uint64_t failed_requests;
        uint64_t average_latency_ms;
    };
    Statistics getStatistics() const;

private:
    ZoneAdapter();
    ~ZoneAdapter();
    ZoneAdapter(const ZoneAdapter&) = delete;
    ZoneAdapter& operator=(const ZoneAdapter&) = delete;

    // Zone 中转模式实现
    WindowResponse fetchViaZone(const WindowRequest& request);

    // 直接访问模式实现
    WindowResponse fetchDirect(const WindowRequest& request);

    // Zone capability 集成
    bool registerWithZone();
    bool requestZoneWindow(const WindowRequest& request, std::vector<uint8_t>& out_data);

    AccessMode mode_;
    std::string zone_capability_name_;
    bool initialized_;
    bool zone_available_;

    // 统计数据
    mutable Statistics stats_;
};

// 全局配置辅助函数

// 从环境变量或配置文件读取访问模式
// 环境变量: XOLLVM_CLOUDMATERIAL_MODE=zone|direct
AccessMode getAccessModeFromConfig();

// 是否强制使用 Zone 中转（生产环境推荐）
// 环境变量: XOLLVM_CLOUDMATERIAL_FORCE_ZONE=1
bool isForceZoneMode();

} // namespace cloud_material
} // namespace xollvm
