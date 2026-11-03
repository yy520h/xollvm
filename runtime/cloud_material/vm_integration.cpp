#include "vm_integration.h"
#include "window_cache.h"
#include <cstring>
#include <fstream>
#include <random>
#include <mutex>
#include <openssl/sha.h>

namespace xollvm {
namespace cloud_material {

namespace {
    std::mutex g_vm_integration_mutex;
    std::random_device g_random_device;
    std::mt19937 g_random_generator(g_random_device());
}

VMIntegration& VMIntegration::getInstance() {
    static VMIntegration instance;
    return instance;
}

VMIntegration::VMIntegration()
    : initialized_(false)
    , zone_adapter_(nullptr) {
}

VMIntegration::~VMIntegration() {
}

bool VMIntegration::initialize(const VMWindowConfig& config) {
    std::lock_guard<std::mutex> lock(g_vm_integration_mutex);

    if (initialized_) {
        return true;
    }

    config_ = config;

    // 初始化 Zone 适配器
    zone_adapter_ = &ZoneAdapter::getInstance();

    AccessMode mode = config.use_zone_relay ? AccessMode::ZONE_RELAY : AccessMode::DIRECT_BACKEND;
    if (!zone_adapter_->initialize(mode, config.zone_capability)) {
        return false;
    }

    initialized_ = true;
    return true;
}

std::vector<VMIntegration::VMWindowMetadata> VMIntegration::splitBytecodeIntoWindows(
    const std::vector<uint8_t>& bytecode) {

    std::lock_guard<std::mutex> lock(g_vm_integration_mutex);

    std::vector<VMWindowMetadata> windows;

    if (bytecode.empty()) {
        return windows;
    }

    // 计算需要多少个窗口
    uint32_t window_size = config_.window_size;
    uint32_t num_windows = (bytecode.size() + window_size - 1) / window_size;

    // 分割真实窗口
    for (uint32_t i = 0; i < num_windows; ++i) {
        VMWindowMetadata metadata;
        metadata.window_id = i;
        metadata.shard_id = 0;  // 简化实现，不分片
        metadata.offset = i * window_size;
        metadata.size = std::min(window_size, static_cast<uint32_t>(bytecode.size() - metadata.offset));
        metadata.is_chaff = false;
        metadata.real_window_id = i;

        // 提取窗口数据并计算 commitment
        std::vector<uint8_t> window_data(
            bytecode.begin() + metadata.offset,
            bytecode.begin() + metadata.offset + metadata.size
        );
        metadata.commitment = computeCommitment(window_data);

        windows.push_back(metadata);
    }

    // 生成 Chaff 窗口
    if (config_.chaff_percentage > 0) {
        auto chaff_windows = generateChaffWindows(windows, config_.chaff_percentage);
        windows.insert(windows.end(), chaff_windows.begin(), chaff_windows.end());
    }

    // 缓存元数据供运行时使用
    window_metadata_ = windows;

    return windows;
}

bool VMIntegration::generateWindowConfig(
    const std::vector<VMWindowMetadata>& metadata,
    const std::string& output_path) {

    std::ofstream file(output_path);
    if (!file.is_open()) {
        return false;
    }

    // 生成 JSON 配置
    file << "{\n";
    file << "  \"version\": \"1.0\",\n";
    file << "  \"window_size\": " << config_.window_size << ",\n";
    file << "  \"chaff_percentage\": " << config_.chaff_percentage << ",\n";
    file << "  \"total_windows\": " << metadata.size() << ",\n";
    file << "  \"windows\": [\n";

    for (size_t i = 0; i < metadata.size(); ++i) {
        const auto& m = metadata[i];
        file << "    {\n";
        file << "      \"window_id\": " << m.window_id << ",\n";
        file << "      \"shard_id\": " << m.shard_id << ",\n";
        file << "      \"offset\": " << m.offset << ",\n";
        file << "      \"size\": " << m.size << ",\n";
        file << "      \"is_chaff\": " << (m.is_chaff ? "true" : "false") << ",\n";

        // commitment 十六进制
        file << "      \"commitment\": \"";
        for (uint8_t byte : m.commitment) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", byte);
            file << hex;
        }
        file << "\"\n";
        file << "    }";
        if (i < metadata.size() - 1) {
            file << ",";
        }
        file << "\n";
    }

    file << "  ]\n";
    file << "}\n";

    file.close();
    return true;
}

std::vector<uint8_t> VMIntegration::fetchVMWindow(uint32_t window_id) {
    std::lock_guard<std::mutex> lock(g_vm_integration_mutex);

    if (!initialized_ || !zone_adapter_) {
        return {};
    }

    // 查找窗口元数据
    VMWindowMetadata* metadata = nullptr;
    for (auto& m : window_metadata_) {
        if (m.window_id == window_id) {
            metadata = &m;
            break;
        }
    }

    if (!metadata) {
        return {};
    }

    // 如果是 Chaff 窗口，重定向到真实窗口
    if (metadata->is_chaff) {
        window_id = metadata->real_window_id;
        // 重新查找真实窗口元数据
        for (auto& m : window_metadata_) {
            if (m.window_id == window_id && !m.is_chaff) {
                metadata = &m;
                break;
            }
        }
    }

    // 通过 Zone 适配器获取窗口
    WindowRequest request;
    request.window_id = window_id;
    request.shard_id = metadata->shard_id;
    request.commitment = metadata->commitment;

    WindowResponse response = zone_adapter_->fetchWindow(request);

    if (!response.success) {
        return {};
    }

    // 如果启用加密，解密窗口数据
    if (config_.enable_encryption) {
        return decryptWindow(response.data, window_id);
    }

    return response.data;
}

void VMIntegration::prefetchVMWindows(const std::vector<uint32_t>& window_ids) {
    // TODO: 实现批量预取优化
    // 当前简化实现：逐个获取
    for (uint32_t window_id : window_ids) {
        fetchVMWindow(window_id);
    }
}

bool VMIntegration::isVMAuthorized() const {
    if (!initialized_ || !zone_adapter_) {
        return false;
    }

    return zone_adapter_->isZoneAuthorized();
}

VMIntegration::ChaffSchedulerStatus VMIntegration::getChaffStatus() const {
    std::lock_guard<std::mutex> lock(g_vm_integration_mutex);

    ChaffSchedulerStatus status;
    status.total_windows = window_metadata_.size();
    status.real_windows = 0;
    status.chaff_windows = 0;

    for (const auto& m : window_metadata_) {
        if (m.is_chaff) {
            status.chaff_windows++;
        } else {
            status.real_windows++;
        }
    }

    // 简化实现：顺序返回下一个窗口
    status.next_window_id = 0;

    return status;
}

// ============================================================================
// 私有辅助方法
// ============================================================================

std::array<uint8_t, 32> VMIntegration::computeCommitment(const std::vector<uint8_t>& data) {
    std::array<uint8_t, 32> commitment;
    SHA256(data.data(), data.size(), commitment.data());
    return commitment;
}

std::vector<VMIntegration::VMWindowMetadata> VMIntegration::generateChaffWindows(
    const std::vector<VMWindowMetadata>& real_windows,
    uint32_t chaff_percentage) {

    std::vector<VMWindowMetadata> chaff_windows;

    if (chaff_percentage == 0 || real_windows.empty()) {
        return chaff_windows;
    }

    // 计算需要多少个 Chaff 窗口
    uint32_t num_real = real_windows.size();
    uint32_t num_chaff = (num_real * chaff_percentage + 50) / 100;  // 四舍五入

    // 生成 Chaff 窗口
    std::uniform_int_distribution<uint32_t> dist(0, num_real - 1);
    uint32_t next_chaff_id = num_real;  // Chaff 窗口 ID 从真实窗口之后开始

    for (uint32_t i = 0; i < num_chaff; ++i) {
        VMWindowMetadata chaff;
        chaff.window_id = next_chaff_id++;
        chaff.shard_id = 0;
        chaff.offset = 0;
        chaff.size = config_.window_size;
        chaff.is_chaff = true;

        // 随机选择一个真实窗口作为 Chaff 的真实映射
        chaff.real_window_id = real_windows[dist(g_random_generator)].window_id;

        // Chaff 窗口的 commitment 与真实窗口相同
        for (const auto& real : real_windows) {
            if (real.window_id == chaff.real_window_id) {
                chaff.commitment = real.commitment;
                break;
            }
        }

        chaff_windows.push_back(chaff);
    }

    return chaff_windows;
}

std::vector<uint8_t> VMIntegration::encryptWindow(
    const std::vector<uint8_t>& data,
    uint32_t window_id) {

    // 简单 XOR 加密（生产环境应使用 AES）
    std::vector<uint8_t> encrypted = data;
    uint8_t key_byte = static_cast<uint8_t>(window_id & 0xFF);

    for (size_t i = 0; i < encrypted.size(); ++i) {
        encrypted[i] ^= key_byte;
    }

    return encrypted;
}

std::vector<uint8_t> VMIntegration::decryptWindow(
    const std::vector<uint8_t>& encrypted,
    uint32_t window_id) {

    // XOR 加密/解密是对称的
    return encryptWindow(encrypted, window_id);
}

// ============================================================================
// C API 实现
// ============================================================================

extern "C" {

int xovm_cloudmaterial_init(const char* config_json) {
    // 简化实现：使用默认配置
    VMIntegration::VMWindowConfig config;

    auto& vm_integration = VMIntegration::getInstance();
    return vm_integration.initialize(config) ? 0 : -1;
}

int xovm_cloudmaterial_fetch_window(
    uint32_t window_id,
    uint8_t* out_data,
    size_t capacity,
    size_t* out_size) {

    if (!out_data || !out_size) {
        return -1;
    }

    auto& vm_integration = VMIntegration::getInstance();
    std::vector<uint8_t> window_data = vm_integration.fetchVMWindow(window_id);

    if (window_data.empty() || window_data.size() > capacity) {
        *out_size = 0;
        return -1;
    }

    std::memcpy(out_data, window_data.data(), window_data.size());
    *out_size = window_data.size();

    return 0;
}

int xovm_cloudmaterial_check_auth() {
    auto& vm_integration = VMIntegration::getInstance();
    return vm_integration.isVMAuthorized() ? 1 : 0;
}

uint32_t xovm_cloudmaterial_next_window() {
    auto& vm_integration = VMIntegration::getInstance();
    auto status = vm_integration.getChaffStatus();
    return status.next_window_id;
}

void xovm_cloudmaterial_cleanup() {
    // 清理资源（当前简化实现无需清理）
}

} // extern "C"

} // namespace cloud_material
} // namespace xollvm
