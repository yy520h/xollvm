#include "zone_adapter.h"
#include "hmac_client.h"
#include "commitment_verifier.h"
#include "ecc_window_client.h"
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>
#include <mutex>
#include <sstream>
#include <curl/curl.h>

// Zone capability 外部接口声明
extern "C" {
    // Zone capability 系统函数
    bool xollvm_zone_capability_begin(const char* name, const char* params);
    bool xollvm_zone_require(const char* name);
    int xollvm_zone_capability_invoke(const char* name, const void* input, size_t input_len,
                                      void* output, size_t output_capacity, size_t* output_len);
}

namespace xollvm {
namespace cloud_material {

namespace {
    std::mutex g_adapter_mutex;
}

ZoneAdapter& ZoneAdapter::getInstance() {
    static ZoneAdapter instance;
    return instance;
}

ZoneAdapter::ZoneAdapter()
    : mode_(AccessMode::ZONE_RELAY)
    , initialized_(false)
    , zone_available_(false)
    , stats_{0, 0, 0, 0, 0} {
}

ZoneAdapter::~ZoneAdapter() {
}

bool ZoneAdapter::initialize(AccessMode mode, const std::string& zone_capability_name) {
    std::lock_guard<std::mutex> lock(g_adapter_mutex);

    if (initialized_) {
        return true;
    }

    mode_ = mode;
    zone_capability_name_ = zone_capability_name;

    // 如果是 Zone 中转模式，尝试注册 Zone capability
    if (mode_ == AccessMode::ZONE_RELAY) {
        zone_available_ = registerWithZone();
        if (!zone_available_) {
            // Zone 不可用，降级到直接访问模式
            mode_ = AccessMode::DIRECT_BACKEND;
        }
    }

    // 检查环境变量强制配置
    if (isForceZoneMode() && mode_ != AccessMode::ZONE_RELAY) {
        // 生产环境强制要求 Zone 模式但 Zone 不可用
        return false;
    }

    initialized_ = true;
    return true;
}

WindowResponse ZoneAdapter::fetchWindow(const WindowRequest& request) {
    auto start = std::chrono::steady_clock::now();

    WindowResponse response;
    response.success = false;
    response.timestamp = std::chrono::system_clock::now().time_since_epoch().count();

    {
        std::lock_guard<std::mutex> lock(g_adapter_mutex);
        stats_.total_requests++;
    }

    // 根据模式选择访问路径
    if (mode_ == AccessMode::ZONE_RELAY && zone_available_) {
        response = fetchViaZone(request);
        std::lock_guard<std::mutex> lock(g_adapter_mutex);
        stats_.zone_relay_requests++;
    } else {
        response = fetchDirect(request);
        std::lock_guard<std::mutex> lock(g_adapter_mutex);
        stats_.direct_requests++;
    }

    if (!response.success) {
        std::lock_guard<std::mutex> lock(g_adapter_mutex);
        stats_.failed_requests++;
    }

    // 更新延迟统计
    auto end = std::chrono::steady_clock::now();
    auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    {
        std::lock_guard<std::mutex> lock(g_adapter_mutex);
        // 简单移动平均
        stats_.average_latency_ms = (stats_.average_latency_ms * (stats_.total_requests - 1) + latency) / stats_.total_requests;
    }

    return response;
}

std::vector<WindowResponse> ZoneAdapter::fetchWindowBatch(const std::vector<WindowRequest>& requests) {
    std::vector<WindowResponse> responses;
    responses.reserve(requests.size());

    // 简单实现：逐个获取
    // TODO: 实现真正的批量请求优化
    for (const auto& request : requests) {
        responses.push_back(fetchWindow(request));
    }

    return responses;
}

void ZoneAdapter::setAccessMode(AccessMode mode) {
    std::lock_guard<std::mutex> lock(g_adapter_mutex);

    if (mode == AccessMode::ZONE_RELAY && !zone_available_) {
        // Zone 不可用，无法切换到 Zone 模式
        return;
    }

    mode_ = mode;
}

bool ZoneAdapter::isZoneAuthorized() const {
    if (mode_ != AccessMode::ZONE_RELAY || !zone_available_) {
        return false;
    }

    // 检查 Zone capability 是否已授权
    return xollvm_zone_require(zone_capability_name_.c_str());
}

ZoneAdapter::Statistics ZoneAdapter::getStatistics() const {
    std::lock_guard<std::mutex> lock(g_adapter_mutex);
    return stats_;
}

// ============================================================================
// Zone 中转模式实现
// ============================================================================

WindowResponse ZoneAdapter::fetchViaZone(const WindowRequest& request) {
    WindowResponse response;
    response.success = false;

    if (!zone_available_) {
        response.error_message = "Zone capability not available";
        return response;
    }

    // 通过 Zone capability 请求窗口
    std::vector<uint8_t> window_data;
    if (!requestZoneWindow(request, window_data)) {
        response.error_message = "Zone window request failed";
        return response;
    }

    // 验证 commitment (SHA256)
    if (!CommitmentVerifier::verify(window_data, request.commitment)) {
        response.error_message = "Window commitment verification failed";
        return response;
    }

    response.success = true;
    response.data = std::move(window_data);
    response.timestamp = std::chrono::system_clock::now().time_since_epoch().count();

    return response;
}

bool ZoneAdapter::registerWithZone() {
    // 尝试注册 CloudMaterial capability 到 Zone
    // 参数格式：窗口大小、缓存策略等配置
    const char* params = "window_size=2048,cache=lru,ttl=300";

    if (!xollvm_zone_capability_begin(zone_capability_name_.c_str(), params)) {
        return false;
    }

    // 检查 capability 是否已激活
    if (!xollvm_zone_require(zone_capability_name_.c_str())) {
        return false;
    }

    return true;
}

bool ZoneAdapter::requestZoneWindow(const WindowRequest& request, std::vector<uint8_t>& out_data) {
    // 构造请求数据包
    // 格式: [window_id(4字节)] [shard_id(4字节)] [commitment(32字节)]
    uint8_t input_buffer[40];
    std::memcpy(input_buffer, &request.window_id, 4);
    std::memcpy(input_buffer + 4, &request.shard_id, 4);
    std::memcpy(input_buffer + 8, request.commitment.data(), 32);

    // 预分配输出缓冲区（假设窗口最大 8KB）
    constexpr size_t MAX_WINDOW_SIZE = 8192;
    out_data.resize(MAX_WINDOW_SIZE);

    size_t actual_size = 0;
    int result = xollvm_zone_capability_invoke(
        zone_capability_name_.c_str(),
        input_buffer, sizeof(input_buffer),
        out_data.data(), out_data.size(),
        &actual_size
    );

    if (result != 0 || actual_size == 0) {
        out_data.clear();
        return false;
    }

    // 调整到实际大小
    out_data.resize(actual_size);
    return true;
}

// ============================================================================
// 直接访问模式实现
// ============================================================================

namespace {
    // libcurl 写入回调
    size_t curl_write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
        size_t total_size = size * nmemb;
        std::vector<uint8_t>* buffer = static_cast<std::vector<uint8_t>*>(userp);

        size_t old_size = buffer->size();
        buffer->resize(old_size + total_size);
        std::memcpy(buffer->data() + old_size, contents, total_size);

        return total_size;
    }

    // 从环境变量或配置获取后端配置
    struct DirectBackendConfig {
        std::string url;
        std::string hmac_secret;
        std::string device_id;
        bool enable_tls;
        bool enable_ecc;
        std::string ecc_server_pubkey;
        int timeout_seconds;

        static DirectBackendConfig fromEnvironment() {
            DirectBackendConfig config;

            const char* url_env = std::getenv("XOLLVM_BACKEND_URL");
            config.url = url_env ? url_env : "http://localhost:8080";

            const char* secret_env = std::getenv("XOLLVM_HMAC_SECRET");
            config.hmac_secret = secret_env ? secret_env : "";

            const char* device_env = std::getenv("XOLLVM_DEVICE_ID");
            config.device_id = device_env ? device_env : "unknown-device";

            const char* tls_env = std::getenv("XOLLVM_ENABLE_TLS");
            config.enable_tls = tls_env ? (std::strcmp(tls_env, "1") == 0) : false;

            const char* ecc_env = std::getenv("XOLLVM_ENABLE_ECC");
            config.enable_ecc = ecc_env ? (std::strcmp(ecc_env, "1") == 0) : true;  // 默认启用

            const char* ecc_pubkey_env = std::getenv("XOLLVM_ECC_SERVER_PUBKEY");
            config.ecc_server_pubkey = ecc_pubkey_env ? ecc_pubkey_env : "";

            config.timeout_seconds = 10;

            return config;
        }
    };

    // 全局 ECC 客户端实例（延迟初始化）
    static ECCWindowClient* g_ecc_client = nullptr;
    static std::mutex g_ecc_mutex;
}

WindowResponse ZoneAdapter::fetchDirect(const WindowRequest& request) {
    WindowResponse response;
    response.success = false;
    response.timestamp = std::chrono::system_clock::now().time_since_epoch().count();

    // 获取后端配置
    static DirectBackendConfig config = DirectBackendConfig::fromEnvironment();

    if (config.hmac_secret.empty()) {
        response.error_message = "HMAC secret not configured";
        return response;
    }

    // 初始化 ECC 客户端（如果启用）
    if (config.enable_ecc && !config.ecc_server_pubkey.empty()) {
        std::lock_guard<std::mutex> lock(g_ecc_mutex);
        if (!g_ecc_client) {
            g_ecc_client = new ECCWindowClient(config.ecc_server_pubkey);
            if (!g_ecc_client->isValid()) {
                delete g_ecc_client;
                g_ecc_client = nullptr;
                response.error_message = "Failed to initialize ECC client";
                return response;
            }
        }
    }

    // 生成临时 ECC 密钥（如果启用）
    std::string ephemeral_pubkey;
    if (config.enable_ecc && g_ecc_client) {
        std::lock_guard<std::mutex> lock(g_ecc_mutex);
        ephemeral_pubkey = g_ecc_client->generateEphemeralKey();
        if (ephemeral_pubkey.empty()) {
            response.error_message = "Failed to generate ephemeral key";
            return response;
        }
    }

    // 初始化 curl
    CURL* curl = curl_easy_init();
    if (!curl) {
        response.error_message = "Failed to initialize curl";
        return response;
    }

    // 构造请求 JSON
    std::ostringstream json_body;
    json_body << "{\"material_id\":\"material_" << request.window_id << "\"";
    json_body << ",\"window_id\":" << request.window_id;
    json_body << ",\"shard_id\":" << request.shard_id;

    // 添加临时公钥（ECC 模式）
    if (!ephemeral_pubkey.empty()) {
        json_body << ",\"ephemeral_pubkey\":\"" << ephemeral_pubkey << "\"";
    }

    json_body << "}";
    std::string payload = json_body.str();

    // 生成 HMAC 认证头
    HMACClient hmac_client(config.hmac_secret, config.device_id);
    std::string auth_header = hmac_client.generateAuthHeader(payload);

    // 设置 HTTP 头
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, ("Authorization: " + auth_header).c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");

    // 设置 curl 选项
    std::string url = config.url + "/api/v1/window";
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, config.timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.data);

    // TLS 配置
    if (config.enable_tls) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    } else {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    // 执行请求
    CURLcode res = curl_easy_perform(curl);

    // 检查结果
    if (res == CURLE_OK) {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        if (http_code == 200) {
            // ECC 解密（如果启用）
            std::vector<uint8_t> decrypted_data;
            if (config.enable_ecc && g_ecc_client) {
                std::lock_guard<std::mutex> lock(g_ecc_mutex);
                decrypted_data = g_ecc_client->decryptWindow(response.data);

                if (decrypted_data.empty()) {
                    response.error_message = "ECC decryption failed";
                    response.data.clear();
                } else {
                    response.data = std::move(decrypted_data);
                }
            }

            // 验证窗口数据的 commitment（在解密后）
            if (!response.data.empty() && CommitmentVerifier::verify(response.data, request.commitment)) {
                response.success = true;
            } else {
                response.error_message = "Window commitment verification failed";
                response.data.clear();
            }
        } else if (http_code == 401) {
            response.error_message = "Authentication failed";
        } else if (http_code == 429) {
            response.error_message = "Rate limit exceeded";
        } else if (http_code == 404) {
            response.error_message = "Window not found";
        } else {
            response.error_message = "HTTP error: " + std::to_string(http_code);
        }
    } else {
        response.error_message = "Network error: " + std::string(curl_easy_strerror(res));
    }

    // 清理
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return response;
}

// ============================================================================
// 全局配置函数
// ============================================================================

AccessMode getAccessModeFromConfig() {
    const char* mode_env = std::getenv("XOLLVM_CLOUDMATERIAL_MODE");
    if (mode_env) {
        if (std::strcmp(mode_env, "zone") == 0) {
            return AccessMode::ZONE_RELAY;
        } else if (std::strcmp(mode_env, "direct") == 0) {
            return AccessMode::DIRECT_BACKEND;
        }
    }

    // 默认使用 Zone 中转模式（更安全）
    return AccessMode::ZONE_RELAY;
}

bool isForceZoneMode() {
    const char* force_env = std::getenv("XOLLVM_CLOUDMATERIAL_FORCE_ZONE");
    return force_env && std::strcmp(force_env, "1") == 0;
}

} // namespace cloud_material
} // namespace xollvm
