#include "cloud_value_manager.h"

#include <cstring>
#include <ctime>
#include <unistd.h>
#include <openssl/sha.h>

// zone_wrapper 提供的网络桥。弱符号：独立单测（只链本文件）时缺失，
// fetchVFromCloud 自动退化为返回 false。
extern "C" {
int xollvm_zone_vm_dispatch_refresh(void) __attribute__((weak));
int xollvm_zone_vm_dispatch_copy_v(uint8_t*) __attribute__((weak));
}

namespace xollvm {

// 编译期嵌入的初始 V（云端预生成，针对构建时的某个 window）。
// 全零表示"无初始值"：此时 offset 由 HMAC(0.., window) 得出，几乎必然非 0，
// 首次运行若未及时拉到有效 V，VM 会自然崩溃——这是约定的失效路径。
static const uint8_t INITIAL_V[V_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

CloudValueManager::CloudValueManager()
    : m_time_offset(0)
    , m_running(false)
    , m_thread(0)
    , m_initialized(false) {
    std::memcpy(m_V.data, INITIAL_V, V_SIZE);
    m_V.fetch_time.store(0, std::memory_order_release);
}

CloudValueManager::~CloudValueManager() {
    shutdown();
}

CloudValueManager& CloudValueManager::getInstance() {
    static CloudValueManager instance;
    return instance;
}

void CloudValueManager::initialize() {
    if (m_initialized) return;
    m_running.store(true, std::memory_order_release);
    if (pthread_create(&m_thread, nullptr, updaterThreadEntry, this) != 0) {
        m_running.store(false, std::memory_order_release);
        return;
    }
    pthread_detach(m_thread);
    m_initialized = true;
}

void CloudValueManager::shutdown() {
    if (!m_initialized) return;
    m_running.store(false, std::memory_order_release);
    m_initialized = false;
}

int64_t CloudValueManager::getSyncedTimestamp() {
    return static_cast<int64_t>(std::time(nullptr))
        + m_time_offset.load(std::memory_order_acquire);
}

uint64_t CloudValueManager::getWindowId() {
    int64_t ts = getSyncedTimestamp();
    if (ts < 0) ts = 0;
    return static_cast<uint64_t>(ts) / VM_DISPATCH_WINDOW_SEC;
}

void CloudValueManager::setTimeOffset(int64_t offset) {
    m_time_offset.store(offset, std::memory_order_release);
}

void CloudValueManager::updateV(const uint8_t* new_V, size_t len) {
    if (!new_V || len < V_SIZE) return;
    std::memcpy(m_V.data, new_V, V_SIZE);
    m_V.fetch_time.store(getSyncedTimestamp(), std::memory_order_release);
}

uint64_t CloudValueManager::hmac64(const uint8_t* key, size_t key_len,
                                   const uint8_t* data, size_t data_len) {
    // 手写 HMAC-SHA256，只用 SHA256_* 原语：
    // 避免一次性 HMAC()/EVP_sha256() 在 zone 符号前缀流水线中漏改前缀。
    uint8_t k[64];
    std::memset(k, 0, sizeof(k));
    if (key_len > 64) {
        SHA256(key, key_len, k);  // 超长 key 先哈希
    } else if (key_len > 0) {
        std::memcpy(k, key, key_len);
    }

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }

    uint8_t inner[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, ipad, sizeof(ipad));
    SHA256_Update(&ctx, data, data_len);
    SHA256_Final(inner, &ctx);

    uint8_t outer[SHA256_DIGEST_LENGTH];
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, opad, sizeof(opad));
    SHA256_Update(&ctx, inner, sizeof(inner));
    SHA256_Final(outer, &ctx);

    uint64_t result = 0;
    std::memcpy(&result, outer, sizeof(result));
    return result;
}

uint64_t CloudValueManager::computeDispatchOffset() {
    // 惰性启动预取线程：首次进入 dispatch 时立即拉取当前 window 的 V
    std::call_once(m_init_once, [this]() { initialize(); });

    uint8_t V_snapshot[V_SIZE];
    std::memcpy(V_snapshot, m_V.data, V_SIZE);

    uint64_t window = getWindowId();
    uint64_t raw = hmac64(V_snapshot, V_SIZE,
                          reinterpret_cast<const uint8_t*>(&window), sizeof(window));

    // 合法 V 下该值为 0；否则落在 (0, MASK]，被 dispatch 用作越界位移
    return raw & static_cast<uint64_t>(VM_DISPATCH_OFFSET_MASK);
}

bool CloudValueManager::fetchVFromCloud(uint64_t windowId, uint8_t* out_V) {
    // 复用 zone_wrapper 的既有网络/登录/租约/capability 流水线：
    //   xollvm_zone_vm_dispatch_refresh() 发起 vm_dispatch 请求并解析 dispatch_v
    //   xollvm_zone_vm_dispatch_copy_v()  取回 32 字节原始 V
    // 两者以弱符号声明：独立单测（未链接 zone_wrapper）时自动退化为无云值。
    (void)windowId;
    if (!xollvm_zone_vm_dispatch_refresh || !xollvm_zone_vm_dispatch_copy_v)
        return false;
    if (xollvm_zone_vm_dispatch_refresh() != 1)
        return false;
    return xollvm_zone_vm_dispatch_copy_v(out_V) == 1;
}

void* CloudValueManager::updaterThreadEntry(void* arg) {
    CloudValueManager* mgr = static_cast<CloudValueManager*>(arg);
    if (mgr) mgr->updaterThreadLoop();
    return nullptr;
}

void CloudValueManager::updaterThreadLoop() {
    bool first = true;
    while (m_running.load(std::memory_order_acquire)) {
        // 启动时立即拉取，之后按预取间隔轮询
        if (!first) {
            sleep(VM_DISPATCH_PREFETCH_SEC);
            if (!m_running.load(std::memory_order_acquire)) break;
        }
        first = false;

        uint64_t window = getWindowId();
        uint8_t new_V[V_SIZE];

        uint32_t retry = 0;
        bool success = false;
        while (retry < V_REQUEST_RETRY && !success) {
            success = fetchVFromCloud(window, new_V);
            if (!success) {
                ++retry;
                if (retry < V_REQUEST_RETRY - 1) sleep(2);
            }
        }

        if (success) {
            std::memcpy(m_V.data, new_V, V_SIZE);
            m_V.fetch_time.store(getSyncedTimestamp(), std::memory_order_release);
        }
        // 失败：继续用旧 V。窗口推进后 offset 自然偏离，VM 崩溃。
    }
}

} // namespace xollvm

extern "C" uint64_t __zone_get_dispatch_offset() {
    return xollvm::CloudValueManager::getInstance().computeDispatchOffset();
}
