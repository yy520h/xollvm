#pragma once

#include <cstdint>
#include <atomic>
#include <mutex>
#include <pthread.h>

namespace xollvm {

// VM Dispatch 云值保护方案运行时管理器
//
// 语义约定（与编译期 VM dispatch 协同）：
//   dispatch_offset = HMAC(V, window_id) & VM_DISPATCH_OFFSET_MASK
//   - V 由云端下发，window_id = floor(server_time / VM_DISPATCH_WINDOW_SEC)
//   - 合法 V：offset == 0，dispatch 基址不发生偏移，VM 正常执行
//   - 过期/缺失/错误 V：offset != 0（最高可达 MASK），dispatch 基址被推移到
//     未映射区域，indirectbr 到非法地址，SIGSEGV
//   - 本地不做任何 if(valid)/if(expired) 判断
//
// 云端职责：为当前 window 搜索一个 V，使 HMAC(V, window_id) & MASK == 0。
// 期望搜索次数为 2^bits（见 MASK 位宽），每次一个 HMAC。

// 偏移掩码：错误 offset 的取值范围。位宽越大越保证越界崩溃，但云端搜索越贵。
// 12 bit：云端期望 ~2^12=4096 次 HMAC（毫秒级）；20 bit 会让云端每 window
// 搜索 ~2^20 次而超时，因此两端必须同时使用 12 bit。
#ifndef VM_DISPATCH_OFFSET_MASK
#define VM_DISPATCH_OFFSET_MASK 0x00000FFFu   // 12 bit，云端期望 ~2^12 次 HMAC
#endif

// 云值时效窗口（秒）
#ifndef VM_DISPATCH_WINDOW_SEC
#define VM_DISPATCH_WINDOW_SEC 60
#endif

// 预取间隔（秒），需满足 window >= prefetch + 抖动余量
#ifndef VM_DISPATCH_PREFETCH_SEC
#define VM_DISPATCH_PREFETCH_SEC 50
#endif

constexpr size_t V_SIZE = 32;                 // HMAC-SHA256 输出长度
constexpr uint32_t V_REQUEST_RETRY = 3;       // 网络失败重试次数

// CloudValue 存储结构
struct CloudValue {
    uint8_t data[V_SIZE];
    std::atomic<int64_t> fetch_time;          // 获取时的服务器时间（秒）

    CloudValue() : fetch_time(0) {
        for (size_t i = 0; i < V_SIZE; ++i) data[i] = 0;
    }
};

class CloudValueManager {
public:
    static CloudValueManager& getInstance();

    void initialize();                        // 启动后台预取线程
    void shutdown();

    // 当前 dispatch 位移：0 表示合法，非 0 表示错误（将导致越界崩溃）
    uint64_t computeDispatchOffset();

    int64_t getSyncedTimestamp();             // 服务器时间（秒）
    uint64_t getWindowId();                   // floor(ts / WINDOW_SEC)
    void setTimeOffset(int64_t offset);       // 首次连接时校准
    void updateV(const uint8_t* new_V, size_t len);

private:
    CloudValueManager();
    ~CloudValueManager();
    CloudValueManager(const CloudValueManager&) = delete;
    CloudValueManager& operator=(const CloudValueManager&) = delete;

    static void* updaterThreadEntry(void* arg);
    void updaterThreadLoop();
    bool fetchVFromCloud(uint64_t windowId, uint8_t* out_V);
    uint64_t hmac64(const uint8_t* key, size_t key_len,
                    const uint8_t* data, size_t data_len);

    CloudValue m_V;
    std::atomic<int64_t> m_time_offset;
    std::atomic<bool> m_running;
    pthread_t m_thread;
    bool m_initialized;
    std::once_flag m_init_once;               // 首次调用时惰性启动预取线程
};

} // namespace xollvm

extern "C" {
    // 供编译期生成的 VM dispatch 代码调用
    uint64_t __zone_get_dispatch_offset();
}
