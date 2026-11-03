// ============================================================================
// window_cache.h - 窗口缓存系统
//
// 功能:
// 1. LRU缓存策略
// 2. 窗口预取
// 3. 批量获取优化
// 4. 缓存统计
// ============================================================================

#ifndef XOVM_MATERIAL_WINDOW_CACHE_H
#define XOVM_MATERIAL_WINDOW_CACHE_H

#include <cstdint>
#include <vector>
#include <unordered_map>
#include <list>
#include <optional>
#include <mutex>
#include <chrono>

namespace xovm::material {

// ============================================================================
// 窗口缓存项
// ============================================================================

struct CachedWindow {
    uint32_t window_id;
    uint32_t shard_id;
    std::vector<uint8_t> bytecode;
    uint8_t commitment[32];

    // 缓存元数据
    std::chrono::steady_clock::time_point cached_at;
    uint32_t access_count;
    uint32_t hit_count;
};

// ============================================================================
// 缓存统计
// ============================================================================

struct CacheStats {
    uint64_t total_requests;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t evictions;
    uint64_t prefetch_hits;

    double hit_rate() const {
        return total_requests > 0
            ? static_cast<double>(cache_hits) / total_requests
            : 0.0;
    }

    double prefetch_efficiency() const {
        return cache_hits > 0
            ? static_cast<double>(prefetch_hits) / cache_hits
            : 0.0;
    }
};

// ============================================================================
// LRU窗口缓存
// ============================================================================

class WindowCache {
public:
    struct Config {
        size_t max_size = 50;              // 最大缓存窗口数
        bool enable_prefetch = true;       // 启用预取
        uint32_t prefetch_count = 3;       // 预取数量
        uint32_t ttl_seconds = 300;        // 缓存过期时间（秒）
        bool enable_stats = true;          // 启用统计
    };

    explicit WindowCache(const Config& config);
    ~WindowCache();

    // 查找窗口（如果命中返回true）
    std::optional<CachedWindow> get(uint32_t window_id, uint32_t shard_id);

    // 添加窗口到缓存
    void put(const CachedWindow& window);

    // 批量添加
    void put_batch(const std::vector<CachedWindow>& windows);

    // 预取窗口
    std::vector<uint32_t> get_prefetch_ids(uint32_t current_window_id);

    // 清除过期条目
    void evict_expired();

    // 清空缓存
    void clear();

    // 获取统计信息
    CacheStats get_stats() const;

    // 重置统计
    void reset_stats();

private:
    // LRU链表节点
    using LRUKey = std::pair<uint32_t, uint32_t>;  // (window_id, shard_id)
    using LRUList = std::list<LRUKey>;
    using LRUIterator = LRUList::iterator;

    struct CacheEntry {
        CachedWindow window;
        LRUIterator lru_it;
    };

    // 内部方法
    void touch(const LRUKey& key);
    void evict_lru();
    bool is_expired(const CachedWindow& window) const;

    Config config_;

    // LRU结构
    LRUList lru_list_;
    std::unordered_map<uint64_t, CacheEntry> cache_map_;  // key = (window_id << 32) | shard_id

    // 统计
    CacheStats stats_;

    // 线程安全
    mutable std::mutex mutex_;

    // 辅助函数
    static uint64_t make_key(uint32_t window_id, uint32_t shard_id) {
        return (static_cast<uint64_t>(window_id) << 32) | shard_id;
    }
};

// ============================================================================
// 批量窗口获取器
// ============================================================================

class BatchWindowFetcher {
public:
    struct Config {
        uint32_t batch_size = 5;           // 每批获取数量
        uint32_t max_parallel = 3;         // 最大并行请求数
        uint32_t timeout_ms = 5000;        // 超时时间
    };

    explicit BatchWindowFetcher(const Config& config);

    // 批量获取窗口
    std::vector<CachedWindow> fetch_batch(
        const std::vector<uint32_t>& window_ids,
        uint32_t shard_id
    );

    // 异步预取
    void prefetch_async(
        const std::vector<uint32_t>& window_ids,
        uint32_t shard_id
    );

private:
    Config config_;
};

// ============================================================================
// 性能优化管理器
// ============================================================================

class PerformanceOptimizer {
public:
    struct Config {
        WindowCache::Config cache_config;
        BatchWindowFetcher::Config batch_config;

        bool enable_compression = false;    // 启用压缩
        bool enable_delta_encoding = false; // 增量编码
    };

    explicit PerformanceOptimizer(const Config& config);

    // 智能窗口获取（带缓存和预取）
    std::optional<CachedWindow> fetch_window_smart(
        uint32_t window_id,
        uint32_t shard_id
    );

    // 获取性能报告
    struct PerformanceReport {
        CacheStats cache_stats;
        uint64_t total_bytes_fetched;
        uint64_t total_bytes_saved;  // 通过缓存节省
        double avg_fetch_time_ms;
        double avg_cache_time_us;
    };

    PerformanceReport get_report() const;

private:
    Config config_;
    WindowCache cache_;
    BatchWindowFetcher batch_fetcher_;

    // 性能指标
    uint64_t total_bytes_fetched_;
    std::chrono::steady_clock::duration total_fetch_time_;
    std::chrono::steady_clock::duration total_cache_time_;
};

} // namespace xovm::material

#endif // XOVM_MATERIAL_WINDOW_CACHE_H
