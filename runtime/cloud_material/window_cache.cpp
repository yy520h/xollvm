// ============================================================================
// window_cache.cpp - 窗口缓存系统实现
// ============================================================================

#include "window_cache.h"
#include <algorithm>

namespace xovm::material {

WindowCache::WindowCache(const Config& config)
    : config_(config) {
    stats_ = {};
}

WindowCache::~WindowCache() {
    clear();
}

std::optional<CachedWindow> WindowCache::get(uint32_t window_id, uint32_t shard_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (config_.enable_stats) {
        stats_.total_requests++;
    }

    uint64_t key = make_key(window_id, shard_id);
    auto it = cache_map_.find(key);

    if (it != cache_map_.end()) {
        auto& entry = it->second;
        auto& window = entry.window;

        // 检查是否过期
        if (!is_expired(window)) {
            // 更新访问统计
            window.access_count++;
            window.hit_count++;

            // 更新LRU
            auto lru_key = std::make_pair(window_id, shard_id);
            touch(lru_key);

            if (config_.enable_stats) {
                stats_.cache_hits++;
            }

            return window;
        } else {
            // 过期，删除
            lru_list_.erase(entry.lru_it);
            cache_map_.erase(it);
        }
    }

    if (config_.enable_stats) {
        stats_.cache_misses++;
    }

    return std::nullopt;
}

void WindowCache::put(const CachedWindow& window) {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t key = make_key(window.window_id, window.shard_id);
    auto lru_key = std::make_pair(window.window_id, window.shard_id);

    // 如果已存在，先删除旧的
    auto it = cache_map_.find(key);
    if (it != cache_map_.end()) {
        lru_list_.erase(it->second.lru_it);
        cache_map_.erase(it);
    }

    // 如果缓存已满，驱逐最老的
    if (cache_map_.size() >= config_.max_size) {
        evict_lru();
    }

    // 添加到LRU列表头部
    lru_list_.push_front(lru_key);

    CacheEntry entry;
    entry.window = window;
    entry.lru_it = lru_list_.begin();

    cache_map_[key] = entry;
}

void WindowCache::put_batch(const std::vector<CachedWindow>& windows) {
    for (const auto& window : windows) {
        put(window);
    }
}

std::vector<uint32_t> WindowCache::get_prefetch_ids(uint32_t current_window_id) {
    std::vector<uint32_t> ids;

    if (!config_.enable_prefetch) {
        return ids;
    }

    // 简单策略：预取接下来的N个窗口
    for (uint32_t i = 1; i <= config_.prefetch_count; ++i) {
        ids.push_back(current_window_id + i);
    }

    return ids;
}

void WindowCache::evict_expired() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = cache_map_.begin();
    while (it != cache_map_.end()) {
        if (is_expired(it->second.window)) {
            lru_list_.erase(it->second.lru_it);
            it = cache_map_.erase(it);

            if (config_.enable_stats) {
                stats_.evictions++;
            }
        } else {
            ++it;
        }
    }
}

void WindowCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    lru_list_.clear();
    cache_map_.clear();
}

CacheStats WindowCache::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void WindowCache::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = {};
}

void WindowCache::touch(const LRUKey& key) {
    // 将指定键移到LRU列表头部
    auto it = std::find(lru_list_.begin(), lru_list_.end(), key);
    if (it != lru_list_.end()) {
        lru_list_.splice(lru_list_.begin(), lru_list_, it);

        // 更新cache_map中的迭代器
        uint64_t map_key = make_key(key.first, key.second);
        cache_map_[map_key].lru_it = lru_list_.begin();
    }
}

void WindowCache::evict_lru() {
    if (lru_list_.empty()) return;

    // 驱逐最老的（列表尾部）
    auto oldest_key = lru_list_.back();
    uint64_t map_key = make_key(oldest_key.first, oldest_key.second);

    cache_map_.erase(map_key);
    lru_list_.pop_back();

    if (config_.enable_stats) {
        stats_.evictions++;
    }
}

bool WindowCache::is_expired(const CachedWindow& window) const {
    auto now = std::chrono::steady_clock::now();
    auto age = std::chrono::duration_cast<std::chrono::seconds>(
        now - window.cached_at);

    return age.count() >= static_cast<long>(config_.ttl_seconds);
}

} // namespace xovm::material
