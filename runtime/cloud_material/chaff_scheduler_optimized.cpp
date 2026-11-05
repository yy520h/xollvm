#include "runtime/cloud_material/chaff_scheduler_optimized.h"

namespace xovm::material {

bool ChaffSchedulerOptimized::validateConfig(const WindowConfig& config) {
  if (config.total_windows == 0 || config.total_windows > 1000000) {
    return false;
  }
  if (config.chaff_percentage > 100) {
    return false;
  }
  if (config.cache_line_size == 0 || config.cache_line_size > 256) {
    return false;
  }
  if (config.max_precomputed_size == 0) {
    return false;
  }
  return true;
}

size_t ChaffSchedulerOptimized::computeCacheAlignedOffset(
    size_t base_offset, uint32_t cache_line_size) {
  // Round up to next cache line boundary
  return ((base_offset + cache_line_size - 1) / cache_line_size) *
         cache_line_size;
}

std::optional<ChaffSchedulerOptimized> ChaffSchedulerOptimized::create(
    const WindowConfig& config) {
  if (!validateConfig(config)) {
    return std::nullopt;
  }

  SchedulingPlan plan;
  plan.real_window_count =
      (config.total_windows * (100 - config.chaff_percentage)) / 100;
  plan.chaff_window_count = config.total_windows - plan.real_window_count;

  // Validate against max precomputed size
  if (plan.window_order.capacity() > config.max_precomputed_size) {
    return std::nullopt;
  }

  // Precompute window order with chaff interleaving
  // Strategy: distribute chaff evenly across window sequence
  uint32_t chaff_stride = plan.real_window_count > 0
                              ? plan.real_window_count / plan.chaff_window_count
                              : 1;
  if (chaff_stride == 0) {
    chaff_stride = 1;
  }

  plan.window_order.reserve(config.total_windows);
  uint32_t real_idx = 0;
  uint32_t chaff_idx = 0;

  for (uint32_t i = 0; i < config.total_windows; ++i) {
    if (chaff_idx < plan.chaff_window_count &&
        (i % chaff_stride == 0 || real_idx >= plan.real_window_count)) {
      plan.window_order.push_back(0x80000000 | chaff_idx);  // mark as chaff
      plan.chaff_window_ids.push_back(chaff_idx);
      chaff_idx++;
    } else if (real_idx < plan.real_window_count) {
      plan.window_order.push_back(real_idx);
      real_idx++;
    }
  }

  // Precompute memory offsets
  plan.memory_offsets.reserve(config.total_windows);
  size_t current_offset = 0;
  for (uint32_t i = 0; i < config.total_windows; ++i) {
    plan.memory_offsets.push_back(current_offset);
    current_offset =
        computeCacheAlignedOffset(current_offset + 64, config.cache_line_size);
  }

  return ChaffSchedulerOptimized(config, plan);
}

std::optional<uint32_t> ChaffSchedulerOptimized::nextWindow() {
  if (current_index_ >= plan_.window_order.size()) {
    return std::nullopt;
  }

  uint32_t window_id = plan_.window_order[current_index_++];
  scheduled_count_++;

  if (window_id & 0x80000000) {
    // This is a chaff window
    return std::nullopt;
  }

  return window_id;
}

std::optional<uint32_t> ChaffSchedulerOptimized::nextChaffWindow() {
  if (chaff_index_ >= plan_.chaff_window_ids.size()) {
    return std::nullopt;
  }

  uint32_t chaff_id = plan_.chaff_window_ids[chaff_index_++];
  chaff_scheduled_count_++;
  return chaff_id;
}

void ChaffSchedulerOptimized::reset() {
  current_index_ = 0;
  chaff_index_ = 0;
  scheduled_count_ = 0;
  chaff_scheduled_count_ = 0;
}

}  // namespace xovm::material
