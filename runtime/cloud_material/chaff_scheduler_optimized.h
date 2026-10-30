#ifndef XOVM_MATERIAL_CHAFF_SCHEDULER_OPTIMIZED_H_
#define XOVM_MATERIAL_CHAFF_SCHEDULER_OPTIMIZED_H_

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace xovm::material {

// Chaff scheduler with performance optimizations
// - O(1) scheduling with precomputed windows
// - Constant-time chaff selection
// - Minimal memory allocation during execution
class ChaffSchedulerOptimized {
 public:
  // Window distribution configuration
  struct WindowConfig {
    uint32_t total_windows;
    uint32_t chaff_percentage;     // 0-100
    uint32_t cache_line_size;      // typically 64 bytes
    uint32_t max_precomputed_size; // prevent unbounded allocation
  };

  // Precomputed scheduling plan
  struct SchedulingPlan {
    std::vector<uint32_t> window_order;        // precomputed order
    std::vector<uint32_t> chaff_window_ids;    // chaff window indices
    std::vector<size_t> memory_offsets;        // cache-aligned offsets
    uint32_t real_window_count;
    uint32_t chaff_window_count;
  };

  static std::optional<ChaffSchedulerOptimized> create(
      const WindowConfig& config);

  // Get next window in O(1) time
  std::optional<uint32_t> nextWindow();

  // Get chaff window without recomputation
  std::optional<uint32_t> nextChaffWindow();

  // Reset scheduler for new cycle
  void reset();

  // Query current statistics
  uint32_t scheduledCount() const { return scheduled_count_; }
  uint32_t chaffScheduledCount() const { return chaff_scheduled_count_; }
  bool isComplete() const { return scheduled_count_ >= plan_.window_order.size(); }

 private:
  ChaffSchedulerOptimized(const WindowConfig& config, const SchedulingPlan& plan)
      : config_(config), plan_(plan), current_index_(0), chaff_index_(0),
        scheduled_count_(0), chaff_scheduled_count_(0) {}

  WindowConfig config_;
  SchedulingPlan plan_;
  size_t current_index_;
  size_t chaff_index_;
  uint32_t scheduled_count_;
  uint32_t chaff_scheduled_count_;

  // Helper: compute cache-aligned offset
  static size_t computeCacheAlignedOffset(size_t base_offset,
                                          uint32_t cache_line_size);

  // Helper: validate configuration
  static bool validateConfig(const WindowConfig& config);
};

}  // namespace xovm::material

#endif  // XOVM_MATERIAL_CHAFF_SCHEDULER_OPTIMIZED_H_
