#ifndef XOVM_MATERIAL_PERFORMANCE_MONITOR_H_
#define XOVM_MATERIAL_PERFORMANCE_MONITOR_H_

#include <cstdint>
#include <optional>
#include <vector>

namespace xovm::material {

// Performance monitor for runtime metrics collection
// Implements fail-closed principle with validated metrics
class PerformanceMonitor {
 public:
  // Metric categories
  enum class MetricCategory {
    WindowExecution,
    ChaffScheduling,
    GuardianVerification,
    CloudCommunication,
    RelocationApplication
  };

  // Single metric sample
  struct MetricSample {
    MetricCategory category;
    uint64_t timestamp_us;  // microseconds since epoch
    uint64_t duration_us;   // execution duration
    uint32_t operation_id;  // specific operation identifier
    bool success;           // operation success flag
  };

  // Aggregated statistics
  struct AggregatedStats {
    MetricCategory category;
    uint64_t total_operations;
    uint64_t successful_operations;
    uint64_t failed_operations;
    uint64_t min_duration_us;
    uint64_t max_duration_us;
    uint64_t avg_duration_us;
    uint64_t p50_duration_us;  // median
    uint64_t p95_duration_us;
    uint64_t p99_duration_us;
  };

  // Monitor configuration
  struct MonitorConfig {
    uint32_t max_samples;        // maximum samples to retain
    uint32_t aggregation_window; // window size for stats (seconds)
    bool enable_percentiles;     // compute percentiles (more expensive)
  };

  static constexpr uint32_t kDefaultMaxSamples = 10000;
  static constexpr uint32_t kDefaultAggregationWindow = 60;

  // Create monitor with configuration
  static std::optional<PerformanceMonitor> create(const MonitorConfig& config);

  // Record metric sample
  bool recordMetric(const MetricSample& sample);

  // Get aggregated statistics for category
  std::optional<AggregatedStats> getStats(MetricCategory category) const;

  // Get all statistics
  std::vector<AggregatedStats> getAllStats() const;

  // Reset all metrics
  void reset();

  // Get total sample count
  uint64_t getTotalSampleCount() const { return total_samples_; }

  // Get sample count for category
  uint64_t getCategorySampleCount(MetricCategory category) const;

  // Constructor (public for std::optional)
  PerformanceMonitor(const MonitorConfig& config)
      : config_(config), total_samples_(0) {}

 private:

  MonitorConfig config_;
  std::vector<MetricSample> samples_;
  uint64_t total_samples_;

  // Helper: validate configuration
  static bool validateConfig(const MonitorConfig& config);

  // Helper: validate metric sample
  static bool validateSample(const MetricSample& sample);

  // Helper: compute percentile
  static uint64_t computePercentile(const std::vector<uint64_t>& sorted_values,
                                    uint32_t percentile);

  // Helper: get samples for category
  std::vector<MetricSample> getSamplesForCategory(
      MetricCategory category) const;

  // No copy
  PerformanceMonitor(const PerformanceMonitor&) = delete;
  PerformanceMonitor& operator=(const PerformanceMonitor&) = delete;
};

}  // namespace xovm::material

#endif  // XOVM_MATERIAL_PERFORMANCE_MONITOR_H_
