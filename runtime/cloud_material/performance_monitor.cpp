#include "runtime/cloud_material/performance_monitor.h"

#include <algorithm>
#include <cstring>

namespace xovm::material {

bool PerformanceMonitor::validateConfig(const MonitorConfig& config) {
  if (config.max_samples == 0 || config.max_samples > 1000000) {
    return false;
  }
  if (config.aggregation_window == 0 || config.aggregation_window > 3600) {
    return false;
  }
  return true;
}

bool PerformanceMonitor::validateSample(const MetricSample& sample) {
  if (sample.timestamp_us == 0) {
    return false;
  }
  if (sample.duration_us == 0) {
    return false;
  }
  return true;
}

uint64_t PerformanceMonitor::computePercentile(
    const std::vector<uint64_t>& sorted_values, uint32_t percentile) {
  if (sorted_values.empty() || percentile > 100) {
    return 0;
  }

  size_t index = (sorted_values.size() * percentile) / 100;
  if (index >= sorted_values.size()) {
    index = sorted_values.size() - 1;
  }

  return sorted_values[index];
}

std::vector<PerformanceMonitor::MetricSample>
PerformanceMonitor::getSamplesForCategory(MetricCategory category) const {
  std::vector<MetricSample> category_samples;
  for (const auto& sample : samples_) {
    if (sample.category == category) {
      category_samples.push_back(sample);
    }
  }
  return category_samples;
}

std::optional<PerformanceMonitor> PerformanceMonitor::create(
    const MonitorConfig& config) {
  if (!validateConfig(config)) {
    return std::nullopt;
  }

  return std::optional<PerformanceMonitor>(std::in_place, config);
}

bool PerformanceMonitor::recordMetric(const MetricSample& sample) {
  if (!validateSample(sample)) {
    return false;
  }

  // Enforce max samples limit
  if (samples_.size() >= config_.max_samples) {
    // Remove oldest sample
    samples_.erase(samples_.begin());
  }

  samples_.push_back(sample);
  total_samples_++;

  return true;
}

std::optional<PerformanceMonitor::AggregatedStats>
PerformanceMonitor::getStats(MetricCategory category) const {
  auto category_samples = getSamplesForCategory(category);
  if (category_samples.empty()) {
    return std::nullopt;
  }

  AggregatedStats stats;
  stats.category = category;
  stats.total_operations = category_samples.size();
  stats.successful_operations = 0;
  stats.failed_operations = 0;
  stats.min_duration_us = UINT64_MAX;
  stats.max_duration_us = 0;
  uint64_t total_duration = 0;

  std::vector<uint64_t> durations;
  durations.reserve(category_samples.size());

  for (const auto& sample : category_samples) {
    if (sample.success) {
      stats.successful_operations++;
    } else {
      stats.failed_operations++;
    }

    durations.push_back(sample.duration_us);
    total_duration += sample.duration_us;

    if (sample.duration_us < stats.min_duration_us) {
      stats.min_duration_us = sample.duration_us;
    }
    if (sample.duration_us > stats.max_duration_us) {
      stats.max_duration_us = sample.duration_us;
    }
  }

  stats.avg_duration_us = total_duration / category_samples.size();

  if (config_.enable_percentiles) {
    std::sort(durations.begin(), durations.end());
    stats.p50_duration_us = computePercentile(durations, 50);
    stats.p95_duration_us = computePercentile(durations, 95);
    stats.p99_duration_us = computePercentile(durations, 99);
  } else {
    stats.p50_duration_us = 0;
    stats.p95_duration_us = 0;
    stats.p99_duration_us = 0;
  }

  return stats;
}

std::vector<PerformanceMonitor::AggregatedStats>
PerformanceMonitor::getAllStats() const {
  std::vector<AggregatedStats> all_stats;

  // Iterate through all categories
  for (int i = 0; i <= 4; ++i) {
    auto category = static_cast<MetricCategory>(i);
    auto stats = getStats(category);
    if (stats.has_value()) {
      all_stats.push_back(stats.value());
    }
  }

  return all_stats;
}

void PerformanceMonitor::reset() {
  samples_.clear();
  total_samples_ = 0;
}

uint64_t PerformanceMonitor::getCategorySampleCount(
    MetricCategory category) const {
  uint64_t count = 0;
  for (const auto& sample : samples_) {
    if (sample.category == category) {
      count++;
    }
  }
  return count;
}

}  // namespace xovm::material
