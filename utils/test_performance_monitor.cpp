#include <cassert>
#include <cstdint>

#include "runtime/cloud_material/performance_monitor.h"

namespace xovm::material::test {

bool testPerformanceMonitorCreation() {
  xovm::material::PerformanceMonitor::MonitorConfig config;
  config.max_samples = 1000;
  config.aggregation_window = 60;
  config.enable_percentiles = true;

  auto monitor = xovm::material::PerformanceMonitor::create(config);
  assert(monitor.has_value() && "Failed to create monitor");
  assert(monitor->getTotalSampleCount() == 0);

  return true;
}

bool testPerformanceMonitorValidation() {
  xovm::material::PerformanceMonitor::MonitorConfig config;
  
  // Invalid: zero max_samples
  config.max_samples = 0;
  config.aggregation_window = 60;
  config.enable_percentiles = true;
  
  auto monitor = xovm::material::PerformanceMonitor::create(config);
  assert(!monitor.has_value() && "Should reject zero max_samples");
  
  // Invalid: max_samples too large
  config.max_samples = 2000000;
  monitor = xovm::material::PerformanceMonitor::create(config);
  assert(!monitor.has_value() && "Should reject max_samples > 1M");
  
  // Invalid: zero aggregation_window
  config.max_samples = 1000;
  config.aggregation_window = 0;
  monitor = xovm::material::PerformanceMonitor::create(config);
  assert(!monitor.has_value() && "Should reject zero aggregation_window");
  
  // Invalid: aggregation_window too large
  config.aggregation_window = 3601;
  monitor = xovm::material::PerformanceMonitor::create(config);
  assert(!monitor.has_value() && "Should reject aggregation_window > 3600");
  
  return true;
}

bool testMetricRecording() {
  xovm::material::PerformanceMonitor::MonitorConfig config;
  config.max_samples = 100;
  config.aggregation_window = 60;
  config.enable_percentiles = true;
  
  auto monitor = xovm::material::PerformanceMonitor::create(config);
  assert(monitor.has_value());
  
  xovm::material::PerformanceMonitor::MetricSample sample;
  sample.category = xovm::material::PerformanceMonitor::MetricCategory::WindowExecution;
  sample.timestamp_us = 1000000;
  sample.duration_us = 500;
  sample.operation_id = 1;
  sample.success = true;
  
  assert(monitor->recordMetric(sample));
  assert(monitor->getTotalSampleCount() == 1);
  
  // Record another sample
  sample.timestamp_us = 1001000;
  sample.duration_us = 600;
  sample.operation_id = 2;
  assert(monitor->recordMetric(sample));
  assert(monitor->getTotalSampleCount() == 2);
  
  return true;
}

bool testMetricValidation() {
  xovm::material::PerformanceMonitor::MonitorConfig config;
  config.max_samples = 100;
  config.aggregation_window = 60;
  config.enable_percentiles = true;
  
  auto monitor = xovm::material::PerformanceMonitor::create(config);
  assert(monitor.has_value());
  
  xovm::material::PerformanceMonitor::MetricSample sample;
  sample.category = xovm::material::PerformanceMonitor::MetricCategory::WindowExecution;
  sample.timestamp_us = 0;  // invalid
  sample.duration_us = 500;
  sample.operation_id = 1;
  sample.success = true;
  
  assert(!monitor->recordMetric(sample) && "Should reject zero timestamp");
  
  sample.timestamp_us = 1000000;
  sample.duration_us = 0;  // invalid
  assert(!monitor->recordMetric(sample) && "Should reject zero duration");
  
  return true;
}

bool testAggregatedStats() {
  xovm::material::PerformanceMonitor::MonitorConfig config;
  config.max_samples = 100;
  config.aggregation_window = 60;
  config.enable_percentiles = true;
  
  auto monitor = xovm::material::PerformanceMonitor::create(config);
  assert(monitor.has_value());
  
  // Record multiple samples
  for (uint32_t i = 1; i <= 10; ++i) {
    xovm::material::PerformanceMonitor::MetricSample sample;
    sample.category = xovm::material::PerformanceMonitor::MetricCategory::WindowExecution;
    sample.timestamp_us = 1000000 + i * 1000;
    sample.duration_us = i * 100;
    sample.operation_id = i;
    sample.success = (i % 2 == 0);
    monitor->recordMetric(sample);
  }
  
  auto stats = monitor->getStats(
      xovm::material::PerformanceMonitor::MetricCategory::WindowExecution);
  assert(stats.has_value());
  assert(stats->total_operations == 10);
  assert(stats->successful_operations == 5);
  assert(stats->failed_operations == 5);
  assert(stats->min_duration_us == 100);
  assert(stats->max_duration_us == 1000);
  assert(stats->avg_duration_us == 550);
  
  return true;
}

bool testCategoryFiltering() {
  xovm::material::PerformanceMonitor::MonitorConfig config;
  config.max_samples = 100;
  config.aggregation_window = 60;
  config.enable_percentiles = true;
  
  auto monitor = xovm::material::PerformanceMonitor::create(config);
  assert(monitor.has_value());
  
  // Record samples for different categories
  xovm::material::PerformanceMonitor::MetricSample sample1;
  sample1.category = xovm::material::PerformanceMonitor::MetricCategory::WindowExecution;
  sample1.timestamp_us = 1000000;
  sample1.duration_us = 500;
  sample1.operation_id = 1;
  sample1.success = true;
  monitor->recordMetric(sample1);
  
  xovm::material::PerformanceMonitor::MetricSample sample2;
  sample2.category = xovm::material::PerformanceMonitor::MetricCategory::ChaffScheduling;
  sample2.timestamp_us = 1001000;
  sample2.duration_us = 300;
  sample2.operation_id = 2;
  sample2.success = true;
  monitor->recordMetric(sample2);
  
  assert(monitor->getCategorySampleCount(
      xovm::material::PerformanceMonitor::MetricCategory::WindowExecution) == 1);
  assert(monitor->getCategorySampleCount(
      xovm::material::PerformanceMonitor::MetricCategory::ChaffScheduling) == 1);
  assert(monitor->getCategorySampleCount(
      xovm::material::PerformanceMonitor::MetricCategory::GuardianVerification) == 0);
  
  return true;
}

bool testMaxSamplesLimit() {
  xovm::material::PerformanceMonitor::MonitorConfig config;
  config.max_samples = 5;  // small limit for testing
  config.aggregation_window = 60;
  config.enable_percentiles = true;
  
  auto monitor = xovm::material::PerformanceMonitor::create(config);
  assert(monitor.has_value());
  
  // Record more than max_samples
  for (uint32_t i = 1; i <= 10; ++i) {
    xovm::material::PerformanceMonitor::MetricSample sample;
    sample.category = xovm::material::PerformanceMonitor::MetricCategory::WindowExecution;
    sample.timestamp_us = 1000000 + i * 1000;
    sample.duration_us = i * 100;
    sample.operation_id = i;
    sample.success = true;
    monitor->recordMetric(sample);
  }
  
  // Should only keep last 5 samples
  auto stats = monitor->getStats(
      xovm::material::PerformanceMonitor::MetricCategory::WindowExecution);
  assert(stats.has_value());
  assert(stats->total_operations == 5);
  assert(monitor->getTotalSampleCount() == 10);  // total count still tracks all
  
  return true;
}

bool testReset() {
  xovm::material::PerformanceMonitor::MonitorConfig config;
  config.max_samples = 100;
  config.aggregation_window = 60;
  config.enable_percentiles = true;
  
  auto monitor = xovm::material::PerformanceMonitor::create(config);
  assert(monitor.has_value());
  
  // Record samples
  xovm::material::PerformanceMonitor::MetricSample sample;
  sample.category = xovm::material::PerformanceMonitor::MetricCategory::WindowExecution;
  sample.timestamp_us = 1000000;
  sample.duration_us = 500;
  sample.operation_id = 1;
  sample.success = true;
  monitor->recordMetric(sample);
  
  assert(monitor->getTotalSampleCount() == 1);
  
  // Reset
  monitor->reset();
  assert(monitor->getTotalSampleCount() == 0);
  
  auto stats = monitor->getStats(
      xovm::material::PerformanceMonitor::MetricCategory::WindowExecution);
  assert(!stats.has_value() && "Should have no stats after reset");
  
  return true;
}

}  // namespace xovm::material::test

extern "C" int runPerformanceMonitorTests() {
  using namespace xovm::material::test;
  
  int tests_passed = 0;
  int tests_failed = 0;
  
  if (testPerformanceMonitorCreation()) {
    tests_passed++;
  } else {
    tests_failed++;
  }
  
  if (testPerformanceMonitorValidation()) {
    tests_passed++;
  } else {
    tests_failed++;
  }
  
  if (testMetricRecording()) {
    tests_passed++;
  } else {
    tests_failed++;
  }
  
  if (testMetricValidation()) {
    tests_passed++;
  } else {
    tests_failed++;
  }
  
  if (testAggregatedStats()) {
    tests_passed++;
  } else {
    tests_failed++;
  }
  
  if (testCategoryFiltering()) {
    tests_passed++;
  } else {
    tests_failed++;
  }
  
  if (testMaxSamplesLimit()) {
    tests_passed++;
  } else {
    tests_failed++;
  }
  
  if (testReset()) {
    tests_passed++;
  } else {
    tests_failed++;
  }
  
  return tests_failed == 0 ? 0 : 1;
}
