// 简化测试运行器 - 只测试核心模块
#include <iostream>
#include <vector>
#include <string>

#include "runtime/cloud_material/chaff_scheduler_optimized.h"
#include "runtime/cloud_material/performance_monitor.h"

using namespace xovm::material;

struct TestResult {
    std::string name;
    bool passed;
};

std::vector<TestResult> results;

void runTest(const std::string& name, bool (*test_fn)()) {
    std::cout << "[运行] " << name << "..." << std::endl;
    bool passed = test_fn();
    results.push_back({name, passed});
    if (passed) {
        std::cout << "  ✓ 通过" << std::endl;
    } else {
        std::cout << "  ✗ 失败" << std::endl;
    }
}

// 测试1: ChaffScheduler基础功能
bool test_chaff_basic() {
    ChaffSchedulerOptimized::WindowConfig config;
    config.total_windows = 100;
    config.chaff_percentage = 30;
    config.cache_line_size = 64;
    config.max_precomputed_size = 10000;
    
    auto scheduler = ChaffSchedulerOptimized::create(config);
    if (!scheduler.has_value()) return false;
    
    int count = 0;
    for (int i = 0; i < 100; i++) {
        auto window = scheduler->nextWindow();
        if (window.has_value()) count++;
    }
    
    return count == 70;  // 70个真实窗口
}

// 测试2: ChaffScheduler无Chaff
bool test_chaff_no_chaff() {
    ChaffSchedulerOptimized::WindowConfig config;
    config.total_windows = 50;
    config.chaff_percentage = 0;
    config.cache_line_size = 64;
    config.max_precomputed_size = 10000;
    
    auto scheduler = ChaffSchedulerOptimized::create(config);
    if (!scheduler.has_value()) return false;
    
    int count = 0;
    for (int i = 0; i < 60; i++) {
        auto window = scheduler->nextWindow();
        if (window.has_value()) count++;
    }
    
    return count == 50;
}

// 测试3: ChaffScheduler重置
bool test_chaff_reset() {
    ChaffSchedulerOptimized::WindowConfig config;
    config.total_windows = 20;
    config.chaff_percentage = 50;
    config.cache_line_size = 64;
    config.max_precomputed_size = 10000;
    
    auto scheduler = ChaffSchedulerOptimized::create(config);
    if (!scheduler.has_value()) return false;
    
    // 第一次遍历
    int count1 = 0;
    for (int i = 0; i < 30; i++) {
        auto window = scheduler->nextWindow();
        if (window.has_value()) count1++;
    }
    
    scheduler->reset();
    
    // 第二次遍历应该相同
    int count2 = 0;
    for (int i = 0; i < 30; i++) {
        auto window = scheduler->nextWindow();
        if (window.has_value()) count2++;
    }
    
    return count1 == count2 && count1 == 10;
}

// 测试4: PerformanceMonitor基础统计
bool test_monitor_basic() {
    PerformanceMonitor::MonitorConfig config;
    config.max_samples = 100;
    config.aggregation_window = 60;
    config.enable_percentiles = true;
    
    auto monitor = PerformanceMonitor::create(config);
    if (!monitor.has_value()) return false;
    
    for (int i = 0; i < 10; i++) {
        PerformanceMonitor::MetricSample sample;
        sample.category = PerformanceMonitor::MetricCategory::WindowExecution;
        sample.timestamp_us = 1000000 + i * 1000;
        sample.duration_us = 100 + i * 10;
        sample.operation_id = i + 1;
        sample.success = true;
        
        if (!monitor->recordMetric(sample)) return false;
    }
    
    auto stats = monitor->getStats(PerformanceMonitor::MetricCategory::WindowExecution);
    return stats.has_value() && stats->total_operations == 10;
}

// 测试5: PerformanceMonitor成功率
bool test_monitor_success_rate() {
    PerformanceMonitor::MonitorConfig config;
    config.max_samples = 100;
    config.aggregation_window = 60;
    config.enable_percentiles = true;
    
    auto monitor = PerformanceMonitor::create(config);
    if (!monitor.has_value()) return false;
    
    // 记录20个样本，80%成功率
    for (int i = 0; i < 20; i++) {
        PerformanceMonitor::MetricSample sample;
        sample.category = PerformanceMonitor::MetricCategory::CloudCommunication;
        sample.timestamp_us = 1000000 + i * 1000;
        sample.duration_us = 50;
        sample.operation_id = i + 1;
        sample.success = (i % 5 != 0);  // 每5个中有1个失败
        
        if (!monitor->recordMetric(sample)) return false;
    }
    
    auto stats = monitor->getStats(PerformanceMonitor::MetricCategory::CloudCommunication);
    return stats.has_value() && 
           stats->successful_operations == 16 && 
           stats->failed_operations == 4;
}

// 测试6: PerformanceMonitor百分位数
bool test_monitor_percentiles() {
    PerformanceMonitor::MonitorConfig config;
    config.max_samples = 1000;
    config.aggregation_window = 60;
    config.enable_percentiles = true;
    
    auto monitor = PerformanceMonitor::create(config);
    if (!monitor.has_value()) return false;
    
    // 记录100个样本，延迟0-99μs
    for (int i = 0; i < 100; i++) {
        PerformanceMonitor::MetricSample sample;
        sample.category = PerformanceMonitor::MetricCategory::ChaffScheduling;
        sample.timestamp_us = 1000000 + i * 1000;
        sample.duration_us = i;
        sample.operation_id = i + 1;
        sample.success = true;
        
        if (!monitor->recordMetric(sample)) return false;
    }
    
    auto stats = monitor->getStats(PerformanceMonitor::MetricCategory::ChaffScheduling);
    if (!stats.has_value()) return false;
    
    // 验证P50大约在中间
    return stats->p50_duration_us >= 45 && stats->p50_duration_us <= 55;
}

// 测试7: PerformanceMonitor多类别
bool test_monitor_categories() {
    PerformanceMonitor::MonitorConfig config;
    config.max_samples = 100;
    config.aggregation_window = 60;
    config.enable_percentiles = true;
    
    auto monitor = PerformanceMonitor::create(config);
    if (!monitor.has_value()) return false;
    
    // 记录多个类别的样本
    for (int i = 0; i < 5; i++) {
        PerformanceMonitor::MetricSample sample;
        sample.category = PerformanceMonitor::MetricCategory::WindowExecution;
        sample.timestamp_us = 1000000 + i * 1000;
        sample.duration_us = 100;
        sample.operation_id = i + 1;
        sample.success = true;
        monitor->recordMetric(sample);
    }
    
    for (int i = 0; i < 3; i++) {
        PerformanceMonitor::MetricSample sample;
        sample.category = PerformanceMonitor::MetricCategory::ChaffScheduling;
        sample.timestamp_us = 1000000 + i * 1000;
        sample.duration_us = 50;
        sample.operation_id = i + 1;
        sample.success = true;
        monitor->recordMetric(sample);
    }
    
    auto stats1 = monitor->getStats(PerformanceMonitor::MetricCategory::WindowExecution);
    auto stats2 = monitor->getStats(PerformanceMonitor::MetricCategory::ChaffScheduling);
    
    return stats1.has_value() && stats1->total_operations == 5 &&
           stats2.has_value() && stats2->total_operations == 3;
}

int main() {
    std::cout << "=== 运行时模块测试套件 ===" << std::endl;
    std::cout << "测试环境: Termux (本地开发)" << std::endl;
    std::cout << "测试范围: ChaffScheduler + PerformanceMonitor" << std::endl;
    std::cout << std::endl;
    
    // 运行所有测试
    runTest("ChaffScheduler基础功能", test_chaff_basic);
    runTest("ChaffScheduler无Chaff模式", test_chaff_no_chaff);
    runTest("ChaffScheduler重置功能", test_chaff_reset);
    runTest("PerformanceMonitor基础统计", test_monitor_basic);
    runTest("PerformanceMonitor成功率", test_monitor_success_rate);
    runTest("PerformanceMonitor百分位数", test_monitor_percentiles);
    runTest("PerformanceMonitor多类别", test_monitor_categories);
    
    // 统计结果
    std::cout << "\n=== 测试结果 ===" << std::endl;
    int passed = 0;
    int failed = 0;
    
    for (const auto& result : results) {
        if (result.passed) {
            passed++;
            std::cout << "✓ " << result.name << std::endl;
        } else {
            failed++;
            std::cout << "✗ " << result.name << std::endl;
        }
    }
    
    std::cout << "\n通过: " << passed << "/" << results.size() << std::endl;
    std::cout << "失败: " << failed << "/" << results.size() << std::endl;
    
    if (failed == 0) {
        std::cout << "\n🎉 所有测试通过！核心功能已验证" << std::endl;
        std::cout << "\n已验证模块：" << std::endl;
        std::cout << "  ✓ ChaffSchedulerOptimized - O(1)调度器" << std::endl;
        std::cout << "  ✓ PerformanceMonitor - 性能监控系统" << std::endl;
        return 0;
    } else {
        std::cout << "\n⚠️  部分测试失败" << std::endl;
        return 1;
    }
}
