// 简单的功能测试 - 不需要网络
#include <iostream>
#include "runtime/cloud_material/performance_monitor.h"
#include "runtime/cloud_material/chaff_scheduler_optimized.h"

using namespace xovm::material;

int main() {
    std::cout << "=== 简单功能测试 ===" << std::endl;
    
    // 测试1: ChaffSchedulerOptimized
    std::cout << "\n[测试1] ChaffSchedulerOptimized" << std::endl;
    
    ChaffSchedulerOptimized::WindowConfig sched_config;
    sched_config.total_windows = 100;
    sched_config.chaff_percentage = 30;
    sched_config.cache_line_size = 64;
    sched_config.max_precomputed_size = 10000;
    
    auto scheduler = ChaffSchedulerOptimized::create(sched_config);
    if (!scheduler.has_value()) {
        std::cerr << "✗ 调度器创建失败" << std::endl;
        return 1;
    }
    std::cout << "✓ 调度器创建成功" << std::endl;
    std::cout << "  配置: 总窗口=" << sched_config.total_windows 
              << ", Chaff=" << sched_config.chaff_percentage << "%" << std::endl;
    
    // 选择窗口（跳过chaff）
    std::cout << "  真实窗口序列: ";
    int real_count = 0;
    int chaff_count = 0;
    for (int i = 0; i < 100 && real_count < 10; i++) {
        auto window = scheduler->nextWindow();
        if (window.has_value()) {
            std::cout << *window << " ";
            real_count++;
        } else {
            chaff_count++;
        }
    }
    std::cout << "\n✓ 窗口选择成功 (真实: " << real_count << ", Chaff: " << chaff_count << ")" << std::endl;
    
    // 测试2: PerformanceMonitor
    std::cout << "\n[测试2] PerformanceMonitor" << std::endl;
    
    PerformanceMonitor::MonitorConfig monitor_config;
    monitor_config.max_samples = 1000;
    monitor_config.aggregation_window = 60;
    monitor_config.enable_percentiles = true;
    
    auto monitor = PerformanceMonitor::create(monitor_config);
    if (!monitor.has_value()) {
        std::cerr << "✗ 监控器创建失败" << std::endl;
        return 1;
    }
    std::cout << "✓ 监控器创建成功" << std::endl;
    
    // 记录50个测试样本
    for (int i = 0; i < 50; i++) {
        PerformanceMonitor::MetricSample sample;
        sample.category = PerformanceMonitor::MetricCategory::WindowExecution;
        sample.timestamp_us = 1000000 + i * 1000;
        sample.duration_us = 50 + (i % 20) * 5;  // 50-145μs
        sample.operation_id = i + 1;
        sample.success = (i % 5 != 0);  // 80%成功率
        
        if (!monitor->recordMetric(sample)) {
            std::cerr << "✗ 记录指标失败" << std::endl;
            return 1;
        }
    }
    
    std::cout << "✓ 记录了 " << monitor->getTotalSampleCount() << " 个样本" << std::endl;
    
    // 获取统计信息
    auto stats = monitor->getStats(PerformanceMonitor::MetricCategory::WindowExecution);
    if (!stats.has_value()) {
        std::cerr << "✗ 获取统计失败" << std::endl;
        return 1;
    }
    
    std::cout << "\n统计结果:" << std::endl;
    std::cout << "  总操作: " << stats->total_operations << std::endl;
    std::cout << "  成功: " << stats->successful_operations 
              << " (" << (stats->successful_operations * 100 / stats->total_operations) << "%)" << std::endl;
    std::cout << "  失败: " << stats->failed_operations << std::endl;
    std::cout << "  延迟范围: " << stats->min_duration_us << "-" << stats->max_duration_us << "μs" << std::endl;
    std::cout << "  平均延迟: " << stats->avg_duration_us << "μs" << std::endl;
    std::cout << "  P50: " << stats->p50_duration_us << "μs" << std::endl;
    std::cout << "  P95: " << stats->p95_duration_us << "μs" << std::endl;
    std::cout << "  P99: " << stats->p99_duration_us << "μs" << std::endl;
    
    std::cout << "\n=== 所有测试通过 ✓ ===" << std::endl;
    return 0;
}
