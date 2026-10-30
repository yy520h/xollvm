// 本地云提供商客户端Demo - 测试RawSocketCloudProvider
#include <iostream>
#include <vector>

#include "runtime/cloud_material/raw_socket_cloud_provider.h"
#include "runtime/cloud_material/cloud_provider_manager.h"
#include "runtime/cloud_material/performance_monitor.h"

using namespace xovm::material;

int main() {
    std::cout << "=== 云提供商客户端Demo ===" << std::endl;
    
    // 1. 测试RawSocketCloudProvider
    std::cout << "\n[测试1] RawSocketCloudProvider 连接测试" << std::endl;
    
    RawSocketCloudProvider::ConnectionConfig config;
    config.remote_ip = 0x7F000001;  // 127.0.0.1
    config.remote_port = 8080;
    config.connection_timeout = 5000;
    config.max_retries = 3;
    config.buffer_size = 65536;
    
    auto provider = RawSocketCloudProvider::create(config);
    if (!provider.has_value()) {
        std::cerr << "创建云提供商失败（服务端可能未启动）" << std::endl;
        std::cout << "\n提示：请先在另一个终端运行服务端：" << std::endl;
        std::cout << "  cd demos && ./local_server_demo" << std::endl;
        return 1;
    }
    
    std::cout << "✓ 连接成功" << std::endl;
    
    // 2. 发送测试消息
    std::cout << "\n[测试2] 发送测试消息" << std::endl;
    std::vector<uint8_t> test_message = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    if (!provider->sendMessage(test_message)) {
        std::cerr << "发送消息失败" << std::endl;
        return 1;
    }
    
    std::cout << "✓ 消息发送成功" << std::endl;
    
    // 3. 接收回复
    std::cout << "\n[测试3] 接收服务端回复" << std::endl;
    auto response = provider->receiveMessage();
    
    if (!response.has_value()) {
        std::cerr << "接收回复失败" << std::endl;
        return 1;
    }
    
    std::cout << "✓ 收到回复，大小: " << response->size() << " 字节" << std::endl;
    std::cout << "  内容: ";
    for (uint8_t byte : *response) {
        std::cout << std::hex << (int)byte << " ";
    }
    std::cout << std::dec << std::endl;
    
    provider->close();
    
    // 4. 测试CloudProviderManager
    std::cout << "\n[测试4] CloudProviderManager 测试" << std::endl;
    
    std::vector<CloudProviderManager::ProviderRegistration> registrations;
    CloudProviderManager::ProviderRegistration reg;
    reg.provider_id = 1;
    reg.config = config;
    reg.is_primary = true;
    registrations.push_back(reg);
    
    auto manager = CloudProviderManager::create(registrations);
    if (!manager.has_value()) {
        std::cerr << "创建管理器失败" << std::endl;
        return 1;
    }
    
    std::cout << "✓ 管理器创建成功" << std::endl;
    std::cout << "  提供商数量: " << manager->getProviderCount() << std::endl;
    std::cout << "  活跃提供商: " << manager->getActiveProvider().value() << std::endl;
    
    // 5. 测试PerformanceMonitor
    std::cout << "\n[测试5] PerformanceMonitor 测试" << std::endl;
    
    PerformanceMonitor::MonitorConfig monitor_config;
    monitor_config.max_samples = 1000;
    monitor_config.aggregation_window = 60;
    monitor_config.enable_percentiles = true;
    
    auto monitor = PerformanceMonitor::create(monitor_config);
    if (!monitor.has_value()) {
        std::cerr << "创建监控器失败" << std::endl;
        return 1;
    }
    
    std::cout << "✓ 监控器创建成功" << std::endl;
    
    // 记录一些测试指标
    for (int i = 0; i < 10; i++) {
        PerformanceMonitor::MetricSample sample;
        sample.category = PerformanceMonitor::MetricCategory::CloudCommunication;
        sample.timestamp_us = 1000000 + i * 1000;
        sample.duration_us = 100 + i * 10;
        sample.operation_id = i + 1;
        sample.success = (i % 3 != 0);  // 模拟一些失败
        monitor->recordMetric(sample);
    }
    
    std::cout << "  记录样本数: " << monitor->getTotalSampleCount() << std::endl;
    
    auto stats = monitor->getStats(PerformanceMonitor::MetricCategory::CloudCommunication);
    if (stats.has_value()) {
        std::cout << "  总操作数: " << stats->total_operations << std::endl;
        std::cout << "  成功: " << stats->successful_operations 
                  << ", 失败: " << stats->failed_operations << std::endl;
        std::cout << "  最小延迟: " << stats->min_duration_us << "μs" << std::endl;
        std::cout << "  最大延迟: " << stats->max_duration_us << "μs" << std::endl;
        std::cout << "  平均延迟: " << stats->avg_duration_us << "μs" << std::endl;
        std::cout << "  P50延迟: " << stats->p50_duration_us << "μs" << std::endl;
        std::cout << "  P95延迟: " << stats->p95_duration_us << "μs" << std::endl;
        std::cout << "  P99延迟: " << stats->p99_duration_us << "μs" << std::endl;
    }
    
    std::cout << "\n=== 所有测试完成 ===" << std::endl;
    std::cout << "✓ RawSocketCloudProvider: 通过" << std::endl;
    std::cout << "✓ CloudProviderManager: 通过" << std::endl;
    std::cout << "✓ PerformanceMonitor: 通过" << std::endl;
    
    return 0;
}
