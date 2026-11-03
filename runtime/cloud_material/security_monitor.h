// ============================================================================
// security_monitor.h - 安全监控和反调试
//
// 功能:
// 1. 反调试检测
// 2. 完整性检查
// 3. 运行时环境验证
// 4. 异常行为检测
// ============================================================================

#ifndef XOVM_MATERIAL_SECURITY_MONITOR_H
#define XOVM_MATERIAL_SECURITY_MONITOR_H

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <chrono>

namespace xovm::material {

// ============================================================================
// 安全威胁类型
// ============================================================================

enum class ThreatType {
    DEBUGGER_DETECTED,          // 检测到调试器
    TRACER_DETECTED,            // 检测到ptrace
    MEMORY_TAMPERING,           // 内存篡改
    CODE_INJECTION,             // 代码注入
    EMULATOR_DETECTED,          // 模拟器环境
    ROOT_DETECTED,              // Root权限
    HOOK_DETECTED,              // 函数Hook
    TIMING_ANOMALY,             // 时间异常
    NETWORK_ANOMALY,            // 网络异常
};

// ============================================================================
// 安全事件
// ============================================================================

struct SecurityEvent {
    ThreatType type;
    std::string description;
    uint32_t severity;  // 1-10
    std::chrono::steady_clock::time_point timestamp;
    std::vector<uint8_t> context_data;
};

// ============================================================================
// 反调试检测器
// ============================================================================

class AntiDebugDetector {
public:
    // 检测ptrace
    static bool detect_ptrace();

    // 检测调试器连接
    static bool detect_debugger();

    // 检测TracerPid
    static bool detect_tracer_pid();

    // 检测断点
    static bool detect_breakpoints();

    // 时间攻击检测
    static bool detect_timing_attack();

    // 综合检测
    static bool is_debugged();
};

// ============================================================================
// 完整性检查器
// ============================================================================

class IntegrityChecker {
public:
    struct Config {
        bool check_code_section = true;
        bool check_data_section = true;
        bool check_loaded_libs = true;
        uint32_t check_interval_ms = 5000;
    };

    explicit IntegrityChecker(const Config& config);

    // 初始化基线
    bool initialize_baseline();

    // 检查代码段完整性
    bool check_code_integrity();

    // 检查数据段完整性
    bool check_data_integrity();

    // 检查动态库
    bool check_loaded_libraries();

    // 综合检查
    bool verify_integrity();

private:
    Config config_;
    std::vector<uint8_t> code_baseline_;
    std::vector<uint8_t> data_baseline_;
    std::vector<std::string> libs_baseline_;
};

// ============================================================================
// 环境检测器
// ============================================================================

class EnvironmentDetector {
public:
    // 检测模拟器
    static bool is_emulator();

    // 检测Root
    static bool is_rooted();

    // 检测Xposed/Frida
    static bool detect_hooking_framework();

    // 检测虚拟机
    static bool is_virtual_machine();

    // 检测沙箱
    static bool is_sandbox();

    // 综合环境检测
    static bool is_safe_environment();
};

// ============================================================================
// 运行时行为监控
// ============================================================================

class BehaviorMonitor {
public:
    struct Config {
        bool monitor_memory = true;
        bool monitor_timing = true;
        bool monitor_network = true;
        uint32_t sample_interval_ms = 1000;
    };

    explicit BehaviorMonitor(const Config& config);

    // 开始监控
    void start();

    // 停止监控
    void stop();

    // 记录窗口执行时间
    void record_window_execution(uint32_t window_id, uint64_t duration_us);

    // 记录网络请求
    void record_network_request(uint32_t window_id, uint64_t latency_ms);

    // 检测异常
    bool detect_anomaly();

    // 获取异常报告
    std::vector<SecurityEvent> get_anomalies() const;

private:
    Config config_;
    bool running_;

    // 基线数据
    struct ExecutionBaseline {
        uint64_t avg_duration_us;
        uint64_t std_dev_us;
    };
    std::unordered_map<uint32_t, ExecutionBaseline> execution_baseline_;

    // 异常记录
    std::vector<SecurityEvent> anomalies_;
};

// ============================================================================
// 安全监控器（主类）
// ============================================================================

class SecurityMonitor {
public:
    struct Config {
        IntegrityChecker::Config integrity_config;
        BehaviorMonitor::Config behavior_config;

        bool enable_anti_debug = true;
        bool enable_integrity_check = true;
        bool enable_environment_check = true;
        bool enable_behavior_monitor = true;

        // 响应策略
        bool fail_on_threat = true;          // 检测到威胁时失败
        bool log_threats = true;             // 记录威胁
        bool obfuscate_execution = true;     // 混淆执行
    };

    using ThreatCallback = std::function<void(const SecurityEvent&)>;

    explicit SecurityMonitor(const Config& config);
    ~SecurityMonitor();

    // 初始化
    bool initialize();

    // 开始监控
    void start();

    // 停止监控
    void stop();

    // 执行安全检查
    bool perform_security_check();

    // 注册威胁回调
    void register_threat_callback(ThreatCallback callback);

    // 获取威胁事件
    std::vector<SecurityEvent> get_threats() const;

    // 清除威胁记录
    void clear_threats();

    // 获取安全状态
    bool is_secure() const;

private:
    Config config_;
    bool initialized_;
    bool running_;

    // 子模块
    IntegrityChecker integrity_checker_;
    BehaviorMonitor behavior_monitor_;

    // 威胁管理
    std::vector<SecurityEvent> threats_;
    ThreatCallback threat_callback_;

    // 内部方法
    void handle_threat(const SecurityEvent& event);
    void check_thread_routine();
};

// ============================================================================
// 辅助宏 - 反调试断言
// ============================================================================

#define XOVM_SECURITY_CHECK() \
    do { \
        if (xovm::material::AntiDebugDetector::is_debugged()) { \
            __builtin_trap(); \
        } \
    } while(0)

#define XOVM_TIMING_CHECK_BEGIN() \
    auto __timing_start = std::chrono::steady_clock::now()

#define XOVM_TIMING_CHECK_END(threshold_us) \
    do { \
        auto __timing_end = std::chrono::steady_clock::now(); \
        auto __duration = std::chrono::duration_cast<std::chrono::microseconds>( \
            __timing_end - __timing_start).count(); \
        if (__duration < (threshold_us)) { \
            __builtin_trap(); \
        } \
    } while(0)

} // namespace xovm::material

#endif // XOVM_MATERIAL_SECURITY_MONITOR_H
