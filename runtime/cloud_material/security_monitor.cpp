// ============================================================================
// security_monitor.cpp - 安全监控实现
// ============================================================================

#include "security_monitor.h"
#include <fstream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <sys/ptrace.h>
#include <dirent.h>
#include <algorithm>

namespace xovm::material {

// ============================================================================
// AntiDebugDetector 实现
// ============================================================================

bool AntiDebugDetector::detect_ptrace() {
    std::ifstream status("/proc/self/status");
    if (!status.is_open()) return false;

    std::string line;
    while (std::getline(status, line)) {
        if (line.find("TracerPid:") == 0) {
            int tracer_pid;
            std::sscanf(line.c_str(), "TracerPid:\t%d", &tracer_pid);
            return tracer_pid != 0;
        }
    }
    return false;
}

bool AntiDebugDetector::detect_debugger() {
    const char* debuggers[] = {"gdb", "lldb", "strace", "ltrace", "gdbserver"};
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return false;

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        if (entry->d_type != DT_DIR || !isdigit(entry->d_name[0])) continue;

        std::string cmdline_path = std::string("/proc/") + entry->d_name + "/cmdline";
        std::ifstream cmdline(cmdline_path);
        if (!cmdline.is_open()) continue;

        std::string cmd;
        std::getline(cmdline, cmd, '\0');

        for (const char* debugger : debuggers) {
            if (cmd.find(debugger) != std::string::npos) {
                closedir(proc_dir);
                return true;
            }
        }
    }

    closedir(proc_dir);
    return false;
}

bool AntiDebugDetector::detect_tracer_pid() {
    return detect_ptrace();
}

bool AntiDebugDetector::detect_breakpoints() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        return true;
    }
    ptrace(PTRACE_DETACH, 0, 1, 0);
    return false;
}

bool AntiDebugDetector::detect_timing_attack() {
    auto start = std::chrono::high_resolution_clock::now();
    volatile int sum = 0;
    for (int i = 0; i < 1000; i++) {
        sum += i;
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    return duration.count() > 10000;
}

bool AntiDebugDetector::is_debugged() {
    return detect_ptrace() || detect_debugger() || detect_breakpoints();
}

// ============================================================================
// IntegrityChecker 实现
// ============================================================================

IntegrityChecker::IntegrityChecker(const Config& config)
    : config_(config) {
}

bool IntegrityChecker::initialize_baseline() {
    return true;
}

bool IntegrityChecker::check_code_integrity() {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return false;

    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(" r-xp ") != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool IntegrityChecker::check_data_integrity() {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return false;

    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(" rw-p ") != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool IntegrityChecker::check_loaded_libraries() {
    return true;
}

bool IntegrityChecker::verify_integrity() {
    bool result = true;
    if (config_.check_code_section) result = result && check_code_integrity();
    if (config_.check_data_section) result = result && check_data_integrity();
    if (config_.check_loaded_libs) result = result && check_loaded_libraries();
    return result;
}

// ============================================================================
// EnvironmentDetector 实现
// ============================================================================

bool EnvironmentDetector::is_emulator() {
    const char* emulator_files[] = {
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props"
    };

    for (const char* file : emulator_files) {
        if (access(file, F_OK) == 0) return true;
    }

    std::ifstream cpuinfo("/proc/cpuinfo");
    if (cpuinfo.is_open()) {
        std::string line;
        while (std::getline(cpuinfo, line)) {
            if (line.find("goldfish") != std::string::npos ||
                line.find("vbox") != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

bool EnvironmentDetector::is_rooted() {
    const char* root_files[] = {
        "/system/app/Superuser.apk",
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su"
    };

    for (const char* file : root_files) {
        if (access(file, F_OK) == 0) return true;
    }
    return false;
}

bool EnvironmentDetector::detect_hooking_framework() {
    const char* ld_preload = getenv("LD_PRELOAD");
    return (ld_preload && strlen(ld_preload) > 0);
}

bool EnvironmentDetector::is_virtual_machine() {
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (cpuinfo.is_open()) {
        std::string line;
        while (std::getline(cpuinfo, line)) {
            if (line.find("hypervisor") != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

bool EnvironmentDetector::is_sandbox() {
    return access("/.dockerenv", F_OK) == 0;
}

bool EnvironmentDetector::is_safe_environment() {
    return !is_emulator() && !is_rooted() &&
           !detect_hooking_framework() && !is_virtual_machine();
}

// ============================================================================
// BehaviorMonitor 实现
// ============================================================================

BehaviorMonitor::BehaviorMonitor(const Config& config)
    : config_(config), running_(false) {
}

void BehaviorMonitor::start() {
    running_ = true;
}

void BehaviorMonitor::stop() {
    running_ = false;
}

void BehaviorMonitor::record_window_execution(uint32_t window_id, uint64_t duration_us) {
    if (!running_) return;
    auto& baseline = execution_baseline_[window_id];
    baseline.avg_duration_us = (baseline.avg_duration_us + duration_us) / 2;
}

void BehaviorMonitor::record_network_request(uint32_t /*window_id*/, uint64_t /*latency_ms*/) {
}

bool BehaviorMonitor::detect_anomaly() {
    return false;
}

std::vector<SecurityEvent> BehaviorMonitor::get_anomalies() const {
    return anomalies_;
}

// ============================================================================
// SecurityMonitor 实现
// ============================================================================

SecurityMonitor::SecurityMonitor(const Config& config)
    : config_(config),
      initialized_(false),
      running_(false),
      integrity_checker_(config.integrity_config),
      behavior_monitor_(config.behavior_config) {
}

SecurityMonitor::~SecurityMonitor() {
    stop();
}

bool SecurityMonitor::initialize() {
    if (config_.enable_integrity_check) {
        if (!integrity_checker_.initialize_baseline()) {
            return false;
        }
    }
    initialized_ = true;
    return true;
}

void SecurityMonitor::start() {
    if (!initialized_) return;
    running_ = true;
    if (config_.enable_behavior_monitor) {
        behavior_monitor_.start();
    }
}

void SecurityMonitor::stop() {
    running_ = false;
    if (config_.enable_behavior_monitor) {
        behavior_monitor_.stop();
    }
}

bool SecurityMonitor::perform_security_check() {
    if (!running_) return true;

    bool secure = true;

    if (config_.enable_anti_debug && AntiDebugDetector::is_debugged()) {
        SecurityEvent event{ThreatType::DEBUGGER_DETECTED, "Debugger detected", 10,
                           std::chrono::steady_clock::now(), {}};
        handle_threat(event);
        secure = false;
    }

    if (config_.enable_environment_check && !EnvironmentDetector::is_safe_environment()) {
        SecurityEvent event{ThreatType::EMULATOR_DETECTED, "Unsafe environment", 7,
                           std::chrono::steady_clock::now(), {}};
        handle_threat(event);
        secure = false;
    }

    if (config_.enable_integrity_check && !integrity_checker_.verify_integrity()) {
        SecurityEvent event{ThreatType::MEMORY_TAMPERING, "Integrity check failed", 9,
                           std::chrono::steady_clock::now(), {}};
        handle_threat(event);
        secure = false;
    }

    return secure;
}

void SecurityMonitor::register_threat_callback(ThreatCallback callback) {
    threat_callback_ = callback;
}

std::vector<SecurityEvent> SecurityMonitor::get_threats() const {
    return threats_;
}

void SecurityMonitor::clear_threats() {
    threats_.clear();
}

bool SecurityMonitor::is_secure() const {
    return threats_.empty();
}

void SecurityMonitor::handle_threat(const SecurityEvent& event) {
    threats_.push_back(event);
    if (threat_callback_) {
        threat_callback_(event);
    }
}

void SecurityMonitor::check_thread_routine() {
}

} // namespace xovm::material
