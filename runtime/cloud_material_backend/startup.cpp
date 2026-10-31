#include "startup.h"

namespace xovm::cloud_material {

StartupCoordinator::StartupCoordinator(StartupStages stages)
    : stages_(std::move(stages)) {}

std::variant<std::monostate, BackendError> StartupCoordinator::runStage(
    const char *name, const StartupStage &stage) {
    if (!stage) return BackendError{std::string("startup_missing_") + name};
    try {
        return stage();
    } catch (...) {
        return BackendError{std::string("startup_stage_failed_") + name};
    }
}

std::variant<std::monostate, BackendError> StartupCoordinator::start() {
    std::lock_guard lock(mutex_);
    if (started_) return BackendError{"startup_already_started"};
    started_ = true;
    ready_ = false;
    const std::pair<const char *, const StartupStage *> stages[] = {
        {"config", &stages_.load_config},
        {"lock", &stages_.acquire_lock},
        {"database", &stages_.check_database},
        {"recovery", &stages_.recover_state},
        {"snapshot", &stages_.validate_snapshot},
        {"providers", &stages_.check_providers},
        {"listener", &stages_.start_listener},
    };
    for (const auto &[name, stage] : stages) {
        auto result = runStage(name, *stage);
        if (std::holds_alternative<BackendError>(result)) return result;
    }
    ready_ = true;
    return std::monostate{};
}

bool StartupCoordinator::ready() const {
    std::lock_guard lock(mutex_);
    return ready_;
}

} // namespace xovm::cloud_material
