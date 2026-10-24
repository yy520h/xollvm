#ifndef XOVM_CLOUD_MATERIAL_BACKEND_STARTUP_H
#define XOVM_CLOUD_MATERIAL_BACKEND_STARTUP_H

#include "canonical_json.h"

#include <functional>
#include <mutex>
#include <variant>

namespace xovm::cloud_material {

using StartupStage = std::function<std::variant<std::monostate, BackendError>()>;

struct StartupStages {
    StartupStage load_config;
    StartupStage acquire_lock;
    StartupStage check_database;
    StartupStage recover_state;
    StartupStage validate_snapshot;
    StartupStage check_providers;
    StartupStage start_listener;
};

class StartupCoordinator {
public:
    explicit StartupCoordinator(StartupStages stages);
    std::variant<std::monostate, BackendError> start();
    bool ready() const;

private:
    std::variant<std::monostate, BackendError> runStage(
        const char *name, const StartupStage &stage);

    StartupStages stages_;
    mutable std::mutex mutex_;
    bool started_ = false;
    bool ready_ = false;
};

} // namespace xovm::cloud_material

#endif
