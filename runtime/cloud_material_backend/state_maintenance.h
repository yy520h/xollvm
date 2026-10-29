#ifndef XOVM_CLOUD_MATERIAL_BACKEND_STATE_MAINTENANCE_H
#define XOVM_CLOUD_MATERIAL_BACKEND_STATE_MAINTENANCE_H

#include "checkpoint.h"
#include "process_lock.h"
#include "session_state.h"

#include <filesystem>
#include <functional>

namespace xovm::cloud_material {

using TrustedNow =
    std::function<std::variant<std::uint64_t, BackendError>()>;

struct StateMaintenanceResult {
    std::size_t records_retired = 0;
    std::size_t response_bytes_reclaimed = 0;
    std::uint64_t sequence = 0;
    bool more_work = false;
    bool operator==(const StateMaintenanceResult &) const = default;
};

using StateMaintenanceOutcome =
    std::variant<StateMaintenanceResult, BackendError>;

StateMaintenanceOutcome runOfflineStateMaintenance(
    const std::filesystem::path &stateDir,
    const TrustedNow &trustedNow,
    const ProcessLock &lock);

} // namespace xovm::cloud_material

#endif
