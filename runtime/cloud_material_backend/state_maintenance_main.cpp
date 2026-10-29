#include "config.h"
#include "process_lock.h"
#include "runtime_providers.h"
#include "state_maintenance.h"

#include <cstdio>
#include <filesystem>

namespace xovm::cloud_material {
namespace {

int fail(const BackendError &error) {
    std::fprintf(stderr, "state maintenance failed: %s\n", error.code.c_str());
    return 1;
}

int run() {
    auto configured = StateMaintenanceConfig::fromEnvironment();
    if (const auto *error = std::get_if<BackendError>(&configured))
        return fail(*error);
    const auto config =
        std::get<StateMaintenanceConfig>(std::move(configured));

    auto locked = ProcessLock::acquireExistingPrivate(
        std::filesystem::path(config.state_dir));
    if (const auto *error = std::get_if<BackendError>(&locked))
        return fail(*error);
    auto lock = std::get<ProcessLock>(std::move(locked));

    RuntimeProviderFactory::registerLinkedProviders();
    auto resolved = RuntimeProviderFactory::resolveTrustedTime(config);
    if (const auto *error = std::get_if<BackendError>(&resolved))
        return fail(*error);
    auto maintained = runOfflineStateMaintenance(
        std::filesystem::path(config.state_dir),
        std::get<TrustedNow>(std::move(resolved)), lock);
    if (const auto *error = std::get_if<BackendError>(&maintained))
        return fail(*error);
    const auto &result = std::get<StateMaintenanceResult>(maintained);
    std::printf(
        "records_retired=%zu response_bytes_reclaimed=%zu sequence=%llu more_work=%s\n",
        result.records_retired, result.response_bytes_reclaimed,
        static_cast<unsigned long long>(result.sequence),
        result.more_work ? "true" : "false");
    return 0;
}

} // namespace
} // namespace xovm::cloud_material

int main(int argc, char **argv) {
    if (argc != 2 || std::string_view(argv[1]) != "reclaim-expired") {
        std::fputs("usage: xovm-cloud-material-state-maintenance reclaim-expired\n",
                   stderr);
        return 2;
    }
    try {
        return xovm::cloud_material::run();
    } catch (...) {
        std::fputs("state maintenance failed: maintenance_failed\n", stderr);
        return 1;
    }
}
