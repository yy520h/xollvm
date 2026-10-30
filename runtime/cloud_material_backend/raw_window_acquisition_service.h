#ifndef XOVM_CLOUD_MATERIAL_BACKEND_RAW_WINDOW_ACQUISITION_SERVICE_H
#define XOVM_CLOUD_MATERIAL_BACKEND_RAW_WINDOW_ACQUISITION_SERVICE_H

#include "auth_policy.h"
#include "build_snapshot.h"
#include "raw_session.h"
#include "session_state.h"
#include "../cloud_material/dynamic_vm_window_provider.h"

#include <array>
#include <cstdint>
#include <functional>
#include <utility>
#include <variant>
#include <vector>

namespace xovm::cloud_material {

class RawWindowAcquisitionService final {
public:
    static constexpr std::uint64_t kMaximumWindowTtlMs = 120000;
    using TrustedNow =
        std::function<std::variant<std::uint64_t, BackendError>()>;
    using MaterialBuilder = std::function<std::variant<
        xovm::material::WindowMaterialProvisionV3, BackendError>(
        const xovm::material::WindowAcquireRequest &)>;

    struct Providers {
        SnapshotManager *snapshots = nullptr;
        AnonymousPolicy *anonymous_policy = nullptr;
        SessionState *sessions = nullptr;
        TrustedNow trusted_now;
        MaterialBuilder build_material;
        std::uint64_t window_ttl_ms = kMaximumWindowTtlMs;
        std::size_t rate_budget = 1;
    };

    explicit RawWindowAcquisitionService(Providers providers)
        : providers_(std::move(providers)) {}

    std::variant<std::vector<std::uint8_t>, BackendError> acquire(
        const AuthenticatedRawContext &context,
        const xovm::material::WindowAcquireRequest &request);

private:
    Providers providers_;
};

} // namespace xovm::cloud_material

#endif
