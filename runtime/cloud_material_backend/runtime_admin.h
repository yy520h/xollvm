#ifndef XOVM_CLOUD_MATERIAL_BACKEND_RUNTIME_ADMIN_H
#define XOVM_CLOUD_MATERIAL_BACKEND_RUNTIME_ADMIN_H

#include "admin_repository.h"
#include "auth_policy.h"
#include "build_snapshot.h"

#include <functional>

namespace xovm::cloud_material {

class RuntimeAdminHandlers {
public:
    using Authorize = std::function<std::variant<AdminPrincipal, BackendError>(
        std::string_view, std::string_view, std::string_view, const std::string &)>;
    using Evidence = std::function<std::variant<std::vector<std::byte>, BackendError>(
        const std::string &, const std::string &)>;
    using ConfigurePolicy = std::function<bool(const BuildSnapshot &, AnonymousPolicy &, std::string &)>;

    RuntimeAdminHandlers(SqliteBuildRepository &repository, SnapshotManager &snapshots,
                         ValidationContext validation, Authorize authorize,
                         Evidence evidence, ConfigurePolicy configurePolicy,
                         AnonymousPolicy &policy);

    std::variant<std::vector<std::byte>, BackendError> handle(
        std::string_view path, std::span<const std::byte> body,
        const std::string &credential);

private:
    SqliteBuildRepository &repository_;
    SnapshotManager &snapshots_;
    ValidationContext validation_;
    Authorize authorize_;
    Evidence evidence_;
    ConfigurePolicy configure_policy_;
    AnonymousPolicy &policy_;
};

} // namespace xovm::cloud_material

#endif
