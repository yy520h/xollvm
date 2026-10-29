#ifndef XOVM_CLOUD_MATERIAL_BACKEND_RUNTIME_PROVIDERS_H
#define XOVM_CLOUD_MATERIAL_BACKEND_RUNTIME_PROVIDERS_H

#include "admin_repository.h"
#include "cloud_api.h"
#include "config.h"
#include "protocol_service.h"

#include <array>
#include <functional>
#include <variant>

namespace xovm::cloud_material {

enum class ProviderRole {
    trusted_time,
    signing_key,
    anonymous_policy,
    trust_root,
};

struct RuntimeProviderBundle {
    // Builds only the fixed-size secret material for an already authenticated
    // public request. Grant metadata, identity, time, state, and encryption keys
    // remain the acquisition service's responsibility. The caller must scrub the
    // returned material immediately after copying/encrypting it into a grant.
    using BuildWindowMaterial = std::function<std::variant<
        xovm::material::WindowMaterial, BackendError>(
        const xovm::material::WindowAcquireRequest &)>;

    std::function<std::variant<std::uint64_t, BackendError>()> trusted_now;
    ProtocolService::RandomBytes random_bytes;
    SignEd25519 sign;
    SigningMetadata signing;
    std::function<bool(const ImportRecord &, std::string &)> validate_pair;
    std::function<bool(const std::string &, const std::string &,
                       std::span<const std::byte>, std::string &)> validate_final_artifact;
    std::function<std::variant<Bytes, BackendError>(const std::string &, const std::string &)> artifact_evidence;
    std::function<std::variant<AdminPrincipal, BackendError>(
        std::string_view, std::string_view, std::string_view, const std::string &)> authorize_admin;
    ProtocolService::AuthorizeControl authorize_control;
    ProtocolService::Issue issue;
    ProtocolService::BuildPayload build_payload;
    std::function<bool(const BuildSnapshot &, AnonymousPolicy &, std::string &)> configure_policy;
    std::function<std::variant<Bytes, BackendError>(std::string_view)> trust_handler;
    CloudApiProviders raw_api;
    BuildWindowMaterial build_window_material;
};

class RuntimeProviderFactory {
public:
    using Resolver = std::function<std::variant<RuntimeProviderBundle, BackendError>(
        ProviderRole, const BackendConfig &)>;

    static void registerProvider(std::string name, Resolver resolver);
    static void registerLinkedProviders();
    static std::variant<RuntimeProviderBundle, BackendError> resolve(
        const BackendConfig &config);
    static std::variant<std::function<std::variant<std::uint64_t, BackendError>()>,
                        BackendError>
    resolveTrustedTime(const StateMaintenanceConfig &config);
    static void clearForTest();
};

} // namespace xovm::cloud_material

#endif
