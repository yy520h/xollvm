#include "runtime_providers.h"

#include <map>
#include <mutex>

namespace xovm::cloud_material {
namespace {

extern "C" void xovm_register_runtime_providers() __attribute__((weak));

std::map<std::string, RuntimeProviderFactory::Resolver> &registry() {
    static std::map<std::string, RuntimeProviderFactory::Resolver> value;
    return value;
}

std::mutex &registryMutex() {
    static std::mutex value;
    return value;
}

std::variant<RuntimeProviderBundle, BackendError> resolveOne(
    ProviderRole role, const std::string &name, const BackendConfig &config) {
    RuntimeProviderFactory::Resolver resolver;
    {
        std::lock_guard lock(registryMutex());
        const auto found = registry().find(name);
        if (found == registry().end()) return std::variant<RuntimeProviderBundle, BackendError>(
            BackendError{"provider_unavailable"});
        resolver = found->second;
    }
    try {
        auto result = resolver(role, config);
        if (const auto *error = std::get_if<BackendError>(&result)) return *error;
        return std::get<RuntimeProviderBundle>(std::move(result));
    } catch (...) {
        return std::variant<RuntimeProviderBundle, BackendError>(
            BackendError{"provider_unavailable"});
    }
}

} // namespace

void RuntimeProviderFactory::registerProvider(std::string name, Resolver resolver) {
    if (name.empty() || !resolver) return;
    std::lock_guard lock(registryMutex());
    registry()[std::move(name)] = std::move(resolver);
}

void RuntimeProviderFactory::registerLinkedProviders() {
    if (xovm_register_runtime_providers) xovm_register_runtime_providers();
}

std::variant<RuntimeProviderBundle, BackendError> RuntimeProviderFactory::resolve(
    const BackendConfig &config) {
    if (config.trusted_time_provider.empty() || config.signing_key_provider.empty() ||
        config.anonymous_policy_provider.empty() || config.trust_root_provider.empty())
        return std::variant<RuntimeProviderBundle, BackendError>(
            BackendError{"provider_unavailable"});
    auto clock = resolveOne(ProviderRole::trusted_time, config.trusted_time_provider, config);
    if (std::holds_alternative<BackendError>(clock)) return std::get<BackendError>(clock);
    auto signer = resolveOne(ProviderRole::signing_key, config.signing_key_provider, config);
    if (std::holds_alternative<BackendError>(signer)) return std::get<BackendError>(signer);
    auto policy = resolveOne(ProviderRole::anonymous_policy, config.anonymous_policy_provider, config);
    if (std::holds_alternative<BackendError>(policy)) return std::get<BackendError>(policy);
    auto trust = resolveOne(ProviderRole::trust_root, config.trust_root_provider, config);
    if (std::holds_alternative<BackendError>(trust)) return std::get<BackendError>(trust);
    auto result = std::get<RuntimeProviderBundle>(std::move(clock));
    auto signerResult = std::get<RuntimeProviderBundle>(std::move(signer));
    auto policyResult = std::get<RuntimeProviderBundle>(std::move(policy));
    auto trustResult = std::get<RuntimeProviderBundle>(std::move(trust));
    if (!result.trusted_now || !signerResult.random_bytes || !signerResult.sign ||
        !signerResult.signing.available() || !policyResult.validate_pair ||
        !policyResult.configure_policy || !policyResult.authorize_control ||
        (!policyResult.issue && !policyResult.build_payload) ||
        !trustResult.validate_final_artifact || !trustResult.artifact_evidence ||
        !policyResult.authorize_admin ||
        !trustResult.trust_handler)
        return std::variant<RuntimeProviderBundle, BackendError>(
            BackendError{"provider_unavailable"});
    result.random_bytes = std::move(signerResult.random_bytes);
    result.sign = std::move(signerResult.sign);
    result.signing = std::move(signerResult.signing);
    result.validate_pair = std::move(policyResult.validate_pair);
    result.configure_policy = std::move(policyResult.configure_policy);
    result.authorize_control = std::move(policyResult.authorize_control);
    result.issue = std::move(policyResult.issue);
    result.build_payload = std::move(policyResult.build_payload);
    result.validate_final_artifact = std::move(trustResult.validate_final_artifact);
    result.artifact_evidence = std::move(trustResult.artifact_evidence);
    result.authorize_admin = std::move(policyResult.authorize_admin);
    result.trust_handler = std::move(trustResult.trust_handler);
    return result;
}

void RuntimeProviderFactory::clearForTest() {
    std::lock_guard lock(registryMutex());
    registry().clear();
}

} // namespace xovm::cloud_material
