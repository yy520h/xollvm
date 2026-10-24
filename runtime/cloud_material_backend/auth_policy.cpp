#include "auth_policy.h"

#include <openssl/evp.h>

#include <array>
#include <cstring>
#include <openssl/crypto.h>

namespace xovm::cloud_material {
namespace {
std::string sha256(std::string_view input) {
    std::array<unsigned char, 32> digest{};
    unsigned int length = 0;
    EVP_Digest(input.data(), input.size(), digest.data(), &length, EVP_sha256(), nullptr);
    return std::string(reinterpret_cast<const char *>(digest.data()), length);
}
}

RelayAuthenticator::RelayAuthenticator(std::string credential, std::uint64_t grantLifetimeMs)
    : credential_digest_(sha256(credential)), grant_lifetime_ms_(grantLifetimeMs) {}

std::variant<AnonymousGrant, BackendError> RelayAuthenticator::authenticate(
    const std::string &credential, const RequestFacts &facts, std::uint64_t trustedNow) const {
    const auto supplied = sha256(credential);
    if (supplied.size() != credential_digest_.size() ||
        CRYPTO_memcmp(supplied.data(), credential_digest_.data(), supplied.size()) != 0 ||
        facts.build_id.empty() || facts.request_digest.empty())
        return BackendError{"unauthorized"};
    AnonymousGrant grant;
    grant.subject_id_ = "anonymous:" + facts.build_id;
    grant.build_id_ = facts.build_id;
    grant.request_digest_ = facts.request_digest;
    if (!grant_lifetime_ms_ || trustedNow > UINT64_MAX - grant_lifetime_ms_)
        return BackendError{"authority_unavailable"};
    grant.valid_until_ms_ = trustedNow + grant_lifetime_ms_;
    grant.scopes_ = {"session.control", "material.issue"};
    return grant;
}

void AnonymousPolicy::setRule(const std::string &buildId, BuildRule rule) {
    std::lock_guard lock(mutex_);
    rules_[buildId] = std::move(rule);
    usage_.erase(buildId);
}

void AnonymousPolicy::clear() {
    std::lock_guard lock(mutex_);
    rules_.clear();
    usage_.clear();
}

void AnonymousPolicy::replaceWith(AnonymousPolicy &&other) {
    if (this == &other) return;
    std::scoped_lock lock(mutex_, other.mutex_);
    rules_ = std::move(other.rules_);
    usage_ = std::move(other.usage_);
}

std::variant<AnonymousGrant, BackendError> AnonymousPolicy::authorize(
    const BuildSnapshot &snapshot, const RequestFacts &facts, std::uint64_t trustedNow,
    std::size_t rateBudget) {
    std::lock_guard lock(mutex_);
    const auto *build = snapshot.find(facts.build_id);
    const auto policy = rules_.find(facts.build_id);
    if (!build || policy == rules_.end() || !policy->second.enabled ||
        policy->second.valid_until_ms <= trustedNow || rateBudget == 0 ||
        policy->second.request_budget == 0 ||
        usage_[facts.build_id] >= policy->second.request_budget ||
        build->registration.software_id != facts.software_id ||
        policy->second.software_id != facts.software_id ||
        build->final_artifact_hash != facts.final_artifact_hash ||
        policy->second.final_artifact_hash != facts.final_artifact_hash ||
         policy->second.revision != build->policy_revision ||
         (facts.type == "material.issue" &&
          (policy->second.regions.count(facts.region_id) == 0 ||
           policy->second.modes.count(facts.mode) == 0 || facts.mode == "operation")))
        return BackendError{"build_unavailable"};
    ++usage_[facts.build_id];
    AnonymousGrant grant;
    grant.subject_id_ = "anonymous:" + facts.build_id;
    grant.build_id_ = facts.build_id;
    grant.request_digest_ = facts.request_digest;
    grant.valid_until_ms_ = policy->second.valid_until_ms;
    grant.scopes_ = {"session.control", "material.issue"};
    return grant;
}

} // namespace xovm::cloud_material
