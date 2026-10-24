#ifndef XOVM_CLOUD_MATERIAL_BACKEND_AUTH_POLICY_H
#define XOVM_CLOUD_MATERIAL_BACKEND_AUTH_POLICY_H

#include "build_snapshot.h"
#include "canonical_json.h"

#include <mutex>
#include <set>

namespace xovm::cloud_material {

struct RequestFacts {
    std::string request_id;
    std::string request_digest;
    std::string software_id;
    std::string build_id;
    std::string final_artifact_hash;
    std::string region_id;
    std::string mode;
    std::string type;
};

class AnonymousGrant {
public:
    const std::string &subjectId() const { return subject_id_; }
    const std::string &buildId() const { return build_id_; }
    const std::string &requestDigest() const { return request_digest_; }
    std::uint64_t validUntilMs() const { return valid_until_ms_; }
    const std::set<std::string> &scopes() const { return scopes_; }

private:
    friend class RelayAuthenticator;
    friend class AnonymousPolicy;
    friend class SessionState;
    friend class ProtocolService;
    std::string subject_id_;
    std::string build_id_;
    std::string request_digest_;
    std::uint64_t valid_until_ms_ = 0;
    std::set<std::string> scopes_;
};

class RelayAuthenticator {
public:
    explicit RelayAuthenticator(std::string credential, std::uint64_t grantLifetimeMs = 86400000);
    std::variant<AnonymousGrant, BackendError> authenticate(
        const std::string &credential, const RequestFacts &facts,
        std::uint64_t trustedNow) const;

private:
    std::string credential_digest_;
    std::uint64_t grant_lifetime_ms_;
};

class AnonymousPolicy {
public:
    struct BuildRule {
        std::string software_id;
        std::string final_artifact_hash;
        std::set<std::string> regions;
        std::set<std::string> modes;
        std::uint64_t valid_until_ms = 0;
        std::uint64_t revision = 0;
        std::size_t request_budget = 0;
        bool enabled = false;
    };

    void setRule(const std::string &buildId, BuildRule rule);
    void clear();
    void replaceWith(AnonymousPolicy &&other);
    std::variant<AnonymousGrant, BackendError> authorize(
        const BuildSnapshot &snapshot, const RequestFacts &facts,
        std::uint64_t trustedNow, std::size_t rateBudget);

private:
    mutable std::mutex mutex_;
    std::map<std::string, BuildRule> rules_;
    std::map<std::string, std::size_t> usage_;
};

} // namespace xovm::cloud_material

#endif
