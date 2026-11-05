#ifndef XOVM_CLOUD_MATERIAL_BACKEND_AUTH_POLICY_H
#define XOVM_CLOUD_MATERIAL_BACKEND_AUTH_POLICY_H

#include "build_snapshot.h"
#include "canonical_json.h"

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <tuple>
#include <variant>

namespace xovm::cloud_material {

struct RequestFacts {
    using Identity = std::tuple<std::string, std::string, std::string, std::string>;

    std::string request_id;
    std::string request_digest;
    std::string software_id;
    std::string build_id;
    std::string final_artifact_hash;
    std::string region_id;
    std::string mode;
    std::string type;

    Identity requestIdentity() const {
        return {software_id, build_id, final_artifact_hash, request_id};
    }
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
private:
    struct Core;
    struct AuthorizationRecord;

public:
    static constexpr std::size_t kDefaultAuthorizationCacheCapacity = 4096;

    class Reservation {
    public:
        Reservation(const Reservation &) = delete;
        Reservation &operator=(const Reservation &) = delete;
        Reservation(Reservation &&other) noexcept;
        Reservation &operator=(Reservation &&other) noexcept;
        ~Reservation() noexcept;

        const AnonymousGrant &grant() const noexcept { return grant_; }

        // Commits this request's budget slot. A live reservation always commits;
        // moved-from reservations return false.
        bool commit() noexcept;

    private:
        friend class AnonymousPolicy;
        Reservation(std::shared_ptr<Core> core,
                    std::shared_ptr<AuthorizationRecord> record,
                    AnonymousGrant grant, bool pendingHolder) noexcept;
        void releasePending() noexcept;

        std::shared_ptr<Core> core_;
        std::shared_ptr<AuthorizationRecord> record_;
        AnonymousGrant grant_;
        bool pending_holder_ = false;
        bool committed_ = false;
    };

    explicit AnonymousPolicy(
        std::size_t authorizationCacheCapacity = kDefaultAuthorizationCacheCapacity);
    AnonymousPolicy(const AnonymousPolicy &) = delete;
    AnonymousPolicy &operator=(const AnonymousPolicy &) = delete;
    AnonymousPolicy(AnonymousPolicy &&) = delete;
    AnonymousPolicy &operator=(AnonymousPolicy &&) = delete;

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
    std::variant<Reservation, BackendError> reserve(
        const BuildSnapshot &snapshot, const RequestFacts &facts,
        std::uint64_t trustedNow, std::size_t rateBudget);

    // Compatibility wrapper for call sites that do not yet have a durable
    // operation around which to hold a Reservation.
    std::variant<AnonymousGrant, BackendError> authorize(
        const BuildSnapshot &snapshot, const RequestFacts &facts,
        std::uint64_t trustedNow, std::size_t rateBudget);

private:
    std::shared_ptr<Core> loadCore() const;
    mutable std::mutex core_mutex_;
    std::shared_ptr<Core> core_;
};

} // namespace xovm::cloud_material

#endif
