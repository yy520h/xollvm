#include "auth_policy.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <array>
#include <cstring>
#include <limits>
#include <mutex>
#include <utility>

namespace xovm::cloud_material {
namespace {
std::string sha256(std::string_view input) {
    std::array<unsigned char, 32> digest{};
    unsigned int length = 0;
    EVP_Digest(input.data(), input.size(), digest.data(), &length, EVP_sha256(), nullptr);
    return std::string(reinterpret_cast<const char *>(digest.data()), length);
}
}

struct AnonymousPolicy::AuthorizationRecord {
    enum class State { Pending, Committed };

    std::string build_id;
    std::string request_digest;
    std::size_t pending_holders = 0;
    State state = State::Pending;
};

struct AnonymousPolicy::Core {
    struct BuildState {
        BuildRule rule;
        std::size_t usage = 0;
    };

    explicit Core(std::size_t capacity) : authorization_cache_capacity(capacity) {}

    std::mutex mutex;
    std::map<std::string, BuildState> builds;
    std::map<RequestFacts::Identity, std::shared_ptr<AuthorizationRecord>> authorizations;
    std::size_t authorization_cache_capacity;
};

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

AnonymousPolicy::Reservation::Reservation(
    std::shared_ptr<Core> core, std::shared_ptr<AuthorizationRecord> record,
    AnonymousGrant grant, bool pendingHolder) noexcept
    : core_(std::move(core)), record_(std::move(record)), grant_(std::move(grant)),
      pending_holder_(pendingHolder) {}

AnonymousPolicy::Reservation::Reservation(Reservation &&other) noexcept
    : core_(std::move(other.core_)), record_(std::move(other.record_)),
      grant_(std::move(other.grant_)), pending_holder_(other.pending_holder_),
      committed_(other.committed_) {
    other.pending_holder_ = false;
    other.committed_ = false;
}

AnonymousPolicy::Reservation &
AnonymousPolicy::Reservation::operator=(Reservation &&other) noexcept {
    if (this == &other) return *this;
    releasePending();
    core_ = std::move(other.core_);
    record_ = std::move(other.record_);
    grant_ = std::move(other.grant_);
    pending_holder_ = other.pending_holder_;
    committed_ = other.committed_;
    other.pending_holder_ = false;
    other.committed_ = false;
    return *this;
}

AnonymousPolicy::Reservation::~Reservation() noexcept {
    releasePending();
}

bool AnonymousPolicy::Reservation::commit() noexcept {
    if (committed_) return true;
    if (!core_ || !record_) return false;

    std::lock_guard lock(core_->mutex);
    if (record_->state == AuthorizationRecord::State::Pending) {
        record_->state = AuthorizationRecord::State::Committed;
        record_->pending_holders = 0;
    }
    committed_ = true;
    pending_holder_ = false;
    return true;
}

void AnonymousPolicy::Reservation::releasePending() noexcept {
    if (!pending_holder_ || !core_ || !record_) return;
    std::lock_guard lock(core_->mutex);
    pending_holder_ = false;
    if (record_->state != AuthorizationRecord::State::Pending) return;
    if (record_->pending_holders != 0) --record_->pending_holders;
    if (record_->pending_holders != 0) return;

    for (auto authorization = core_->authorizations.begin();
         authorization != core_->authorizations.end(); ++authorization) {
        if (authorization->second != record_) continue;
        core_->authorizations.erase(authorization);
        const auto build = core_->builds.find(record_->build_id);
        if (build != core_->builds.end() && build->second.usage != 0)
            --build->second.usage;
        return;
    }
}

AnonymousPolicy::AnonymousPolicy(std::size_t authorizationCacheCapacity)
    : core_(std::make_shared<Core>(authorizationCacheCapacity)) {}

std::shared_ptr<AnonymousPolicy::Core> AnonymousPolicy::loadCore() const {
    std::lock_guard lock(core_mutex_);
    return core_;
}

void AnonymousPolicy::setRule(const std::string &buildId, BuildRule rule) {
    for (;;) {
        auto current = loadCore();
        auto replacement = std::make_shared<Core>(current->authorization_cache_capacity);
        {
            std::lock_guard lock(current->mutex);
            replacement->builds = current->builds;
            for (const auto &[identity, authorization] : current->authorizations) {
                if (authorization->build_id != buildId)
                    replacement->authorizations.emplace(identity, authorization);
            }
        }
        replacement->builds.insert_or_assign(buildId, Core::BuildState{
            .rule = rule,
            .usage = 0,
        });

        std::lock_guard lock(core_mutex_);
        if (core_ != current) continue;
        core_ = std::move(replacement);
        return;
    }
}

void AnonymousPolicy::clear() {
    const auto capacity = loadCore()->authorization_cache_capacity;
    auto replacement = std::make_shared<Core>(capacity);
    std::lock_guard lock(core_mutex_);
    core_ = std::move(replacement);
}

void AnonymousPolicy::replaceWith(AnonymousPolicy &&other) {
    if (this == &other) return;
    std::scoped_lock lock(core_mutex_, other.core_mutex_);
    core_.swap(other.core_);
}

std::variant<AnonymousPolicy::Reservation, BackendError> AnonymousPolicy::reserve(
    const BuildSnapshot &snapshot, const RequestFacts &facts, std::uint64_t trustedNow,
    std::size_t rateBudget) {
    auto core = loadCore();
    std::lock_guard lock(core->mutex);
    const auto *build = snapshot.find(facts.build_id);
    const auto policy = core->builds.find(facts.build_id);
    if (!build || policy == core->builds.end() || !policy->second.rule.enabled ||
        policy->second.rule.valid_until_ms <= trustedNow || rateBudget == 0 ||
        policy->second.rule.request_budget == 0 || facts.request_id.empty() ||
        facts.request_digest.empty() ||
        build->registration.software_id != facts.software_id ||
        policy->second.rule.software_id != facts.software_id ||
        build->final_artifact_hash != facts.final_artifact_hash ||
        policy->second.rule.final_artifact_hash != facts.final_artifact_hash ||
        policy->second.rule.revision != build->policy_revision ||
        (facts.type == "material.issue" &&
         (policy->second.rule.regions.count(facts.region_id) == 0 ||
          policy->second.rule.modes.count(facts.mode) == 0 || facts.mode == "operation")))
        return BackendError{"build_unavailable"};

    AnonymousGrant grant;
    grant.subject_id_ = "anonymous:" + facts.build_id;
    grant.build_id_ = facts.build_id;
    grant.request_digest_ = facts.request_digest;
    grant.valid_until_ms_ = policy->second.rule.valid_until_ms;
    grant.scopes_ = {"session.control", "material.issue"};

    const auto identity = facts.requestIdentity();
    const auto previous = core->authorizations.find(identity);
    if (previous != core->authorizations.end()) {
        const auto &record = previous->second;
        if (record->request_digest != facts.request_digest)
            return BackendError{"request_conflict"};
        if (record->state == AuthorizationRecord::State::Pending) {
            if (record->pending_holders == std::numeric_limits<std::size_t>::max())
                return BackendError{"build_unavailable"};
            ++record->pending_holders;
            return Reservation(core, record, std::move(grant), true);
        }
        return Reservation(core, record, std::move(grant), false);
    }

    if (policy->second.usage >= policy->second.rule.request_budget ||
        core->authorizations.size() >= core->authorization_cache_capacity)
        return BackendError{"build_unavailable"};

    auto record = std::make_shared<AuthorizationRecord>();
    record->build_id = facts.build_id;
    record->request_digest = facts.request_digest;
    record->pending_holders = 1;

    const auto [inserted, didInsert] = core->authorizations.emplace(identity, record);
    (void)inserted;
    if (!didInsert) return BackendError{"authority_unavailable"};
    ++policy->second.usage;
    return Reservation(core, std::move(record), std::move(grant), true);
}

std::variant<AnonymousGrant, BackendError> AnonymousPolicy::authorize(
    const BuildSnapshot &snapshot, const RequestFacts &facts, std::uint64_t trustedNow,
    std::size_t rateBudget) {
    auto result = reserve(snapshot, facts, trustedNow, rateBudget);
    if (auto *error = std::get_if<BackendError>(&result)) return std::move(*error);

    auto reservation = std::get<Reservation>(std::move(result));
    AnonymousGrant grant = reservation.grant();
    if (!reservation.commit()) return BackendError{"build_unavailable"};
    return grant;
}

} // namespace xovm::cloud_material
