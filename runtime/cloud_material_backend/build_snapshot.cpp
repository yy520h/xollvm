#include "build_snapshot.h"

#include <atomic>
#include <condition_variable>
#include <stdexcept>
#include <utility>
#include <vector>
#include <algorithm>
#include <string_view>

namespace xovm::cloud_material {

namespace {
bool validHash(std::string_view value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
}

bool registrationSizeAllowed(size_t manifest, size_t registration,
                             const std::vector<size_t> &regions) {
    if (manifest > kMaxPublicManifestBytes || registration > kMaxPrivateRegistrationBytes ||
        regions.empty() || regions.size() > kMaxRegisteredRegions) return false;
    size_t total = 0;
    for (size_t size : regions) {
        if (!size || size > kMaxCanonicalRegionBytes || size > kMaxPrivateRegistrationBytes - total)
            return false;
        total += size;
    }
    return true;
}

std::variant<std::shared_ptr<const BuildSnapshot>, SnapshotError>
BuildSnapshot::load(const SqliteBuildRepository &repository,
                    const ValidationContext &validation) {
    auto snapshot = std::shared_ptr<BuildSnapshot>(new BuildSnapshot);
    static std::atomic<std::uint64_t> nextGeneration{1};
    snapshot->generation_ = nextGeneration.fetch_add(1, std::memory_order_relaxed);
    if (!validation.validate_pair) return SnapshotError{"registration_validator_unavailable"};
    std::vector<StoredBuild> enabled;
    try {
        enabled = repository.listEnabled();
    } catch (...) {
        return SnapshotError{"invalid_stored_build"};
    }
    for (auto &build : enabled) {
        std::string validationError;
        bool validPair = false;
        try {
            validPair = validation.validate_pair(build.registration, validationError);
        } catch (...) {
            return SnapshotError{"registration_validator_failed"};
        }
        if (!validPair ||
            !validHash(build.final_artifact_hash) ||
            build.registration.verifier_sidecars.empty())
            return SnapshotError{"invalid_enabled_build"};
        for (const auto &[region, verifier] : build.registration.verifier_sidecars)
            if (!validHash(region) || verifier.empty() || verifier.size() > kMaxCanonicalRegionBytes)
                return SnapshotError{"invalid_verifier_sidecar"};
        if (!snapshot->builds_.emplace(build.registration.build_id, std::move(build)).second)
            return SnapshotError{"duplicate_build_identity"};
    }
    return std::shared_ptr<const BuildSnapshot>(std::move(snapshot));
}

const StoredBuild *BuildSnapshot::find(const std::string &buildId) const {
    const auto found = builds_.find(buildId);
    return found == builds_.end() ? nullptr : &found->second;
}

void BuildSnapshot::forEachBuild(const std::function<void(const StoredBuild &)> &visitor) const {
    if (!visitor) return;
    for (const auto &[buildId, build] : builds_) {
        (void)buildId;
        visitor(build);
    }
}

SnapshotManager::SnapshotManager(SnapshotHandle initial) : current_(std::move(initial)) {
    if (!current_) ready_ = false;
}

SnapshotManager::SnapshotHandle SnapshotManager::acquire() const {
    std::lock_guard lock(mutex_);
    if (!ready_) return std::make_shared<const BuildSnapshot>();
    return current_;
}

void SnapshotManager::publish(SnapshotHandle nextSnapshot) {
    if (!nextSnapshot) throw std::invalid_argument("invalid_snapshot");
    std::lock_guard lock(mutex_);
    if (fail_next_publish_) {
        fail_next_publish_ = false;
        ready_ = false;
        current_ = std::make_shared<const BuildSnapshot>();
        throw std::runtime_error("snapshot_publish_failed");
    }
    current_ = std::move(nextSnapshot);
    ready_ = true;
}

bool SnapshotManager::ready() const {
    std::lock_guard lock(mutex_);
    return ready_;
}

bool SnapshotManager::allowsIssuance(const SnapshotHandle &snapshot,
                                     const std::string &buildId) const {
    std::lock_guard lock(mutex_);
    return ready_ && snapshot && snapshot->find(buildId) &&
           blocked_builds_.find(buildId) == blocked_builds_.end();
}

SnapshotManager::IssuanceGuard::IssuanceGuard(SnapshotManager *manager, std::string buildId)
    : manager_(manager), build_id_(std::move(buildId)) {}

SnapshotManager::IssuanceGuard::IssuanceGuard(IssuanceGuard &&other) noexcept
    : manager_(std::exchange(other.manager_, nullptr)), build_id_(std::move(other.build_id_)) {}

SnapshotManager::IssuanceGuard &SnapshotManager::IssuanceGuard::operator=(IssuanceGuard &&other) noexcept {
    if (this != &other) {
        if (manager_) manager_->endIssuance(build_id_);
        manager_ = std::exchange(other.manager_, nullptr);
        build_id_ = std::move(other.build_id_);
    }
    return *this;
}

SnapshotManager::IssuanceGuard::~IssuanceGuard() {
    if (manager_) manager_->endIssuance(build_id_);
}

void SnapshotManager::IssuanceGuard::finishCommit() {
    if (manager_) {
        auto *manager = std::exchange(manager_, nullptr);
        manager->endIssuance(build_id_);
    }
}

SnapshotManager::IssuanceGuard SnapshotManager::beginIssuance(
    const SnapshotHandle &snapshot, const std::string &buildId) {
    std::lock_guard lock(mutex_);
    if (!ready_ || !snapshot || current_.get() != snapshot.get() || !snapshot->find(buildId) ||
        blocked_builds_.find(buildId) != blocked_builds_.end()) return {};
    ++in_flight_[buildId];
    return IssuanceGuard(this, buildId);
}

void SnapshotManager::endIssuance(const std::string &buildId) {
    std::lock_guard lock(mutex_);
    auto found = in_flight_.find(buildId);
    if (found != in_flight_.end() && --found->second == 0) {
        in_flight_.erase(found);
        issuance_condition_.notify_all();
    }
}

bool SnapshotManager::blockBuildWhile(const std::string &buildId,
                                      const std::function<bool()> &durableRevoke) {
    std::unique_lock lock(mutex_);
    if (blocked_builds_.find(buildId) != blocked_builds_.end()) return false;
    blocked_builds_.insert(buildId);
    issuance_condition_.notify_all();
    issuance_condition_.wait(lock, [&] { return in_flight_.find(buildId) == in_flight_.end(); });
    if (durableRevoke()) return true;
    blocked_builds_.erase(buildId);
    return false;
}

void SnapshotManager::waitUntilBlockedForTest(const std::string &buildId) {
    std::unique_lock lock(mutex_);
    issuance_condition_.wait(lock, [&] { return blocked_builds_.find(buildId) != blocked_builds_.end(); });
}

void SnapshotManager::failClosed() {
    std::lock_guard lock(mutex_);
    ready_ = false;
    current_ = std::make_shared<const BuildSnapshot>();
}

void SnapshotManager::failNextPublishForTest() {
    std::lock_guard lock(mutex_);
    fail_next_publish_ = true;
}

} // namespace xovm::cloud_material
