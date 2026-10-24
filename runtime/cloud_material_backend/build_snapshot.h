#ifndef XOVM_CLOUD_MATERIAL_BACKEND_BUILD_SNAPSHOT_H
#define XOVM_CLOUD_MATERIAL_BACKEND_BUILD_SNAPSHOT_H

#include "admin_repository.h"

#include <memory>
#include <mutex>
#include <functional>
#include <condition_variable>
#include <unordered_map>
#include <string>
#include <set>
#include <variant>
#include <unordered_map>

namespace xovm::cloud_material {

struct SnapshotError {
    std::string code;
};

bool registrationSizeAllowed(size_t publicManifestBytes, size_t privateRegistrationBytes,
                              const std::vector<size_t> &regionBytes);

class BuildSnapshot {
public:
    static std::variant<std::shared_ptr<const BuildSnapshot>, SnapshotError>
    load(const SqliteBuildRepository &repository, const ValidationContext &validation);

    const StoredBuild *find(const std::string &buildId) const;
    std::uint64_t generation() const { return generation_; }
    void forEachBuild(const std::function<void(const StoredBuild &)> &visitor) const;

private:
    friend struct RepositoryTestAccess;
    std::uint64_t generation_ = 0;
    std::unordered_map<std::string, StoredBuild> builds_;
};

class SnapshotManager {
public:
    using SnapshotHandle = std::shared_ptr<const BuildSnapshot>;
    class IssuanceGuard {
    public:
        IssuanceGuard() = default;
        IssuanceGuard(IssuanceGuard &&) noexcept;
        IssuanceGuard &operator=(IssuanceGuard &&) noexcept;
        ~IssuanceGuard();
        explicit operator bool() const { return manager_ != nullptr; }
        void finishCommit();
    private:
        friend class SnapshotManager;
        IssuanceGuard(SnapshotManager *manager, std::string buildId);
        SnapshotManager *manager_ = nullptr;
        std::string build_id_;
    };

    explicit SnapshotManager(SnapshotHandle initial);
    SnapshotHandle acquire() const;
    void publish(SnapshotHandle nextSnapshot);
    bool ready() const;
    bool allowsIssuance(const SnapshotHandle &snapshot, const std::string &buildId) const;
    // Task 3 issuance must hold this guard through WAL sync and exact response commit.
    // allowsIssuance() alone does not fence revoke against an in-flight commit.
    IssuanceGuard beginIssuance(const SnapshotHandle &snapshot, const std::string &buildId);
    bool blockBuildWhile(const std::string &buildId,
                         const std::function<bool()> &durableRevoke);
    void failClosed();

private:
    friend struct RepositoryTestAccess;
    void failNextPublishForTest();
    void waitUntilBlockedForTest(const std::string &buildId);
    void endIssuance(const std::string &buildId);
    mutable std::mutex mutex_;
    SnapshotHandle current_;
    bool ready_ = true;
    bool fail_next_publish_ = false;
    std::set<std::string> blocked_builds_;
    std::condition_variable_any issuance_condition_;
    std::unordered_map<std::string, size_t> in_flight_;
};

} // namespace xovm::cloud_material

#endif
