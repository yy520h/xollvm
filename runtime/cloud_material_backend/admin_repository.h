#ifndef XOVM_CLOUD_MATERIAL_BACKEND_ADMIN_REPOSITORY_H
#define XOVM_CLOUD_MATERIAL_BACKEND_ADMIN_REPOSITORY_H

#include "canonical_json.h"

#include <filesystem>
#include <functional>
#include <cstddef>
#include <cstdint>
#include <span>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <cstddef>
#include <string_view>

namespace xovm::cloud_material {

struct ImportRecord {
    std::string build_id;
    std::string software_id;
    std::vector<std::byte> public_manifest;
    std::vector<std::byte> private_registration;
    std::map<std::string, std::vector<std::byte>> verifier_sidecars;
};

inline constexpr size_t kMaxPublicManifestBytes = 4 * 1024 * 1024;
inline constexpr size_t kMaxPrivateRegistrationBytes = 512 * 1024 * 1024;
inline constexpr size_t kMaxCanonicalRegionBytes = 192 * 1024 * 1024;
inline constexpr size_t kMaxRegisteredRegions = 4096;
inline constexpr size_t kMaxArtifactVerificationEvidenceBytes = 64 * 1024;

struct AdminPrincipal {
    std::string software_id;
    std::set<std::string> scopes;
};

struct ValidationContext {
    // Must validate canonical syntax, closed registration schema, hashes, and pair membership.
    std::function<bool(const ImportRecord &, std::string &)> validate_pair;
    // Configured only by the trusted privileged admin adapter.
    std::function<bool(const std::string &, const std::string &,
                       std::span<const std::byte>, std::string &)> validate_final_artifact;
};

struct RepositoryTestAccess;

struct StoredBuild {
    ImportRecord registration;
    std::string final_artifact_hash;
    std::uint64_t policy_revision = 0;
};

class SnapshotManager;
struct RepositoryTestAccess;
bool registrationSizeAllowed(size_t manifest, size_t registration,
                             const std::vector<size_t> &regions);

class SqliteBuildRepository {
public:
    static std::variant<std::monostate, BackendError> checkSchema(
        const std::filesystem::path &databasePath);
    SqliteBuildRepository(const std::filesystem::path &databasePath,
                          ValidationContext validation);
    ~SqliteBuildRepository();
    SqliteBuildRepository(const SqliteBuildRepository &) = delete;
    SqliteBuildRepository &operator=(const SqliteBuildRepository &) = delete;

    bool importBuild(const ImportRecord &record, const AdminPrincipal &principal);
    bool enableAndPublish(const std::string &buildId, const std::string &finalArtifactHash,
                          std::span<const std::byte> verificationEvidence,
                          const AdminPrincipal &principal, SnapshotManager &manager,
                          ValidationContext validation);
    bool revokeAndPublish(const std::string &buildId, const AdminPrincipal &principal,
                          SnapshotManager &manager, ValidationContext validation);
    // Import commits first; a failed verification or enable leaves a validated build.
    bool importEnableAndPublish(const ImportRecord &record, const AdminPrincipal &principal,
                                const std::string &finalArtifactHash,
                                std::span<const std::byte> verificationEvidence,
                                SnapshotManager &manager,
                                ValidationContext validation);
    std::vector<StoredBuild> listEnabled() const;

private:
    bool enableBuild(const std::string &buildId, const std::string &finalArtifactHash,
                     std::span<const std::byte> verificationEvidence,
                     const AdminPrincipal &principal);
    bool revokeBuild(const std::string &buildId, const AdminPrincipal &principal);
    void testFailSidecarsAfter(int count);
    void testFailRowsAfter(int count);
    void testFailSidecarRowsAfter(int count);
    void testCorruptVerifier(const std::string &buildId, const std::string &regionId);
    void testSetArtifactHash(const std::string &buildId, const std::string &hash);
    void testOversizePublicManifest(const std::string &buildId);
    friend struct RepositoryTestAccess;
    struct Impl;
    Impl *impl_;
};

} // namespace xovm::cloud_material

#endif
