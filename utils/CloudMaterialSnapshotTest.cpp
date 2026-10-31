#include "admin_repository.h"
#include "build_snapshot.h"

#include <cstdio>
#include <filesystem>
#include <functional>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <chrono>
#include <cstddef>
#include <map>
#include <string>
#include <utility>
#include <vector>
#include <span>
#include <algorithm>
#include <sqlite3.h>
#include <stdexcept>

namespace xovm::cloud_material {
struct RepositoryTestAccess {
    static void failAfterSidecarInsert(SqliteBuildRepository &repository, int count) { repository.testFailSidecarsAfter(count); }
    static void failListEnabledAfterRows(SqliteBuildRepository &repository, int count) { repository.testFailRowsAfter(count); }
    static void failSidecarsAfterRows(SqliteBuildRepository &repository, int count) { repository.testFailSidecarRowsAfter(count); }
    static void corruptVerifier(SqliteBuildRepository &repository, const std::string &build, const std::string &region) { repository.testCorruptVerifier(build, region); }
    static void setArtifactHash(SqliteBuildRepository &repository, const std::string &build, const std::string &hash) { repository.testSetArtifactHash(build, hash); }
    static void oversizeManifest(SqliteBuildRepository &repository, const std::string &build) { repository.testOversizePublicManifest(build); }
    static void failNextPublish(SnapshotManager &manager) { manager.failNextPublishForTest(); }
    static void waitUntilBlocked(SnapshotManager &manager, const std::string &build) { manager.waitUntilBlockedForTest(build); }
};
}

namespace {
using namespace xovm::cloud_material;

struct TestState {
    unsigned assertions = 0;
    unsigned failures = 0;
    const char *test_name = "";
};

TestState state;

bool expect(bool condition, const char *expression, const char *file, int line) {
    ++state.assertions;
    if (condition) return true;
    ++state.failures;
    std::fprintf(stderr, "%s:%d: %s failed in %s\n", file, line, expression,
                 state.test_name);
    return false;
}

#define EXPECT_TRUE(expression) \
    expect(static_cast<bool>(expression), #expression, __FILE__, __LINE__)
#define EXPECT_FALSE(expression) \
    expect(!static_cast<bool>(expression), "! (" #expression ")", __FILE__, __LINE__)
#define ASSERT_TRUE(expression) \
    do { \
        if (!EXPECT_TRUE(expression)) return; \
    } while (false)
#define ASSERT_FALSE(expression) \
    do { \
        if (!EXPECT_FALSE(expression)) return; \
    } while (false)
#define TEST(suite, name) static void suite##_##name()

constexpr char kBuildId[] = "1111111111111111111111111111111111111111111111111111111111111111";
constexpr char kRegionId[] = "2222222222222222222222222222222222222222222222222222222222222222";
constexpr char kArtifactHash[] = "3333333333333333333333333333333333333333333333333333333333333333";
const std::vector<std::byte> kArtifactEvidence{std::byte{'v'}, std::byte{'e'}, std::byte{'r'}, std::byte{'i'}, std::byte{'f'}, std::byte{'i'}, std::byte{'e'}, std::byte{'d'}};

ValidationContext validationContext(bool acceptArtifact = true, bool includeArtifactVerifier = true,
                                    bool throwPair = false) {
    ValidationContext context{
      .validate_pair = [throwPair](const ImportRecord &record, std::string &error) {
        if (throwPair) throw std::runtime_error("validator_test_exception");
        const std::string publicText(reinterpret_cast<const char *>(record.public_manifest.data()), record.public_manifest.size());
        const std::string privateText(reinterpret_cast<const char *>(record.private_registration.data()), record.private_registration.size());
        if (publicText.find(record.build_id) == std::string::npos || privateText.find(record.build_id) == std::string::npos ||
            record.verifier_sidecars.empty() ||
            !record.verifier_sidecars.contains(kRegionId)) {
            error = "invalid_test_registration";
            return false;
        }
        return true;
      }
    };
    if (includeArtifactVerifier) context.validate_final_artifact =
      [acceptArtifact](const std::string &buildId, const std::string &hash,
                                    std::span<const std::byte> evidence, std::string &error) {
        if (!acceptArtifact || buildId.empty() || hash != kArtifactHash ||
            !std::equal(evidence.begin(), evidence.end(), kArtifactEvidence.begin(), kArtifactEvidence.end())) {
            error = "artifact_verification_rejected";
            return false;
        }
        return true;
      };
    return context;
}

ImportRecord validRecord(std::string buildId = kBuildId) {
    ImportRecord record;
    record.build_id = std::move(buildId);
    record.software_id = "test.software";
    const std::string publicText = "{\"build_id\":\"" + record.build_id +
        "\",\"software_id\":\"test.software\"}";
    const std::string privateText = "{\"build_id\":\"" + record.build_id +
        "\",\"regions\":[{\"region_id\":\"" + std::string(kRegionId) + "\"}]}";
    for (char c : publicText) record.public_manifest.push_back(static_cast<std::byte>(c));
    for (char c : privateText) record.private_registration.push_back(static_cast<std::byte>(c));
    const std::string regionText = "{\"region_id\":\"" + std::string(kRegionId) + "\"}";
    std::vector<std::byte> verifier;
    for (char c : regionText) verifier.push_back(static_cast<std::byte>(c));
    record.verifier_sidecars.emplace(kRegionId, std::move(verifier));
    return record;
}

AdminPrincipal admin() {
    return {.software_id = "test.software", .scopes = {"build.publish", "build.revoke"}};
}

bool enable(SqliteBuildRepository &repository, SnapshotManager &manager,
            ValidationContext validation = validationContext(),
            std::span<const std::byte> evidence = kArtifactEvidence,
            std::string hash = kArtifactHash, std::string buildId = kBuildId) {
    return repository.enableAndPublish(buildId, hash, evidence, admin(), manager,
                                       std::move(validation));
}

struct TempDatabase {
    std::filesystem::path path = std::filesystem::temp_directory_path() /
        ("xovm-snapshot-test-" + std::to_string(reinterpret_cast<uintptr_t>(this)) + ".db");
    ~TempDatabase() {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        std::filesystem::remove(path.string() + "-wal", ignored);
        std::filesystem::remove(path.string() + "-shm", ignored);
    }
};

TEST(CloudMaterialSnapshot, ImportIsIdempotentAndRejectsIdentityConflict) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    auto record = validRecord();
    EXPECT_TRUE(repository.importBuild(record, admin()));
    EXPECT_TRUE(repository.importBuild(record, admin()));

    auto conflict = record;
    conflict.private_registration.back() = std::byte{' '};
    EXPECT_FALSE(repository.importBuild(conflict, admin()));
}

TEST(CloudMaterialSnapshot, SameDomWithDifferentCanonicalBytesConflicts) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    auto record = validRecord();
    ASSERT_TRUE(repository.importBuild(record, admin()));
    auto different = record;
    different.public_manifest.insert(different.public_manifest.end(), {std::byte{' '}});
    EXPECT_FALSE(repository.importBuild(different, admin()));
}

TEST(CloudMaterialSnapshot, ExactCanonicalRegistrationBytesDefineIdentity) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    auto record = validRecord();
    ASSERT_TRUE(repository.importBuild(record, admin()));
    auto differentCanonicalRecord = record;
    const std::string suffix = ",\"x\":1}";
    differentCanonicalRecord.private_registration.pop_back();
    for (char c : suffix)
        differentCanonicalRecord.private_registration.push_back(static_cast<std::byte>(c));
    EXPECT_FALSE(repository.importBuild(differentCanonicalRecord, admin()));
}

TEST(CloudMaterialSnapshot, RejectsRegistrationNestingBeyondProtocolLimit) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    auto record = validRecord();
    const std::string nested = ",\"x\":[[[[[[[[0]]]]]]]]}";
    record.public_manifest.pop_back();
    for (char c : nested) record.public_manifest.push_back(static_cast<std::byte>(c));
    EXPECT_FALSE(repository.importBuild(record, admin()));
}

TEST(CloudMaterialSnapshot, RejectsU32OverflowAndOverlongIntegerTokens) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    for (const std::string number : {"4294967296", "123456789012345678901234567890"}) {
        auto record = validRecord();
        record.public_manifest.pop_back();
        const std::string suffix = ",\"x\":" + number + "}";
        for (char c : suffix) record.public_manifest.push_back(static_cast<std::byte>(c));
        EXPECT_FALSE(repository.importBuild(record, admin()));
    }
}

TEST(CloudMaterialSnapshot, RejectsGeneralArraysOverWireLimit) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    auto record = validRecord();
    record.public_manifest.pop_back();
    std::string extension = ",\"x\":[";
    for (unsigned i = 0; i < 257; ++i) {
        if (i) extension += ',';
        extension += '0';
    }
    extension += "]}";
    for (char c : extension) record.public_manifest.push_back(static_cast<std::byte>(c));
    EXPECT_FALSE(repository.importBuild(record, admin()));
}

TEST(CloudMaterialSnapshot, MissingRegistrationValidatorFailsClosed) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), {});
    EXPECT_FALSE(repository.importBuild(validRecord(), admin()));
    auto snapshot = BuildSnapshot::load(repository, {});
    EXPECT_TRUE(std::holds_alternative<SnapshotError>(snapshot));
    EXPECT_TRUE(repository.listEnabled().empty());
}

TEST(CloudMaterialSnapshot, ThrowingPairValidatorReturnsSnapshotError) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    ASSERT_TRUE(repository.importBuild(validRecord(), admin()));
    auto loaded = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(loaded));
    SnapshotManager manager(std::get<std::shared_ptr<const BuildSnapshot>>(loaded));
    ASSERT_TRUE(enable(repository, manager));
    decltype(BuildSnapshot::load(repository, validationContext())) result;
    bool escaped = false;
    try {
        result = BuildSnapshot::load(repository, validationContext(true, true, true));
    } catch (...) { escaped = true; }
    EXPECT_FALSE(escaped);
    EXPECT_TRUE(std::holds_alternative<SnapshotError>(result));
}

TEST(CloudMaterialSnapshot, ThrowingValidatorAfterEnableFailsClosed) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    ASSERT_TRUE(repository.importBuild(validRecord(), admin()));
    auto initial = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(initial));
    SnapshotManager manager(std::get<std::shared_ptr<const BuildSnapshot>>(initial));
    bool escaped = false;
    bool result = true;
    try {
        result = repository.enableAndPublish(kBuildId, kArtifactHash, kArtifactEvidence,
            admin(), manager, validationContext(true, true, true));
    } catch (...) { escaped = true; }
    EXPECT_FALSE(escaped);
    EXPECT_FALSE(result);
    EXPECT_FALSE(manager.ready());
    EXPECT_TRUE(repository.listEnabled().size() == 1);
}

TEST(CloudMaterialSnapshot, ThrowingValidatorAfterRevokeFailsClosed) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    ASSERT_TRUE(repository.importBuild(validRecord(), admin()));
    const std::string otherBuildId(64, '4');
    ASSERT_TRUE(repository.importBuild(validRecord(otherBuildId), admin()));
    auto initial = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(initial));
    SnapshotManager manager(std::get<std::shared_ptr<const BuildSnapshot>>(initial));
    ASSERT_TRUE(enable(repository, manager));
    ASSERT_TRUE(enable(repository, manager, validationContext(), kArtifactEvidence,
                       kArtifactHash, otherBuildId));
    bool escaped = false;
    bool result = true;
    try {
        result = repository.revokeAndPublish(kBuildId, admin(), manager,
                                             validationContext(true, true, true));
    } catch (...) { escaped = true; }
    EXPECT_FALSE(escaped);
    EXPECT_FALSE(result);
    EXPECT_FALSE(manager.ready());
    EXPECT_TRUE(repository.listEnabled().size() == 1);
}

TEST(CloudMaterialSnapshot, MigrationUsesIntegerTimestampDefault) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    ASSERT_TRUE(repository.importBuild(validRecord(), admin()));
    sqlite3 *connection = nullptr;
    ASSERT_TRUE(sqlite3_open(db.path.c_str(), &connection) == SQLITE_OK);
    sqlite3_stmt *statement = nullptr;
    ASSERT_TRUE(sqlite3_prepare_v2(connection,
        "SELECT typeof(created_at), created_at FROM builds WHERE build_id=?1",
        -1, &statement, nullptr) == SQLITE_OK);
    ASSERT_TRUE(sqlite3_bind_text(statement, 1, kBuildId, -1, SQLITE_STATIC) == SQLITE_OK);
    ASSERT_TRUE(sqlite3_step(statement) == SQLITE_ROW);
    EXPECT_TRUE(std::string(reinterpret_cast<const char *>(sqlite3_column_text(statement, 0))) == "integer");
    EXPECT_TRUE(sqlite3_column_int64(statement, 1) > 0);
    sqlite3_finalize(statement);
    sqlite3_close(connection);
}

TEST(CloudMaterialSnapshot, ArtifactEnableRequiresTrustedVerifierAndEvidence) {
    TempDatabase db;
    auto noVerifier = validationContext(true, false);
    SqliteBuildRepository repository(db.path.string(), noVerifier);
    ASSERT_TRUE(repository.importBuild(validRecord(), admin()));
    auto loaded = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(loaded));
    SnapshotManager manager(std::get<std::shared_ptr<const BuildSnapshot>>(loaded));
    EXPECT_FALSE(enable(repository, manager, noVerifier));
    EXPECT_FALSE(enable(repository, manager, validationContext(), {}));
    EXPECT_FALSE(enable(repository, manager, validationContext(), kArtifactEvidence,
                        std::string(64, '4')));
    EXPECT_TRUE(repository.listEnabled().empty());
    EXPECT_FALSE(enable(repository, manager));
}

TEST(CloudMaterialSnapshot, ArtifactVerifierRejectsMismatchedBuildHashEvidence) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext(false));
    ASSERT_TRUE(repository.importBuild(validRecord(), admin()));
    auto loaded = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(loaded));
    SnapshotManager manager(std::get<std::shared_ptr<const BuildSnapshot>>(loaded));
    EXPECT_FALSE(enable(repository, manager));
    EXPECT_TRUE(repository.listEnabled().empty());
}

TEST(CloudMaterialSnapshot, RejectsInvalidAdminSoftwareIdBeforeSqliteBinding) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    auto invalidId = validRecord();
    invalidId.software_id = "bad id";
    EXPECT_FALSE(repository.importBuild(invalidId,
        AdminPrincipal{.software_id = "bad id", .scopes = {"build.publish"}}));
    invalidId.software_id = std::string(65, 'a');
    EXPECT_FALSE(repository.importBuild(invalidId,
        AdminPrincipal{.software_id = invalidId.software_id, .scopes = {"build.publish"}}));
}

TEST(CloudMaterialSnapshot, RejectsOversizedStoredBlobBeforeSnapshotCopy) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    ASSERT_TRUE(repository.importBuild(validRecord(), admin()));
    auto loaded = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(loaded));
    SnapshotManager manager(std::get<std::shared_ptr<const BuildSnapshot>>(loaded));
    ASSERT_TRUE(enable(repository, manager));
    RepositoryTestAccess::oversizeManifest(repository, kBuildId);
    EXPECT_TRUE(std::holds_alternative<SnapshotError>(BuildSnapshot::load(repository, validationContext())));
}

TEST(CloudMaterialSnapshot, RejectsInvalidMembershipAndUnauthorizedAdmin) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    auto invalid = validRecord();
    invalid.private_registration.front() = std::byte{' '};
    EXPECT_FALSE(repository.importBuild(invalid, admin()));
    EXPECT_FALSE(repository.importBuild(validRecord(), AdminPrincipal{.software_id = "test.software"}));
}

TEST(CloudMaterialSnapshot, FailedValidationLeavesNoPartialImport) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    auto invalid = validRecord();
    invalid.verifier_sidecars.clear();
    EXPECT_FALSE(repository.importBuild(invalid, admin()));
    EXPECT_TRUE(repository.listEnabled().empty());
}

TEST(CloudMaterialSnapshot, FailedTransactionRollsBackBuildAndSidecars) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    auto record = validRecord();
    const std::string secondRegion = "4444444444444444444444444444444444444444444444444444444444444444";
    const std::string regionText = "{\"region_id\":\"" + secondRegion + "\"}";
    std::vector<std::byte> secondVerifier;
    for (char c : regionText) secondVerifier.push_back(static_cast<std::byte>(c));
    record.verifier_sidecars.emplace(secondRegion, std::move(secondVerifier));
    RepositoryTestAccess::failAfterSidecarInsert(repository, 1);
    EXPECT_FALSE(repository.importBuild(record, admin()));
    EXPECT_TRUE(repository.importBuild(record, admin()));
}

TEST(CloudMaterialSnapshot, EnableAndRevokeAreDurableStateTransitions) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    ASSERT_TRUE(repository.importBuild(validRecord(), admin()));
    auto initial = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(initial));
    SnapshotManager manager(std::get<std::shared_ptr<const BuildSnapshot>>(initial));
    EXPECT_TRUE(enable(repository, manager));
    EXPECT_TRUE(repository.listEnabled().size() == 1);
    EXPECT_TRUE(repository.revokeAndPublish(kBuildId, admin(), manager, validationContext()));
    EXPECT_TRUE(repository.listEnabled().empty());
}

TEST(CloudMaterialSnapshot, LoadRejectsCorruptEnabledBuildWithoutPublishingPartialSnapshot) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    ASSERT_TRUE(repository.importBuild(validRecord(), admin()));
    auto empty = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(empty));
    SnapshotManager manager(std::get<std::shared_ptr<const BuildSnapshot>>(empty));
    ASSERT_TRUE(enable(repository, manager));
    auto first = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(first));
    (void)first;
    const auto pinned = manager.acquire();

    RepositoryTestAccess::corruptVerifier(repository, kBuildId, kRegionId);
    auto invalid = BuildSnapshot::load(repository, validationContext());
    EXPECT_TRUE(std::holds_alternative<SnapshotError>(invalid));
    EXPECT_TRUE(manager.acquire() == pinned);
    EXPECT_TRUE(pinned->find(kBuildId) != nullptr);
}

TEST(CloudMaterialSnapshot, PinnedGenerationRemainsImmutableAcrossPublish) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    ASSERT_TRUE(repository.importBuild(validRecord(), admin()));
    auto emptySnapshot = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(emptySnapshot));
    SnapshotManager manager(std::get<std::shared_ptr<const BuildSnapshot>>(emptySnapshot));
    ASSERT_TRUE(enable(repository, manager));
    auto first = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(first));
    manager.publish(std::get<std::shared_ptr<const BuildSnapshot>>(first));
    const auto old = manager.acquire();
    EXPECT_TRUE(manager.allowsIssuance(old, kBuildId));
    ASSERT_TRUE(repository.revokeAndPublish(kBuildId, admin(), manager, validationContext()));
    EXPECT_FALSE(manager.allowsIssuance(old, kBuildId));
    EXPECT_TRUE(manager.acquire() != old);
    EXPECT_TRUE(manager.acquire()->find(kBuildId) == nullptr);
    EXPECT_TRUE(old->find(kBuildId) != nullptr);
}

TEST(CloudMaterialSnapshot, RevokePublicationFailureFailsClosedBeforeAcknowledgment) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    ASSERT_TRUE(repository.importBuild(validRecord(), admin()));
    auto empty = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(empty));
    SnapshotManager manager(std::get<std::shared_ptr<const BuildSnapshot>>(empty));
    ASSERT_TRUE(enable(repository, manager));
    auto loaded = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(loaded));
    (void)loaded;
    RepositoryTestAccess::failNextPublish(manager);
    EXPECT_FALSE(repository.revokeAndPublish(kBuildId, admin(), manager, validationContext()));
    EXPECT_FALSE(manager.ready());
    EXPECT_TRUE(manager.acquire()->find(kBuildId) == nullptr);
    EXPECT_TRUE(repository.listEnabled().empty());
}

TEST(CloudMaterialSnapshot, EnableAndRevokeRejectWrongSoftwareOrScope) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    ASSERT_TRUE(repository.importBuild(validRecord(), admin()));
    auto loaded = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(loaded));
    SnapshotManager manager(std::get<std::shared_ptr<const BuildSnapshot>>(loaded));
    EXPECT_FALSE(repository.enableAndPublish(kBuildId, kArtifactHash, kArtifactEvidence,
        AdminPrincipal{.software_id = "other.software", .scopes = {"build.publish"}},
        manager, validationContext()));
    EXPECT_FALSE(repository.enableAndPublish(kBuildId, kArtifactHash, kArtifactEvidence,
        AdminPrincipal{.software_id = "test.software", .scopes = {"build.revoke"}},
        manager, validationContext()));
    ASSERT_TRUE(enable(repository, manager));
    EXPECT_FALSE(repository.revokeAndPublish(kBuildId,
        AdminPrincipal{.software_id = "other.software", .scopes = {"build.revoke"}},
        manager, validationContext()));
}

TEST(CloudMaterialSnapshot, RejectsInvalidStoredArtifactHash) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    ASSERT_TRUE(repository.importBuild(validRecord(), admin()));
    auto loaded = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(loaded));
    SnapshotManager manager(std::get<std::shared_ptr<const BuildSnapshot>>(loaded));
    ASSERT_TRUE(enable(repository, manager));
    RepositoryTestAccess::setArtifactHash(repository, kBuildId, std::string(64, 'G'));
    auto invalid = BuildSnapshot::load(repository, validationContext());
    EXPECT_TRUE(std::holds_alternative<SnapshotError>(invalid));
}

TEST(CloudMaterialSnapshot, RegistrationSizePolicyUsesProtocolCapsWithoutLargeAllocations) {
    EXPECT_TRUE(registrationSizeAllowed(4 * 1024 * 1024, 512 * 1024 * 1024, {192 * 1024 * 1024}));
    EXPECT_FALSE(registrationSizeAllowed(4 * 1024 * 1024 + 1, 1, {1}));
    EXPECT_FALSE(registrationSizeAllowed(1, 512 * 1024 * 1024 + 1, {1}));
    EXPECT_FALSE(registrationSizeAllowed(1, 1, {192 * 1024 * 1024 + 1}));
    EXPECT_FALSE(registrationSizeAllowed(1, 1, {}));
    EXPECT_FALSE(registrationSizeAllowed(1, 1, std::vector<size_t>(4097, 1)));
}

TEST(CloudMaterialSnapshot, SQLiteReadErrorsNeverReturnPartialSnapshot) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    auto initial = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(initial));
    SnapshotManager manager(std::get<std::shared_ptr<const BuildSnapshot>>(initial));
    ASSERT_TRUE(repository.importBuild(validRecord(), admin()));
    ASSERT_TRUE(enable(repository, manager));
    RepositoryTestAccess::failListEnabledAfterRows(repository, 0);
    auto failed = BuildSnapshot::load(repository, validationContext());
    EXPECT_TRUE(std::holds_alternative<SnapshotError>(failed));
    EXPECT_TRUE(manager.acquire()->find(kBuildId) != nullptr);
    RepositoryTestAccess::failListEnabledAfterRows(repository, 1);
    failed = BuildSnapshot::load(repository, validationContext());
    EXPECT_TRUE(std::holds_alternative<SnapshotError>(failed));
    RepositoryTestAccess::failSidecarsAfterRows(repository, 0);
    failed = BuildSnapshot::load(repository, validationContext());
    EXPECT_TRUE(std::holds_alternative<SnapshotError>(failed));
}

TEST(CloudMaterialSnapshot, RevokeWaitsForInFlightIssuanceGuard) {
    TempDatabase db;
    SqliteBuildRepository repository(db.path.string(), validationContext());
    ASSERT_TRUE(repository.importBuild(validRecord(), admin()));
    auto loaded = BuildSnapshot::load(repository, validationContext());
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(loaded));
    SnapshotManager manager(std::get<std::shared_ptr<const BuildSnapshot>>(loaded));
    ASSERT_TRUE(enable(repository, manager));
    auto handle = manager.acquire();
    auto guard = manager.beginIssuance(handle, kBuildId);
    ASSERT_TRUE(static_cast<bool>(guard));
    std::mutex mutex;
    std::condition_variable condition;
    bool entered = false;
    bool revokeDone = false;
    std::thread revoker([&] {
        {
            std::lock_guard lock(mutex);
            entered = true;
        }
        condition.notify_all();
        const bool result = repository.revokeAndPublish(kBuildId, admin(), manager,
                                                        validationContext());
        std::lock_guard lock(mutex);
        revokeDone = result;
        condition.notify_all();
    });
    {
        std::unique_lock lock(mutex);
        condition.wait(lock, [&] { return entered; });
        lock.unlock();
        RepositoryTestAccess::waitUntilBlocked(manager, kBuildId);
        lock.lock();
        EXPECT_FALSE(condition.wait_for(lock, std::chrono::milliseconds(25), [&] { return revokeDone; }));
    }
    guard.finishCommit();
    revoker.join();
    EXPECT_TRUE(revokeDone);
    EXPECT_FALSE(manager.allowsIssuance(handle, kBuildId));
}

} // namespace

int main() {
    using Test = void (*)();
    const std::pair<const char *, Test> tests[] = {
        {"ImportIsIdempotentAndRejectsIdentityConflict", CloudMaterialSnapshot_ImportIsIdempotentAndRejectsIdentityConflict},
        {"SameDomWithDifferentCanonicalBytesConflicts", CloudMaterialSnapshot_SameDomWithDifferentCanonicalBytesConflicts},
        {"ExactCanonicalRegistrationBytesDefineIdentity", CloudMaterialSnapshot_ExactCanonicalRegistrationBytesDefineIdentity},
        {"RejectsRegistrationNestingBeyondProtocolLimit", CloudMaterialSnapshot_RejectsRegistrationNestingBeyondProtocolLimit},
        {"RejectsU32OverflowAndOverlongIntegerTokens", CloudMaterialSnapshot_RejectsU32OverflowAndOverlongIntegerTokens},
        {"RejectsGeneralArraysOverWireLimit", CloudMaterialSnapshot_RejectsGeneralArraysOverWireLimit},
        {"MissingRegistrationValidatorFailsClosed", CloudMaterialSnapshot_MissingRegistrationValidatorFailsClosed},
        {"ThrowingPairValidatorReturnsSnapshotError", CloudMaterialSnapshot_ThrowingPairValidatorReturnsSnapshotError},
        {"ThrowingValidatorAfterEnableFailsClosed", CloudMaterialSnapshot_ThrowingValidatorAfterEnableFailsClosed},
        {"ThrowingValidatorAfterRevokeFailsClosed", CloudMaterialSnapshot_ThrowingValidatorAfterRevokeFailsClosed},
        {"MigrationUsesIntegerTimestampDefault", CloudMaterialSnapshot_MigrationUsesIntegerTimestampDefault},
        {"ArtifactEnableRequiresTrustedVerifierAndEvidence", CloudMaterialSnapshot_ArtifactEnableRequiresTrustedVerifierAndEvidence},
        {"ArtifactVerifierRejectsMismatchedBuildHashEvidence", CloudMaterialSnapshot_ArtifactVerifierRejectsMismatchedBuildHashEvidence},
        {"RejectsInvalidAdminSoftwareIdBeforeSqliteBinding", CloudMaterialSnapshot_RejectsInvalidAdminSoftwareIdBeforeSqliteBinding},
        {"RejectsOversizedStoredBlobBeforeSnapshotCopy", CloudMaterialSnapshot_RejectsOversizedStoredBlobBeforeSnapshotCopy},
        {"RejectsInvalidMembershipAndUnauthorizedAdmin", CloudMaterialSnapshot_RejectsInvalidMembershipAndUnauthorizedAdmin},
        {"FailedValidationLeavesNoPartialImport", CloudMaterialSnapshot_FailedValidationLeavesNoPartialImport},
        {"FailedTransactionRollsBackBuildAndSidecars", CloudMaterialSnapshot_FailedTransactionRollsBackBuildAndSidecars},
        {"EnableAndRevokeAreDurableStateTransitions", CloudMaterialSnapshot_EnableAndRevokeAreDurableStateTransitions},
        {"LoadRejectsCorruptEnabledBuildWithoutPublishingPartialSnapshot", CloudMaterialSnapshot_LoadRejectsCorruptEnabledBuildWithoutPublishingPartialSnapshot},
        {"PinnedGenerationRemainsImmutableAcrossPublish", CloudMaterialSnapshot_PinnedGenerationRemainsImmutableAcrossPublish},
        {"RevokePublicationFailureFailsClosedBeforeAcknowledgment", CloudMaterialSnapshot_RevokePublicationFailureFailsClosedBeforeAcknowledgment},
        {"EnableAndRevokeRejectWrongSoftwareOrScope", CloudMaterialSnapshot_EnableAndRevokeRejectWrongSoftwareOrScope},
        {"RejectsInvalidStoredArtifactHash", CloudMaterialSnapshot_RejectsInvalidStoredArtifactHash},
        {"RegistrationSizePolicyUsesProtocolCapsWithoutLargeAllocations", CloudMaterialSnapshot_RegistrationSizePolicyUsesProtocolCapsWithoutLargeAllocations},
        {"SQLiteReadErrorsNeverReturnPartialSnapshot", CloudMaterialSnapshot_SQLiteReadErrorsNeverReturnPartialSnapshot},
        {"RevokeWaitsForInFlightIssuanceGuard", CloudMaterialSnapshot_RevokeWaitsForInFlightIssuanceGuard},
    };
    unsigned failed_tests = 0;
    for (const auto &[name, test] : tests) {
        const unsigned before = state.failures;
        state.test_name = name;
        test();
        if (state.failures != before) {
            ++failed_tests;
            std::fprintf(stderr, "[FAIL] %s\n", name);
        } else {
            std::fprintf(stdout, "[PASS] %s\n", name);
        }
    }
    std::fprintf(stdout, "%zu tests, %u assertions, %u failures\n",
                 std::size(tests), state.assertions, state.failures);
    return failed_tests == 0 ? 0 : 1;
}
