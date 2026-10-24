#include "admin_repository.h"

#include "build_snapshot.h"

#include <sqlite3.h>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>

#include <fstream>
#include <variant>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <limits>
#include <algorithm>
#include <span>
#include <cctype>
#include <cstring>
#include <span>

namespace xovm::cloud_material {
namespace {

struct Statement {
    sqlite3_stmt *value = nullptr;
    ~Statement() { sqlite3_finalize(value); }
};

bool exec(sqlite3 *db, const char *sql) {
    return sqlite3_exec(db, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool prepare(sqlite3 *db, const char *sql, Statement &statement) {
    return sqlite3_prepare_v2(db, sql, -1, &statement.value, nullptr) == SQLITE_OK;
}

bool bindText(sqlite3_stmt *statement, int index, const std::string &value) {
    return sqlite3_bind_text(statement, index, value.data(), static_cast<int>(value.size()),
                             SQLITE_TRANSIENT) == SQLITE_OK;
}

bool validHash(const std::string &value) {
    if (value.size() != 64) return false;
    for (char c : value)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

bool validSoftwareId(const std::string &value) {
    if (value.empty() || value.size() > 64) return false;
    auto validFirst = [](unsigned char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9');
    };
    if (!validFirst(static_cast<unsigned char>(value.front()))) return false;
    return std::all_of(value.begin() + 1, value.end(), [&](unsigned char c) {
        return validFirst(c) || c == '.' || c == '_' || c == '-';
    });
}

bool authorized(const AdminPrincipal &principal, const std::string &softwareId,
                const char *scope) {
    return principal.software_id == softwareId && principal.scopes.find(scope) != principal.scopes.end();
}

class CanonicalScanner {
public:
    explicit CanonicalScanner(std::span<const std::byte> input, unsigned regionArrayDepth = 0)
        : input_(input), region_array_depth_(regionArrayDepth) {}
    bool parse() { return value(0) && position_ == input_.size(); }
private:
    unsigned char at() const { return std::to_integer<unsigned char>(input_[position_]); }
    bool string(std::string *decoded = nullptr) {
        if (position_ == input_.size() || at() != '"') return false;
        ++position_;
        std::string key;
        while (position_ < input_.size() && at() != '"') {
            const unsigned char c = at();
            if (c < 0x20 || c > 0x7e) return false;
            if (c == '\\') {
                ++position_;
                if (position_ == input_.size() || (at() != '\\' && at() != '"')) return false;
            }
            key.push_back(static_cast<char>(at()));
            ++position_;
        }
        if (position_ == input_.size()) return false;
        ++position_;
        if (decoded) {
            if (key.empty() || !((key.front() >= 'a' && key.front() <= 'z'))) return false;
            for (char c : key)
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return false;
            *decoded = std::move(key);
        }
        return true;
    }
    bool value(unsigned depth, size_t arrayLimit = 256) {
        if (position_ == input_.size() || depth > 8) return false;
        const unsigned char c = at();
        if (c == '"') return string();
        if (c == '{') {
            ++position_;
            if (position_ < input_.size() && at() == '}') { ++position_; return true; }
            std::string previous;
            for (size_t count = 0; count < 40; ++count) {
                std::string key;
                if (!string(&key) || (!previous.empty() && key <= previous) ||
                    position_ == input_.size() || at() != ':') return false;
                previous = std::move(key);
                ++position_;
                const size_t arrayLimit = depth == 0 && previous == "regions" ? 4096 :
                    depth == region_array_depth_ &&
                        (previous == "instruction_offsets" || previous == "logical_opcodes")
                            ? 8388608 : 256;
                if (!value(depth + 1, arrayLimit) || position_ == input_.size()) return false;
                if (at() == '}') { ++position_; return true; }
                if (at() != ',') return false;
                ++position_;
            }
            return false;
        }
        if (c == '[') {
            ++position_;
            if (position_ < input_.size() && at() == ']') { ++position_; return true; }
            for (size_t count = 0; count < arrayLimit; ++count) {
                if (!value(depth + 1) || position_ == input_.size()) return false;
                if (at() == ']') { ++position_; return true; }
                if (at() != ',') return false;
                ++position_;
            }
            return false;
        }
        if (c >= '0' && c <= '9') {
            if (c == '0') { ++position_; return position_ == input_.size() || !digit(at()); }
            std::uint32_t number = 0;
            while (position_ < input_.size() && digit(at())) {
                const std::uint32_t next = static_cast<std::uint32_t>(at() - '0');
                if (number > (std::numeric_limits<std::uint32_t>::max() - next) / 10)
                    return false;
                number = number * 10 + next;
                ++position_;
            }
            return true;
        }
        for (auto literal : {std::string_view("true"), std::string_view("false")}) {
            if (input_.size() - position_ >= literal.size() &&
                std::equal(literal.begin(), literal.end(), input_.begin() + position_,
                    [](char left, std::byte right) { return left == std::to_integer<unsigned char>(right); })) {
                position_ += literal.size();
                return true;
            }
        }
        return false;
    }
    static bool digit(unsigned char c) { return c >= '0' && c <= '9'; }
    std::span<const std::byte> input_;
    size_t position_ = 0;
    unsigned region_array_depth_;
};

bool canonicalBytes(std::span<const std::byte> bytes, size_t maximum,
                    unsigned regionArrayDepth = 0) {
    return !bytes.empty() && bytes.size() <= maximum &&
           CanonicalScanner(bytes, regionArrayDepth).parse();
}

void appendField(std::string &output, std::string_view field) {
    const std::uint64_t size = field.size();
    for (unsigned shift = 0; shift < 64; shift += 8)
        output.push_back(static_cast<char>((size >> shift) & 0xff));
    output.append(field);
}

std::vector<unsigned char> digest(const ImportRecord &record) {
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (!context || EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(context);
        return {};
    }
    auto updateField = [&](std::string_view field) {
        const std::uint64_t size = field.size();
        unsigned char encodedSize[8];
        for (unsigned index = 0; index < 8; ++index)
            encodedSize[index] = static_cast<unsigned char>(size >> (56 - index * 8));
        return EVP_DigestUpdate(context, encodedSize, sizeof(encodedSize)) == 1 &&
               EVP_DigestUpdate(context, field.data(), field.size()) == 1;
    };
    bool ok = updateField(record.build_id) && updateField(record.software_id) &&
        updateField(std::string_view(reinterpret_cast<const char *>(record.public_manifest.data()), record.public_manifest.size())) &&
        updateField(std::string_view(reinterpret_cast<const char *>(record.private_registration.data()), record.private_registration.size()));
    for (const auto &[region, verifier] : record.verifier_sidecars) {
        ok = ok && updateField(region) && updateField(std::string_view(
            reinterpret_cast<const char *>(verifier.data()), verifier.size()));
    }
    unsigned int size = 0;
    std::vector<unsigned char> result(32);
    ok = ok && EVP_DigestFinal_ex(context, result.data(), &size) == 1 && size == 32;
    EVP_MD_CTX_free(context);
    if (!ok) return {};
    return result;
}

std::string columnText(sqlite3_stmt *statement, int column) {
    const auto *text = sqlite3_column_text(statement, column);
    const int size = sqlite3_column_bytes(statement, column);
    return text ? std::string(reinterpret_cast<const char *>(text), size) : std::string{};
}

} // namespace

struct SqliteBuildRepository::Impl {
    sqlite3 *db = nullptr;
    ValidationContext validation;
    int fail_sidecars_after = -1;
    int fail_rows_after = -1;
    int fail_sidecar_rows_after = -1;
    std::string corrupt_artifact_hash;
    std::string corrupt_verifier_build;
    std::string corrupt_verifier_region;
};

struct RepositoryTestAccess {
    static void failAfterSidecarInsert(SqliteBuildRepository &repository, int count) {
        repository.testFailSidecarsAfter(count);
    }
    static void failListEnabledAfterRows(SqliteBuildRepository &repository, int count) {
        repository.testFailRowsAfter(count);
    }
    static void corruptVerifier(SqliteBuildRepository &repository, const std::string &build,
                                const std::string &region) {
        repository.testCorruptVerifier(build, region);
    }
    static void setArtifactHash(SqliteBuildRepository &repository, const std::string &build,
                                const std::string &hash) {
        repository.testSetArtifactHash(build, hash);
    }
    static void oversizeManifest(SqliteBuildRepository &repository, const std::string &build) {
        repository.testOversizePublicManifest(build);
    }
    static void failNextPublish(SnapshotManager &manager) { manager.failNextPublishForTest(); }
};

SqliteBuildRepository::SqliteBuildRepository(const std::filesystem::path &databasePath,
                                             ValidationContext validation)
    : impl_(new Impl{nullptr, std::move(validation)}) {
    if (sqlite3_open_v2(databasePath.c_str(), &impl_->db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                        nullptr) != SQLITE_OK)
        throw std::runtime_error("sqlite_open_failed");
    sqlite3_busy_timeout(impl_->db, 5000);
    const auto migrationPath = std::filesystem::path(__FILE__).parent_path() /
                               "migrations/001_build_registry.sql";
    std::ifstream input(migrationPath);
    const std::string sql((std::istreambuf_iterator<char>(input)), {});
        if (sql.empty() || !exec(impl_->db, sql.c_str()))
            throw std::runtime_error("sqlite_migration_failed");
}

std::variant<std::monostate, BackendError> SqliteBuildRepository::checkSchema(
    const std::filesystem::path &databasePath) {
    sqlite3 *db = nullptr;
    if (sqlite3_open_v2(databasePath.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
                        nullptr) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return BackendError{"database_unavailable"};
    }
    const char *query = "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1";
    sqlite3_stmt *statement = nullptr;
    bool valid = sqlite3_prepare_v2(db, query, -1, &statement, nullptr) == SQLITE_OK;
    std::map<std::string, std::string> definitions;
    for (const char *table : {"builds", "verifier_sidecars"}) {
        if (!valid || sqlite3_reset(statement) != SQLITE_OK ||
            sqlite3_bind_text(statement, 1, table, -1, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_step(statement) != SQLITE_ROW) {
            valid = false;
            break;
        }
        const auto *sql = sqlite3_column_text(statement, 0);
        if (!sql) {
            valid = false;
            break;
        }
        definitions.emplace(table, reinterpret_cast<const char *>(sql));
    }
    if (statement) sqlite3_finalize(statement);
    sqlite3_close(db);
    const auto &builds = definitions["builds"];
    const auto &sidecars = definitions["verifier_sidecars"];
    constexpr std::string_view buildColumns[] = {
        "build_id", "software_id", "public_manifest", "private_registration",
        "identity_hash", "state", "final_artifact_hash", "policy_revision"};
    constexpr std::string_view sidecarColumns[] = {
        "build_id", "region_id", "verifier", "verifier_hash"};
    const auto containsColumns = [](const std::string &definition,
                                    const auto &columns) {
        return std::all_of(std::begin(columns), std::end(columns),
            [&definition](std::string_view column) {
                return definition.find(std::string(column)) != std::string::npos;
            });
    };
    if (!valid || definitions.size() != 2 ||
        !containsColumns(builds, buildColumns) ||
        !containsColumns(sidecars, sidecarColumns))
        return BackendError{"database_schema_invalid"};
    return std::monostate{};
}

SqliteBuildRepository::~SqliteBuildRepository() {
    if (impl_) {
        sqlite3_close(impl_->db);
        delete impl_;
    }
}

bool SqliteBuildRepository::importBuild(const ImportRecord &record,
                                        const AdminPrincipal &principal) {
    std::vector<size_t> regionSizes;
    for (const auto &[region, bytes] : record.verifier_sidecars) regionSizes.push_back(bytes.size());
    if (!registrationSizeAllowed(record.public_manifest.size(), record.private_registration.size(), regionSizes) ||
        !canonicalBytes(std::span<const std::byte>(record.public_manifest), kMaxPublicManifestBytes) ||
        !canonicalBytes(std::span<const std::byte>(record.private_registration), kMaxPrivateRegistrationBytes, 2)) return false;
    if (!validHash(record.build_id) || !validSoftwareId(record.software_id) ||
        !validSoftwareId(principal.software_id) ||
        record.verifier_sidecars.empty() || record.verifier_sidecars.size() > 4096 ||
        !authorized(principal, record.software_id, "build.publish") ||
        !impl_->validation.validate_pair) return false;
    std::string validationError;
    if (!impl_->validation.validate_pair(record, validationError)) return false;
    for (const auto &[region, verifier] : record.verifier_sidecars) {
        if (!validHash(region) || verifier.empty() || verifier.size() > kMaxCanonicalRegionBytes ||
            !canonicalBytes(std::span<const std::byte>(verifier), kMaxCanonicalRegionBytes, 0)) return false;
    }
    const auto identity = digest(record);
    if (identity.size() != 32 || !exec(impl_->db, "BEGIN IMMEDIATE")) return false;
    bool ok = false;
    do {
        Statement find;
        if (!prepare(impl_->db, "SELECT identity_hash FROM builds WHERE build_id=?1", find) ||
            !bindText(find.value, 1, record.build_id)) break;
        const int found = sqlite3_step(find.value);
        if (found == SQLITE_ROW) {
            ok = sqlite3_column_bytes(find.value, 0) == 32 &&
                 std::equal(identity.begin(), identity.end(),
                            static_cast<const unsigned char *>(sqlite3_column_blob(find.value, 0)));
            break;
        }
        if (found != SQLITE_DONE) break;
        Statement insert;
        if (!prepare(impl_->db,
                "INSERT INTO builds(build_id,software_id,public_manifest,private_registration,"
                "identity_hash,state,policy_revision) VALUES(?1,?2,?3,?4,?5,'pending',1)", insert) ||
            !bindText(insert.value, 1, record.build_id) ||
            !bindText(insert.value, 2, record.software_id) ||
            sqlite3_bind_blob(insert.value, 3, record.public_manifest.data(), static_cast<int>(record.public_manifest.size()), SQLITE_TRANSIENT) != SQLITE_OK ||
            sqlite3_bind_blob(insert.value, 4, record.private_registration.data(), static_cast<int>(record.private_registration.size()), SQLITE_TRANSIENT) != SQLITE_OK ||
            sqlite3_bind_blob(insert.value, 5, identity.data(), static_cast<int>(identity.size()),
                              SQLITE_TRANSIENT) != SQLITE_OK ||
            sqlite3_step(insert.value) != SQLITE_DONE) break;
        bool sidecarsOk = true;
        size_t insertedSidecars = 0;
        for (const auto &[region, verifier] : record.verifier_sidecars) {
            std::vector<unsigned char> verifierHash(EVP_MAX_MD_SIZE);
            unsigned int hashSize = 0;
            if (EVP_Digest(verifier.data(), verifier.size(), verifierHash.data(), &hashSize,
                           EVP_sha256(), nullptr) != 1 || hashSize != 32) {
                sidecarsOk = false;
                break;
            }
            Statement sidecar;
            if (!prepare(impl_->db,
                    "INSERT INTO verifier_sidecars(build_id,region_id,verifier,verifier_hash) "
                    "VALUES(?1,?2,?3,?4)", sidecar) ||
                !bindText(sidecar.value, 1, record.build_id) ||
                !bindText(sidecar.value, 2, region) ||
                sqlite3_bind_blob(sidecar.value, 3, verifier.data(),
                                  static_cast<int>(verifier.size()), SQLITE_TRANSIENT) != SQLITE_OK ||
                sqlite3_bind_blob(sidecar.value, 4, verifierHash.data(), 32,
                                  SQLITE_TRANSIENT) != SQLITE_OK ||
                sqlite3_step(sidecar.value) != SQLITE_DONE) {
                sidecarsOk = false;
                break;
            }
            ++insertedSidecars;
            if (impl_->fail_sidecars_after >= 0 && insertedSidecars >= static_cast<size_t>(impl_->fail_sidecars_after)) {
                impl_->fail_sidecars_after = -1;
                sidecarsOk = false;
                break;
            }
        }
        if (!sidecarsOk) break;
        Statement validated;
        if (!prepare(impl_->db,
                "UPDATE builds SET state='validated',policy_revision=policy_revision+1 "
                "WHERE build_id=?1 AND state='pending'", validated) ||
            !bindText(validated.value, 1, record.build_id) ||
            sqlite3_step(validated.value) != SQLITE_DONE || sqlite3_changes(impl_->db) != 1) break;
        ok = true;
    } while (false);
    if (ok) ok = exec(impl_->db, "COMMIT");
    if (!ok) exec(impl_->db, "ROLLBACK");
    return ok;
}

bool SqliteBuildRepository::enableBuild(const std::string &buildId,
                                        const std::string &finalArtifactHash,
                                        std::span<const std::byte> verificationEvidence,
                                        const AdminPrincipal &principal) {
    Statement owner;
    if (!validHash(buildId) || !validHash(finalArtifactHash) ||
        !validSoftwareId(principal.software_id) ||
        principal.scopes.find("build.publish") == principal.scopes.end() ||
        verificationEvidence.empty() || verificationEvidence.size() > kMaxArtifactVerificationEvidenceBytes) return false;
    if (
        !prepare(impl_->db, "SELECT 1 FROM builds WHERE build_id=?1 AND software_id=?2", owner) ||
        !bindText(owner.value, 1, buildId) || !bindText(owner.value, 2, principal.software_id) ||
        sqlite3_step(owner.value) != SQLITE_ROW || !exec(impl_->db, "BEGIN IMMEDIATE")) return false;
    Statement update;
    bool ok = prepare(impl_->db,
        "UPDATE builds SET state='enabled',final_artifact_hash=?1,policy_revision=policy_revision+1 "
        "WHERE build_id=?2 AND software_id=?3 AND state='validated'", update) &&
        bindText(update.value, 1, finalArtifactHash) && bindText(update.value, 2, buildId) &&
        bindText(update.value, 3, principal.software_id) &&
        sqlite3_step(update.value) == SQLITE_DONE && sqlite3_changes(impl_->db) == 1;
    if (ok) ok = exec(impl_->db, "COMMIT");
    if (!ok) exec(impl_->db, "ROLLBACK");
    return ok;
}

bool SqliteBuildRepository::revokeBuild(const std::string &buildId,
                                        const AdminPrincipal &principal) {
    Statement owner;
    if (!validHash(buildId) || !validSoftwareId(principal.software_id) ||
        principal.scopes.find("build.revoke") == principal.scopes.end() ||
        !prepare(impl_->db, "SELECT 1 FROM builds WHERE build_id=?1 AND software_id=?2", owner) ||
        !bindText(owner.value, 1, buildId) || !bindText(owner.value, 2, principal.software_id) ||
        sqlite3_step(owner.value) != SQLITE_ROW || !exec(impl_->db, "BEGIN IMMEDIATE")) return false;
    Statement update;
    bool ok = prepare(impl_->db,
        "UPDATE builds SET state='revoked',policy_revision=policy_revision+1 "
        "WHERE build_id=?1 AND software_id=?2 AND state='enabled'", update) &&
        bindText(update.value, 1, buildId) && bindText(update.value, 2, principal.software_id) &&
        sqlite3_step(update.value) == SQLITE_DONE && sqlite3_changes(impl_->db) == 1;
    if (ok) ok = exec(impl_->db, "COMMIT");
    if (!ok) exec(impl_->db, "ROLLBACK");
    return ok;
}

bool SqliteBuildRepository::enableAndPublish(const std::string &buildId,
    const std::string &artifactHash, std::span<const std::byte> verificationEvidence,
    const AdminPrincipal &principal,
    SnapshotManager &manager, ValidationContext validation) {
    if (!impl_->validation.validate_final_artifact || verificationEvidence.empty() ||
        verificationEvidence.size() > kMaxArtifactVerificationEvidenceBytes ||
        !validHash(buildId) || !validHash(artifactHash) ||
        !validSoftwareId(principal.software_id) ||
        principal.scopes.find("build.publish") == principal.scopes.end()) return false;
    std::string verificationError;
    bool verified = false;
    try {
        verified = impl_->validation.validate_final_artifact(buildId, artifactHash,
                                                              verificationEvidence, verificationError);
    } catch (...) {
        return false;
    }
    if (!verified ||
        !enableBuild(buildId, artifactHash, verificationEvidence, principal)) return false;
    auto loaded = BuildSnapshot::load(*this, validation);
    if (!std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(loaded)) {
        manager.failClosed();
        return false;
    }
    try { manager.publish(std::get<std::shared_ptr<const BuildSnapshot>>(std::move(loaded))); }
    catch (...) { manager.failClosed(); return false; }
    return true;
}

bool SqliteBuildRepository::importEnableAndPublish(const ImportRecord &record,
    const AdminPrincipal &principal, const std::string &artifactHash,
    std::span<const std::byte> verificationEvidence,
    SnapshotManager &manager, ValidationContext validation) {
    // Import remains durable if the later, separately verified enable transition fails.
    if (!importBuild(record, principal)) return false;
    return enableAndPublish(record.build_id, artifactHash, verificationEvidence, principal,
                            manager, std::move(validation));
}

bool SqliteBuildRepository::revokeAndPublish(const std::string &buildId,
                                             const AdminPrincipal &principal,
                                             SnapshotManager &manager,
                                             ValidationContext validation) {
    if (!manager.blockBuildWhile(buildId, [&] { return revokeBuild(buildId, principal); }))
        return false;
    auto loaded = BuildSnapshot::load(*this, validation);
    if (auto *error = std::get_if<SnapshotError>(&loaded)) {
        (void)error;
        manager.failClosed();
        return false;
    }
    try {
        manager.publish(std::get<std::shared_ptr<const BuildSnapshot>>(std::move(loaded)));
    } catch (...) {
        manager.failClosed();
        return false;
    }
    return true;
}

std::vector<StoredBuild> SqliteBuildRepository::listEnabled() const {
    std::vector<StoredBuild> result;
    Statement query;
    if (!prepare(impl_->db,
        "SELECT build_id,software_id,public_manifest,private_registration,final_artifact_hash,"
        "policy_revision FROM builds WHERE state='enabled' ORDER BY build_id", query))
        throw std::runtime_error("sqlite_build_query_failed");
    size_t rows = 0;
    int rowStatus;
    while ((rowStatus = sqlite3_step(query.value)) == SQLITE_ROW) {
        if (impl_->fail_rows_after == 0) {
            impl_->fail_rows_after = -1;
            throw std::runtime_error("sqlite_build_read_injected_failure");
        }
        ++rows;
        StoredBuild build;
        build.registration.build_id = columnText(query.value, 0);
        build.registration.software_id = columnText(query.value, 1);
        auto copyBlob = [&](int column, std::vector<std::byte> &output) {
            const auto *data = static_cast<const std::byte *>(sqlite3_column_blob(query.value, column));
            const int size = sqlite3_column_bytes(query.value, column);
            const size_t maximum = column == 2 ? kMaxPublicManifestBytes : kMaxPrivateRegistrationBytes;
            if (!data || size <= 0 || static_cast<size_t>(size) > maximum)
                throw std::runtime_error("invalid_stored_registration");
            output.assign(data, data + size);
        };
        copyBlob(2, build.registration.public_manifest);
        copyBlob(3, build.registration.private_registration);
        build.final_artifact_hash = columnText(query.value, 4);
        build.policy_revision = static_cast<std::uint64_t>(sqlite3_column_int64(query.value, 5));
        Statement sidecars;
        if (!prepare(impl_->db,
            "SELECT region_id,verifier,verifier_hash FROM verifier_sidecars "
            "WHERE build_id=?1 ORDER BY region_id",
            sidecars) || !bindText(sidecars.value, 1, build.registration.build_id))
            throw std::runtime_error("sqlite_sidecar_query_failed");
        int sidecarStatus;
        size_t sidecarRows = 0;
        size_t sidecarBytes = 0;
        while ((sidecarStatus = sqlite3_step(sidecars.value)) == SQLITE_ROW) {
            if (sidecarRows >= kMaxRegisteredRegions)
                throw std::runtime_error("too_many_stored_sidecars");
            if (impl_->fail_sidecar_rows_after == 0) {
                impl_->fail_sidecar_rows_after = -1;
                throw std::runtime_error("sqlite_sidecar_read_injected_failure");
            }
            if (impl_->fail_sidecar_rows_after > 0 &&
                ++sidecarRows >= static_cast<size_t>(impl_->fail_sidecar_rows_after)) {
                impl_->fail_sidecar_rows_after = -1;
                throw std::runtime_error("sqlite_sidecar_read_injected_failure");
            }
            const auto *data = static_cast<const std::byte *>(sqlite3_column_blob(sidecars.value, 1));
            const int size = sqlite3_column_bytes(sidecars.value, 1);
            if (!data || size <= 0 || static_cast<size_t>(size) > kMaxCanonicalRegionBytes)
                throw std::runtime_error("invalid_stored_sidecar");
            if (static_cast<size_t>(size) > kMaxPrivateRegistrationBytes - sidecarBytes)
                throw std::runtime_error("stored_sidecar_bytes_exceeded");
            sidecarBytes += static_cast<size_t>(size);
            std::vector<unsigned char> actualHash(EVP_MAX_MD_SIZE);
            unsigned int actualHashSize = 0;
            if (EVP_Digest(data, static_cast<size_t>(size), actualHash.data(), &actualHashSize,
                           EVP_sha256(), nullptr) != 1 || actualHashSize != 32 ||
                sqlite3_column_bytes(sidecars.value, 2) != 32 ||
                sqlite3_column_blob(sidecars.value, 2) == nullptr ||
                !std::equal(actualHash.begin(), actualHash.begin() + 32,
                    static_cast<const unsigned char *>(sqlite3_column_blob(sidecars.value, 2))))
                throw std::runtime_error("stored_sidecar_hash_mismatch");
            build.registration.verifier_sidecars.emplace(columnText(sidecars.value, 0),
                std::vector<std::byte>(data, data + size));
        }
        if (sidecarStatus != SQLITE_DONE) throw std::runtime_error("sqlite_sidecar_read_failed");
        result.push_back(std::move(build));
        if (impl_->fail_rows_after > 0 && rows >= static_cast<size_t>(impl_->fail_rows_after)) {
            impl_->fail_rows_after = -1;
            throw std::runtime_error("sqlite_build_read_injected_failure");
        }
    }
    if (rowStatus != SQLITE_DONE) throw std::runtime_error("sqlite_build_read_failed");
    return result;
}

void SqliteBuildRepository::testCorruptVerifier(const std::string &buildId,
                                                const std::string &regionId) {
    Statement update;
    (void)(prepare(impl_->db,
        "UPDATE verifier_sidecars SET verifier=x'00' WHERE build_id=?1 AND region_id=?2", update) &&
        bindText(update.value, 1, buildId) && bindText(update.value, 2, regionId) &&
        sqlite3_step(update.value) == SQLITE_DONE && sqlite3_changes(impl_->db) == 1);
}

void SqliteBuildRepository::testFailSidecarsAfter(int count) { impl_->fail_sidecars_after = count; }
void SqliteBuildRepository::testFailRowsAfter(int count) { impl_->fail_rows_after = count; }
void SqliteBuildRepository::testFailSidecarRowsAfter(int count) { impl_->fail_sidecar_rows_after = count; }
void SqliteBuildRepository::testSetArtifactHash(const std::string &buildId, const std::string &hash) {
    exec(impl_->db, "PRAGMA ignore_check_constraints=ON");
    Statement update;
    if (prepare(impl_->db, "UPDATE builds SET final_artifact_hash=?1 WHERE build_id=?2", update)) {
        bindText(update.value, 1, hash);
        bindText(update.value, 2, buildId);
        sqlite3_step(update.value);
    }
    exec(impl_->db, "PRAGMA ignore_check_constraints=OFF");
}

void SqliteBuildRepository::testOversizePublicManifest(const std::string &buildId) {
    exec(impl_->db, "PRAGMA ignore_check_constraints=ON");
    exec(impl_->db,
        ("UPDATE builds SET public_manifest=zeroblob(" +
         std::to_string(kMaxPublicManifestBytes + 1) + ") WHERE build_id='" + buildId + "'").c_str());
    exec(impl_->db, "PRAGMA ignore_check_constraints=OFF");
}

} // namespace xovm::cloud_material
