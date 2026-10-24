#include "runtime_admin.h"

#include <cstdio>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sqlite3.h>
#include <string>
#include <vector>

namespace {
using namespace xovm::cloud_material;

struct TestState {
    unsigned assertions = 0;
    unsigned failures = 0;
    const char *name = "";
};

TestState state;

bool expect(bool condition, const char *expression, int line) {
    ++state.assertions;
    if (condition) return true;
    ++state.failures;
    std::fprintf(stderr, "line %d: %s failed in %s\n", line, expression, state.name);
    return false;
}

#define EXPECT_TRUE(expression) expect(static_cast<bool>(expression), #expression, __LINE__)
#define EXPECT_FALSE(expression) expect(!static_cast<bool>(expression), "! (" #expression ")", __LINE__)
#define TEST(name) static void name()

constexpr char kBuild[] = "1111111111111111111111111111111111111111111111111111111111111111";
constexpr char kRegion[] = "2222222222222222222222222222222222222222222222222222222222222222";
constexpr char kArtifact[] = "3333333333333333333333333333333333333333333333333333333333333333";

std::string base64(std::string_view input) {
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    for (std::size_t i = 0; i < input.size(); i += 3) {
        const auto a = static_cast<unsigned char>(input[i]);
        const auto b = i + 1 < input.size() ? static_cast<unsigned char>(input[i + 1]) : 0;
        const auto c = i + 2 < input.size() ? static_cast<unsigned char>(input[i + 2]) : 0;
        output.push_back(alphabet[a >> 2]);
        output.push_back(alphabet[((a & 3) << 4) | (b >> 4)]);
        output.push_back(i + 1 < input.size() ? alphabet[((b & 15) << 2) | (c >> 6)] : '=');
        output.push_back(i + 2 < input.size() ? alphabet[c & 63] : '=');
    }
    return output;
}

std::vector<std::byte> bytes(std::string_view value) {
    std::vector<std::byte> result;
    for (const auto character : value) result.push_back(static_cast<std::byte>(character));
    return result;
}

struct Fixture {
    std::filesystem::path database = std::filesystem::temp_directory_path() /
        ("xovm-runtime-admin-" + std::to_string(reinterpret_cast<std::uintptr_t>(this)) + ".sqlite");
    Fixture() {
        std::filesystem::remove(database);
        sqlite3 *db = nullptr;
        sqlite3_open(database.c_str(), &db);
        const auto migration = std::filesystem::path(__FILE__).parent_path().parent_path() /
            "runtime/cloud_material_backend/migrations/001_build_registry.sql";
        std::ifstream input(migration);
        const std::string sql((std::istreambuf_iterator<char>(input)), {});
        sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
        sqlite3_close(db);
    }
    ~Fixture() {
        std::error_code ignored;
        std::filesystem::remove(database, ignored);
        std::filesystem::remove(database.string() + "-wal", ignored);
        std::filesystem::remove(database.string() + "-shm", ignored);
    }
};

ValidationContext validation() {
    return ValidationContext{
        .validate_pair = [](const ImportRecord &record, std::string &) {
            return record.build_id == kBuild && record.software_id == "test.software" &&
                record.verifier_sidecars.contains(kRegion);
        },
        .validate_final_artifact = [](const std::string &, const std::string &hash,
                                      std::span<const std::byte> evidence, std::string &) {
            const auto expected = bytes("evidence");
            return hash == kArtifact && evidence.size() == expected.size() &&
                std::equal(evidence.begin(), evidence.end(), expected.begin());
        },
    };
}

std::string importBody() {
    const auto manifest = std::string("{\"build_id\":\"") + kBuild +
        "\",\"software_id\":\"test.software\"}";
    const auto registration = std::string("{\"build_id\":\"") + kBuild + "\"}";
    const auto sidecar = std::string("{\"") + kRegion + "\":\"" + base64("{}") + "\"}";
    auto result = std::string("{\"final_artifact_hash\":\"") + kArtifact +
        "\",\"private_registration_b64\":\"" + base64(registration) +
        "\",\"public_manifest_b64\":\"" + base64(manifest) +
        "\",\"verifier_sidecars_b64\":\"" + base64(sidecar) + "\"}";
    return result;
}

TEST(runtime_admin_import_enable_revoke_updates_snapshot) {
    Fixture fixture;
    auto context = validation();
    SqliteBuildRepository repository(fixture.database, context);
    auto initial = BuildSnapshot::load(repository, context);
    EXPECT_TRUE(std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(initial));
    if (!std::holds_alternative<std::shared_ptr<const BuildSnapshot>>(initial)) return;
    SnapshotManager manager(std::get<std::shared_ptr<const BuildSnapshot>>(std::move(initial)));
    AnonymousPolicy policy;
    auto configurePolicy = [](const BuildSnapshot &snapshot, AnonymousPolicy &policy,
                              std::string &) {
        snapshot.forEachBuild([&policy](const StoredBuild &build) {
            policy.setRule(build.registration.build_id, AnonymousPolicy::BuildRule{
                .software_id = build.registration.software_id,
                .final_artifact_hash = build.final_artifact_hash,
                .regions = {kRegion},
                .modes = {"lease"},
                .valid_until_ms = 2000,
                .revision = build.policy_revision,
                .request_budget = 4,
                .enabled = true,
            });
        });
        return true;
    };
    RuntimeAdminHandlers handlers(repository, manager, context,
        [](std::string_view operation, std::string_view, std::string_view,
           const std::string &) -> std::variant<AdminPrincipal, BackendError> {
            if (operation == "import" || operation == "enable" || operation == "revoke")
                return AdminPrincipal{"test.software", {"build.publish", "build.revoke"}};
            return BackendError{"unauthorized"};
        }, [](const std::string &, const std::string &) {
            return std::variant<std::vector<std::byte>, BackendError>(bytes("evidence"));
        }, configurePolicy, policy);
    const auto import = importBody();
    const auto imported = handlers.handle("/v2/admin/builds/import",
        std::as_bytes(std::span(import.data(), import.size())), "Bearer admin");
    EXPECT_TRUE(std::holds_alternative<std::vector<std::byte>>(imported));
    const auto enabledBody = std::string("{\"final_artifact_hash\":\"") + kArtifact + "\"}";
    const auto enabled = handlers.handle(std::string("/v2/admin/builds/") + kBuild + "/enable",
        std::as_bytes(std::span(enabledBody.data(), enabledBody.size())), "Bearer admin");
    EXPECT_TRUE(std::holds_alternative<std::vector<std::byte>>(enabled));
    EXPECT_TRUE(manager.acquire()->find(kBuild) != nullptr);
    RequestFacts facts;
    facts.request_id = std::string(64, '4');
    facts.request_digest = std::string(64, '5');
    facts.software_id = "test.software";
    facts.build_id = kBuild;
    facts.final_artifact_hash = kArtifact;
    facts.region_id = kRegion;
    facts.mode = "lease";
    facts.type = "material.issue";
    EXPECT_TRUE(std::holds_alternative<AnonymousGrant>(
        policy.authorize(*manager.acquire(), facts, 1000, 1)));
    const std::string emptyObject = "{}";
    const auto revoked = handlers.handle(std::string("/v2/admin/builds/") + kBuild + "/revoke",
        std::as_bytes(std::span(emptyObject.data(), emptyObject.size())), "Bearer admin");
    EXPECT_TRUE(std::holds_alternative<std::vector<std::byte>>(revoked));
    EXPECT_TRUE(manager.acquire()->find(kBuild) == nullptr);
    EXPECT_TRUE(std::holds_alternative<BackendError>(
        policy.authorize(*manager.acquire(), facts, 1000, 1)));
}

TEST(runtime_admin_rejects_unknown_fields_before_mutation) {
    Fixture fixture;
    auto context = validation();
    SqliteBuildRepository repository(fixture.database, context);
    auto initial = BuildSnapshot::load(repository, context);
    SnapshotManager manager(std::get<std::shared_ptr<const BuildSnapshot>>(std::move(initial)));
    AnonymousPolicy policy;
    RuntimeAdminHandlers handlers(repository, manager, context,
        [](std::string_view, std::string_view, std::string_view, const std::string &)
            -> std::variant<AdminPrincipal, BackendError> {
            return AdminPrincipal{"test.software", {"build.publish", "build.revoke"}};
        }, {}, [](const BuildSnapshot &, AnonymousPolicy &, std::string &) { return true; }, policy);
    const auto body = importBody().substr(0, importBody().size() - 1) + ",\"extra\":true}";
    const auto result = handlers.handle("/v2/admin/builds/import",
        std::as_bytes(std::span(body.data(), body.size())), "Bearer admin");
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    EXPECT_TRUE(repository.listEnabled().empty());
}

template <typename Test>
void run(const char *name, Test test) {
    const auto before = state.failures;
    state.name = name;
    test();
    std::fprintf(state.failures == before ? stdout : stderr, "[%s] %s\n",
                 state.failures == before ? "PASS" : "FAIL", name);
}
} // namespace

int main() {
    run("runtime_admin_import_enable_revoke_updates_snapshot",
        runtime_admin_import_enable_revoke_updates_snapshot);
    run("runtime_admin_rejects_unknown_fields_before_mutation",
        runtime_admin_rejects_unknown_fields_before_mutation);
    std::fprintf(stdout, "2 tests, %u assertions, %u failures\n", state.assertions, state.failures);
    return state.failures == 0 ? 0 : 1;
}
