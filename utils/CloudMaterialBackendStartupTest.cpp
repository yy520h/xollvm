#include "startup.h"
#include "http_server.h"
#include "admin_repository.h"
#include "runtime_providers.h"
#include "state_wal.h"
#include "session_state.h"

#include <cstdio>
#include <filesystem>
#include <sqlite3.h>
#include <string>
#include <vector>
#include <unistd.h>
#include <array>
#include <chrono>
#include <future>
#include <memory>

namespace {
using namespace xovm::cloud_material;

struct TestState {
    unsigned assertions = 0;
    unsigned failures = 0;
    const char *test_name = "";
};

TestState state;

bool expect(bool condition, const char *expression, int line) {
    ++state.assertions;
    if (condition) return true;
    ++state.failures;
    std::fprintf(stderr, "line %d: %s failed in %s\n", line, expression, state.test_name);
    return false;
}

#define EXPECT_TRUE(expression) expect(static_cast<bool>(expression), #expression, __LINE__)
#define EXPECT_FALSE(expression) expect(!static_cast<bool>(expression), "! (" #expression ")", __LINE__)
#define TEST(name) static void name()

StartupStages stages(std::vector<std::string> &events) {
    StartupStages result;
    result.load_config = [&events] { events.push_back("config"); return std::monostate{}; };
    result.acquire_lock = [&events] { events.push_back("lock"); return std::monostate{}; };
    result.check_database = [&events] { events.push_back("database"); return std::monostate{}; };
    result.recover_state = [&events] { events.push_back("recovery"); return std::monostate{}; };
    result.validate_snapshot = [&events] { events.push_back("snapshot"); return std::monostate{}; };
    result.check_providers = [&events] { events.push_back("providers"); return std::monostate{}; };
    result.start_listener = [&events] { events.push_back("listener"); return std::monostate{}; };
    return result;
}

TEST(startup_runs_readiness_stages_in_order) {
    std::vector<std::string> events;
    StartupCoordinator coordinator(stages(events));
    auto result = coordinator.start();
    EXPECT_TRUE(std::holds_alternative<std::monostate>(result));
    const std::vector<std::string> expected = {
        "config", "lock", "database", "recovery", "snapshot", "providers", "listener"};
    EXPECT_TRUE(events == expected);
    EXPECT_TRUE(coordinator.ready());
}

TEST(startup_stops_before_listener_when_stage_fails) {
    std::vector<std::string> events;
    auto configured = stages(events);
    configured.validate_snapshot = [&events] {
        events.push_back("snapshot");
        return BackendError{"snapshot_invalid"};
    };
    StartupCoordinator coordinator(std::move(configured));
    auto result = coordinator.start();
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    EXPECT_FALSE(coordinator.ready());
    const std::vector<std::string> expected = {
        "config", "lock", "database", "recovery", "snapshot"};
    EXPECT_TRUE(events == expected);
}

TEST(startup_does_not_run_later_stages_after_lock_failure) {
    std::vector<std::string> events;
    auto configured = stages(events);
    configured.acquire_lock = [&events] {
        events.push_back("lock");
        return BackendError{"lock_busy"};
    };
    StartupCoordinator coordinator(std::move(configured));
    auto result = coordinator.start();
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    const std::vector<std::string> expected = {"config", "lock"};
    EXPECT_TRUE(events == expected);
    EXPECT_FALSE(coordinator.ready());
}

TEST(startup_cannot_start_twice) {
    std::vector<std::string> events;
    StartupCoordinator coordinator(stages(events));
    EXPECT_TRUE(std::holds_alternative<std::monostate>(coordinator.start()));
    auto second = coordinator.start();
    EXPECT_TRUE(std::holds_alternative<BackendError>(second));
    if (std::holds_alternative<BackendError>(second))
        EXPECT_TRUE(std::get<BackendError>(second).code == "startup_already_started");
}

TEST(startup_marks_http_ready_only_after_listener_stage) {
    std::vector<std::string> events;
    HttpServerConfig config;
    config.port = 0;
    config.relay_token = "relay-startup-secret-long-enough";
    config.admin_token = "admin-startup-secret-long-enough";
    HttpServer server(config);
    auto configured = stages(events);
    configured.start_listener = [&events, &server] {
        events.push_back("listener");
        auto result = server.start();
        if (std::holds_alternative<BackendError>(result)) return result;
        server.setReady(true);
        return std::variant<std::monostate, BackendError>{std::monostate{}};
    };
    StartupCoordinator coordinator(std::move(configured));
    EXPECT_TRUE(std::holds_alternative<std::monostate>(coordinator.start()));
    EXPECT_TRUE(coordinator.ready());
    server.stop();
}

TEST(database_schema_check_rejects_uninitialized_database) {
    const auto path = std::filesystem::temp_directory_path() /
        ("xovm-schema-check-" + std::to_string(static_cast<long long>(::getpid())) + ".sqlite");
    std::filesystem::remove(path);
    sqlite3 *db = nullptr;
    EXPECT_TRUE(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
    EXPECT_TRUE(db != nullptr);
    const auto result = SqliteBuildRepository::checkSchema(path);
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    sqlite3_close(db);
    std::filesystem::remove(path);
}

TEST(database_schema_check_rejects_wrong_table_shape) {
    const auto path = std::filesystem::temp_directory_path() /
        ("xovm-schema-shape-" + std::to_string(static_cast<long long>(::getpid())) + ".sqlite");
    std::filesystem::remove(path);
    sqlite3 *db = nullptr;
    EXPECT_TRUE(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
    EXPECT_TRUE(sqlite3_exec(db, "CREATE TABLE builds(id TEXT);"
        "CREATE TABLE verifier_sidecars(id TEXT);", nullptr, nullptr, nullptr) == SQLITE_OK);
    const auto result = SqliteBuildRepository::checkSchema(path);
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    sqlite3_close(db);
    std::filesystem::remove(path);
}

BackendConfig providerConfig() {
    BackendConfig config;
    config.trusted_time_provider = "clock.test";
    config.signing_key_provider = "signer.test";
    config.anonymous_policy_provider = "policy.test";
    config.trust_root_provider = "trust.test";
    return config;
}

TEST(runtime_provider_factory_rejects_unregistered_names) {
    RuntimeProviderFactory::clearForTest();
    const auto result = RuntimeProviderFactory::resolve(providerConfig());
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    if (std::holds_alternative<BackendError>(result))
        EXPECT_TRUE(std::get<BackendError>(result).code == "provider_unavailable");
}

TEST(runtime_provider_factory_requires_all_provider_capabilities) {
    RuntimeProviderFactory::clearForTest();
    RuntimeProviderFactory::registerProvider("clock.test",
        [](ProviderRole, const BackendConfig &) -> std::variant<RuntimeProviderBundle, BackendError> {
            RuntimeProviderBundle bundle;
            bundle.trusted_now = [] {
                return std::variant<std::uint64_t, BackendError>(std::uint64_t{1});
            };
            return bundle;
        });
    RuntimeProviderFactory::registerProvider("signer.test",
        [](ProviderRole, const BackendConfig &) -> std::variant<RuntimeProviderBundle, BackendError> {
            RuntimeProviderBundle bundle;
            bundle.random_bytes = [](std::size_t size) {
                return std::variant<Bytes, BackendError>(Bytes(size, std::byte{1}));
            };
            bundle.sign = [](std::span<const std::uint8_t>) {
                return std::variant<std::array<std::uint8_t, 64>, BackendError>(std::array<std::uint8_t, 64>{});
            };
            bundle.signing.key_id = "test-key";
            bundle.signing.trust_epoch = 1;
            return bundle;
        });
    RuntimeProviderFactory::registerProvider("policy.test",
        [](ProviderRole, const BackendConfig &) -> std::variant<RuntimeProviderBundle, BackendError> {
            RuntimeProviderBundle bundle;
            bundle.validate_pair = [](const ImportRecord &, std::string &) { return true; };
            bundle.authorize_admin = [](std::string_view, std::string_view, std::string_view,
                                       const std::string &) -> std::variant<AdminPrincipal, BackendError> {
                return BackendError{"not_configured"};
            };
            bundle.configure_policy = [](const BuildSnapshot &, AnonymousPolicy &, std::string &) {
                return true;
            };
            bundle.authorize_control = [](const Request &, const RequestFacts &, std::uint64_t) {
                return std::variant<ProtocolService::ControlAuthorization, BackendError>(
                    BackendError{"not_configured"});
            };
            return bundle;
        });
    RuntimeProviderFactory::registerProvider("trust.test",
        [](ProviderRole, const BackendConfig &) -> std::variant<RuntimeProviderBundle, BackendError> {
            return RuntimeProviderBundle{};
        });
    const auto result = RuntimeProviderFactory::resolve(providerConfig());
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    RuntimeProviderFactory::clearForTest();
}

TEST(runtime_provider_factory_merges_all_registered_capabilities) {
    RuntimeProviderFactory::clearForTest();
    bool provide_window_material_builder = false;
    RuntimeProviderFactory::registerProvider("clock.test",
        [](ProviderRole role, const BackendConfig &) -> std::variant<RuntimeProviderBundle, BackendError> {
            if (role != ProviderRole::trusted_time) return BackendError{"provider_role_invalid"};
            RuntimeProviderBundle bundle;
            bundle.trusted_now = [] {
                return std::variant<std::uint64_t, BackendError>(std::uint64_t{1});
            };
            return bundle;
        });
    RuntimeProviderFactory::registerProvider("signer.test",
        [](ProviderRole role, const BackendConfig &) -> std::variant<RuntimeProviderBundle, BackendError> {
            if (role != ProviderRole::signing_key) return BackendError{"provider_role_invalid"};
            RuntimeProviderBundle bundle;
            bundle.random_bytes = [](std::size_t size) {
                return std::variant<Bytes, BackendError>(Bytes(size, std::byte{1}));
            };
            bundle.sign = [](std::span<const std::uint8_t>) {
                return std::variant<std::array<std::uint8_t, 64>, BackendError>(
                    std::array<std::uint8_t, 64>{});
            };
            bundle.signing.key_id = "test-key";
            bundle.signing.trust_epoch = 1;
            return bundle;
        });
    RuntimeProviderFactory::registerProvider("policy.test",
        [&provide_window_material_builder](ProviderRole role, const BackendConfig &)
            -> std::variant<RuntimeProviderBundle, BackendError> {
            if (role != ProviderRole::anonymous_policy) return BackendError{"provider_role_invalid"};
            RuntimeProviderBundle bundle;
            bundle.validate_pair = [](const ImportRecord &, std::string &) { return true; };
            bundle.authorize_admin = [](std::string_view, std::string_view, std::string_view,
                                       const std::string &) -> std::variant<AdminPrincipal, BackendError> {
                return BackendError{"not_configured"};
            };
            bundle.configure_policy = [](const BuildSnapshot &, AnonymousPolicy &, std::string &) {
                return true;
            };
            bundle.authorize_control = [](const Request &, const RequestFacts &, std::uint64_t) {
                return std::variant<ProtocolService::ControlAuthorization, BackendError>(
                    BackendError{"not_configured"});
            };
            bundle.issue = [](const Request &, const AnonymousGrant &,
                              SessionState::Transaction &) -> std::variant<Bytes, BackendError> {
                return BackendError{"not_configured"};
            };
            if (provide_window_material_builder) {
                bundle.build_window_material = [](
                    const xovm::material::WindowAcquireRequest &)
                    -> std::variant<xovm::material::WindowMaterial, BackendError> {
                    xovm::material::WindowMaterial material{};
                    material.window[0] = 1;
                    return material;
                };
            }
            return bundle;
        });
    RuntimeProviderFactory::registerProvider("trust.test",
        [](ProviderRole role, const BackendConfig &) -> std::variant<RuntimeProviderBundle, BackendError> {
            if (role != ProviderRole::trust_root) return BackendError{"provider_role_invalid"};
            RuntimeProviderBundle bundle;
            bundle.validate_final_artifact = [](const std::string &, const std::string &,
                                                std::span<const std::byte>, std::string &) {
                return true;
            };
            bundle.artifact_evidence = [](const std::string &, const std::string &) {
                return std::variant<Bytes, BackendError>(BackendError{"not_configured"});
            };
            bundle.trust_handler = [](std::string_view) -> std::variant<Bytes, BackendError> {
                return BackendError{"not_configured"};
            };
            return bundle;
        });
    const auto disabledResult = RuntimeProviderFactory::resolve(providerConfig());
    EXPECT_TRUE(std::holds_alternative<RuntimeProviderBundle>(disabledResult));
    if (std::holds_alternative<RuntimeProviderBundle>(disabledResult)) {
        const auto &bundle = std::get<RuntimeProviderBundle>(disabledResult);
        EXPECT_TRUE(static_cast<bool>(bundle.trusted_now));
        EXPECT_TRUE(static_cast<bool>(bundle.random_bytes));
        EXPECT_TRUE(static_cast<bool>(bundle.sign));
        EXPECT_TRUE(static_cast<bool>(bundle.validate_pair));
        EXPECT_TRUE(static_cast<bool>(bundle.validate_final_artifact));
        EXPECT_FALSE(static_cast<bool>(bundle.build_window_material));
    }

    auto rawConfig = providerConfig();
    rawConfig.raw_port = 8443;
    const auto missingBuilder = RuntimeProviderFactory::resolve(rawConfig);
    EXPECT_TRUE(std::holds_alternative<BackendError>(missingBuilder));
    if (std::holds_alternative<BackendError>(missingBuilder))
        EXPECT_TRUE(std::get<BackendError>(missingBuilder).code == "provider_unavailable");

    provide_window_material_builder = true;
    auto enabledResult = RuntimeProviderFactory::resolve(rawConfig);
    EXPECT_TRUE(std::holds_alternative<RuntimeProviderBundle>(enabledResult));
    if (std::holds_alternative<RuntimeProviderBundle>(enabledResult)) {
        auto &bundle = std::get<RuntimeProviderBundle>(enabledResult);
        EXPECT_TRUE(static_cast<bool>(bundle.build_window_material));
        static_assert(sizeof(xovm::material::WindowMaterial) == 192);
        static_assert(xovm::material::kWindowMaterialSize == 192);
        xovm::material::WindowAcquireRequest request{};
        request.request_id[0] = 1;
        request.build_id[0] = 2;
        request.region_id[0] = 3;
        request.generation = 4;
        request.window_id = 5;
        request.previous_state_hash[0] = 6;
        const auto material = bundle.build_window_material(request);
        EXPECT_TRUE(std::holds_alternative<xovm::material::WindowMaterial>(material));
        if (std::holds_alternative<xovm::material::WindowMaterial>(material))
            EXPECT_TRUE(sizeof(std::get<xovm::material::WindowMaterial>(material)) ==
                        xovm::material::kWindowMaterialSize);
    }
    RuntimeProviderFactory::clearForTest();
}

TEST(runtime_provider_factory_does_not_hold_registry_lock_during_resolver) {
    RuntimeProviderFactory::clearForTest();
    RuntimeProviderFactory::registerProvider("clock.test",
        [](ProviderRole, const BackendConfig &) -> std::variant<RuntimeProviderBundle, BackendError> {
            RuntimeProviderFactory::registerProvider("nested.test", {});
            return BackendError{"clock_unavailable"};
        });
    auto future = std::async(std::launch::async, [] {
        return RuntimeProviderFactory::resolve(providerConfig());
    });
    EXPECT_TRUE(future.wait_for(std::chrono::seconds(1)) == std::future_status::ready);
    if (future.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
        auto result = future.get();
        EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    }
    RuntimeProviderFactory::clearForTest();
}

TEST(recovered_wal_state_is_restored_before_runtime_use) {
    const auto path = std::filesystem::temp_directory_path() /
        ("xovm-runtime-recovery-" + std::to_string(static_cast<long long>(::getpid())) + ".wal");
    std::filesystem::remove(path);
    StateWal writer(path);
    StateDelta delta;
    const std::string state = R"({"next_counter":7,"retained_bytes":0,"replies":{},"claims":{},"generations":{},"sessions":{}})";
    for (const auto byte : state) delta.bytes.push_back(static_cast<std::byte>(byte));
    const std::vector<std::byte> response{std::byte{'o'}, std::byte{'k'}};
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(writer.appendAndSync(1, delta, response)));
    auto recovered = writer.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (std::holds_alternative<RecoveredState>(recovered)) {
        StateWal runtimeWal(path, {}, std::get<RecoveredState>(recovered).last_sequence);
        SessionState stateStore(&runtimeWal);
        EXPECT_TRUE(std::holds_alternative<std::monostate>(
            stateStore.restore(std::get<RecoveredState>(recovered))));
        EXPECT_TRUE(std::holds_alternative<BackendError>(
            runtimeWal.appendAndSync(1, delta, response)));
    }
    std::filesystem::remove(path);
}

TEST(runtime_provider_factory_allows_explicit_linked_registration_hook) {
    RuntimeProviderFactory::clearForTest();
    RuntimeProviderFactory::registerLinkedProviders();
    const auto result = RuntimeProviderFactory::resolve(providerConfig());
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    RuntimeProviderFactory::clearForTest();
}

template <typename Test>
void run(const char *name, Test test) {
    const unsigned before = state.failures;
    state.test_name = name;
    test();
    std::fprintf(state.failures == before ? stdout : stderr, "[%s] %s\n",
                 state.failures == before ? "PASS" : "FAIL", name);
}
} // namespace

int main() {
    run("startup_runs_readiness_stages_in_order", startup_runs_readiness_stages_in_order);
    run("startup_stops_before_listener_when_stage_fails",
        startup_stops_before_listener_when_stage_fails);
    run("startup_does_not_run_later_stages_after_lock_failure",
        startup_does_not_run_later_stages_after_lock_failure);
    run("startup_cannot_start_twice", startup_cannot_start_twice);
    run("startup_marks_http_ready_only_after_listener_stage",
        startup_marks_http_ready_only_after_listener_stage);
    run("database_schema_check_rejects_uninitialized_database",
        database_schema_check_rejects_uninitialized_database);
    run("database_schema_check_rejects_wrong_table_shape",
        database_schema_check_rejects_wrong_table_shape);
    run("runtime_provider_factory_rejects_unregistered_names",
        runtime_provider_factory_rejects_unregistered_names);
    run("runtime_provider_factory_requires_all_provider_capabilities",
        runtime_provider_factory_requires_all_provider_capabilities);
    run("runtime_provider_factory_merges_all_registered_capabilities",
        runtime_provider_factory_merges_all_registered_capabilities);
    run("runtime_provider_factory_does_not_hold_registry_lock_during_resolver",
        runtime_provider_factory_does_not_hold_registry_lock_during_resolver);
    run("recovered_wal_state_is_restored_before_runtime_use",
        recovered_wal_state_is_restored_before_runtime_use);
    run("runtime_provider_factory_allows_explicit_linked_registration_hook",
        runtime_provider_factory_allows_explicit_linked_registration_hook);
    std::fprintf(stdout, "13 tests, %u assertions, %u failures\n",
                 state.assertions, state.failures);
    return state.failures == 0 ? 0 : 1;
}
