#include "admin_repository.h"
#include "auth_policy.h"
#include "build_snapshot.h"
#include "checkpoint.h"
#include "config.h"
#include "http_server.h"
#include "process_lock.h"
#include "protocol_service.h"
#include "runtime_providers.h"
#include "runtime_admin.h"
#include "session_state.h"
#include "state_wal.h"
#include "startup.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <csignal>
#include <thread>

namespace xovm::cloud_material {

namespace {

std::atomic<bool> stop_requested{false};

void requestStop(int) {
    stop_requested.store(true);
}

struct RuntimeResources {
    BackendConfig config;
    std::unique_ptr<ProcessLock> lock;
    std::unique_ptr<Checkpoint> checkpoint;
    std::unique_ptr<StateWal> wal;
    std::unique_ptr<SessionState> state;
    std::unique_ptr<SqliteBuildRepository> repository;
    std::shared_ptr<const BuildSnapshot> snapshot;
    std::unique_ptr<SnapshotManager> snapshots;
    std::unique_ptr<RelayAuthenticator> relay_authenticator;
    std::unique_ptr<AnonymousPolicy> anonymous_policy;
    RuntimeProviderBundle providers;
    std::unique_ptr<ProtocolService> service;
    std::unique_ptr<RuntimeAdminHandlers> admin;
    std::unique_ptr<HttpServer> server;
};

int run() {
    std::signal(SIGINT, requestStop);
    std::signal(SIGTERM, requestStop);
    RuntimeProviderFactory::registerLinkedProviders();
    RuntimeResources resources;
    StartupStages stages;
    stages.load_config = [&resources]() -> std::variant<std::monostate, BackendError> {
        auto result = BackendConfig::fromEnvironment();
        if (const auto *error = std::get_if<BackendError>(&result)) return *error;
        resources.config = std::get<BackendConfig>(std::move(result));
        return std::variant<std::monostate, BackendError>{std::monostate{}};
    };
    stages.acquire_lock = [&resources]() -> std::variant<std::monostate, BackendError> {
        auto result = ProcessLock::acquire(std::filesystem::path(resources.config.state_dir));
        if (const auto *error = std::get_if<BackendError>(&result)) return *error;
        resources.lock = std::make_unique<ProcessLock>(std::move(std::get<ProcessLock>(result)));
        return std::variant<std::monostate, BackendError>{std::monostate{}};
    };
    stages.check_database = [&resources]() -> std::variant<std::monostate, BackendError> {
        return SqliteBuildRepository::checkSchema(
            std::filesystem::path(resources.config.sqlite_path));
    };
    stages.recover_state = [&resources]() -> std::variant<std::monostate, BackendError> {
        const auto stateDir = std::filesystem::path(resources.config.state_dir);
        resources.checkpoint = std::make_unique<Checkpoint>(
            stateDir / "checkpoint.bin", stateDir / "state.wal");
        auto recovered = resources.checkpoint->recover();
        if (const auto *error = std::get_if<BackendError>(&recovered)) return *error;
        const auto &state = std::get<RecoveredState>(recovered);
        resources.wal = std::make_unique<StateWal>(stateDir / "state.wal", StateWal::IoHooks{},
                                                   state.last_sequence);
        resources.state = std::make_unique<SessionState>(resources.wal.get());
        auto restored = resources.state->restore(state);
        if (const auto *error = std::get_if<BackendError>(&restored)) return *error;
        return std::variant<std::monostate, BackendError>{std::monostate{}};
    };
    stages.validate_snapshot = [&resources]() -> std::variant<std::monostate, BackendError> {
        auto providerResult = RuntimeProviderFactory::resolve(resources.config);
        if (const auto *error = std::get_if<BackendError>(&providerResult)) return *error;
        resources.providers = std::get<RuntimeProviderBundle>(std::move(providerResult));
        ValidationContext validation;
        validation.validate_pair = resources.providers.validate_pair;
        validation.validate_final_artifact = resources.providers.validate_final_artifact;
        try {
            resources.repository = std::make_unique<SqliteBuildRepository>(
                std::filesystem::path(resources.config.sqlite_path), validation);
        } catch (...) {
            return BackendError{"database_unavailable"};
        }
        auto loaded = BuildSnapshot::load(*resources.repository, validation);
        if (const auto *error = std::get_if<SnapshotError>(&loaded))
            return BackendError{error->code};
        resources.snapshot = std::get<std::shared_ptr<const BuildSnapshot>>(std::move(loaded));
        resources.snapshots = std::make_unique<SnapshotManager>(resources.snapshot);
        resources.relay_authenticator = std::make_unique<RelayAuthenticator>(
            resources.config.relay_token);
        resources.anonymous_policy = std::make_unique<AnonymousPolicy>();
        std::string policyError;
        if (!resources.providers.configure_policy(*resources.snapshot,
                                                  *resources.anonymous_policy, policyError))
            return BackendError{"policy_unavailable"};
        resources.admin = std::make_unique<RuntimeAdminHandlers>(
            *resources.repository, *resources.snapshots, validation,
            resources.providers.authorize_admin, resources.providers.artifact_evidence,
            resources.providers.configure_policy, *resources.anonymous_policy);
        return std::variant<std::monostate, BackendError>{std::monostate{}};
    };
    stages.check_providers = [&resources]() -> std::variant<std::monostate, BackendError> {
        auto now = resources.providers.trusted_now();
        if (const auto *error = std::get_if<BackendError>(&now)) return *error;
        if (!resources.providers.random_bytes || !resources.providers.sign ||
            !resources.providers.authorize_control || !resources.providers.validate_pair ||
            !resources.providers.validate_final_artifact ||
            !resources.providers.artifact_evidence || !resources.providers.authorize_admin)
            return BackendError{"provider_unavailable"};
        ProtocolService::Providers providers;
        providers.relay_authenticator = resources.relay_authenticator.get();
        providers.anonymous_policy = resources.anonymous_policy.get();
        providers.snapshots = resources.snapshots.get();
        providers.state = resources.state.get();
        providers.trusted_now = resources.providers.trusted_now;
        providers.random_bytes = resources.providers.random_bytes;
        providers.authorize_control = resources.providers.authorize_control;
        providers.signing = resources.providers.signing;
        providers.sign = resources.providers.sign;
        providers.issue = resources.providers.issue;
        providers.build_payload = resources.providers.build_payload;
        resources.service = std::make_unique<ProtocolService>(std::move(providers));
        return std::variant<std::monostate, BackendError>{std::monostate{}};
    };
    stages.start_listener = [&resources]() -> std::variant<std::monostate, BackendError> {
        HttpServerConfig config;
        config.bind_address = resources.config.bind_address;
        config.port = resources.config.port;
        config.relay_token = resources.config.relay_token;
        config.admin_token = resources.config.admin_token;
        config.idle_timeout_ms = resources.config.request_timeout_ms;
        config.max_concurrent_requests = resources.config.max_concurrent_requests;
        resources.server = std::make_unique<HttpServer>(std::move(config));
        resources.server->setRelayHandler([&resources](std::span<const std::byte> request,
                                                        const std::string &) {
            return resources.service->handle(request, resources.config.relay_token);
        });
        resources.server->setAdminHandler([&resources](std::string_view path,
                                                         std::span<const std::byte> body,
                                                         const std::string &credential) {
            return resources.admin->handle(path, body, credential);
        });
        resources.server->setTrustHandler(resources.providers.trust_handler);
        auto result = resources.server->start();
        if (const auto *error = std::get_if<BackendError>(&result)) return *error;
        resources.server->setReady(true);
        return std::variant<std::monostate, BackendError>{std::monostate{}};
    };

    StartupCoordinator coordinator(std::move(stages));
    auto result = coordinator.start();
    if (const auto *error = std::get_if<BackendError>(&result)) {
        std::fprintf(stderr, "backend startup failed: %s\n", error->code.c_str());
        return 1;
    }
    while (!stop_requested.load()) std::this_thread::sleep_for(std::chrono::seconds(1));
    resources.server->stop();
    return 0;
}

} // namespace

} // namespace xovm::cloud_material

int main() {
    return xovm::cloud_material::run();
}
