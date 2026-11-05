#include "admin_repository.h"
#include "auth_policy.h"
#include "build_snapshot.h"
#include "checkpoint.h"
#include "config.h"
#include "http_server.h"
#include "process_lock.h"
#include "protocol_service.h"
#include "raw_api_dispatch.h"
#include "raw_server.h"
#include "raw_window_acquisition_service.h"
#include "runtime_providers.h"
#include "runtime_admin.h"
#include "session_state.h"
#include "state_wal.h"
#include "startup.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <memory>
#include <optional>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <csignal>
#include <thread>

namespace xovm::cloud_material {

namespace {

std::atomic<bool> stop_requested{false};

void requestStop(int) {
    stop_requested.store(true);
}

std::string hex(std::span<const std::uint8_t> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}

std::optional<std::array<std::uint8_t, 32>> rawHelloDigest(
    const xovm::material::RawHello &hello) {
    constexpr std::string_view domain = "xovm/raw-session/open/v1";
    const auto canonical = xovm::material::encodeRawHello(hello);
    if (canonical.empty()) return std::nullopt;
    std::vector<std::uint8_t> framed;
    framed.reserve(domain.size() + sizeof(std::uint32_t) + canonical.size());
    framed.insert(framed.end(), domain.begin(), domain.end());
    const auto size = static_cast<std::uint32_t>(canonical.size());
    framed.push_back(static_cast<std::uint8_t>(size >> 24));
    framed.push_back(static_cast<std::uint8_t>(size >> 16));
    framed.push_back(static_cast<std::uint8_t>(size >> 8));
    framed.push_back(static_cast<std::uint8_t>(size));
    framed.insert(framed.end(), canonical.begin(), canonical.end());
    std::array<std::uint8_t, 32> result{};
    unsigned int resultSize = 0;
    const bool ok = EVP_Digest(framed.data(), framed.size(), result.data(),
                               &resultSize, EVP_sha256(), nullptr) == 1 &&
                    resultSize == result.size();
    OPENSSL_cleanse(framed.data(), framed.size());
    if (!ok) return std::nullopt;
    return result;
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
    std::unique_ptr<RawWindowAcquisitionService> raw_window_acquisition;
    std::unique_ptr<RawApiDispatch> raw_dispatch;
    std::unique_ptr<RawServer> raw_server;
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
        SessionState validated;
        auto restored = validated.restore(state);
        if (const auto *error = std::get_if<BackendError>(&restored)) return *error;
        resources.wal = std::make_unique<StateWal>(stateDir / "state.wal", StateWal::IoHooks{},
                                                   state.last_sequence);
        resources.state = std::make_unique<SessionState>(resources.wal.get());
        restored = resources.state->restore(state);
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
        if (resources.config.raw_port != 0) {
            auto raw = resources.providers.raw_api;
            if (!raw.announcement || !raw.update || !raw.variables ||
                !raw.account_login || !raw.card_login ||
                !resources.providers.random_bytes || !resources.providers.sign ||
                !resources.providers.trusted_now ||
                !resources.providers.build_window_material || !resources.snapshots ||
                !resources.anonymous_policy || !resources.state)
                return BackendError{"raw_provider_unavailable"};
            RawWindowAcquisitionService::Providers acquisitionProviders;
            acquisitionProviders.snapshots = resources.snapshots.get();
            acquisitionProviders.anonymous_policy = resources.anonymous_policy.get();
            acquisitionProviders.sessions = resources.state.get();
            acquisitionProviders.trusted_now = resources.providers.trusted_now;
            acquisitionProviders.build_material =
                resources.providers.build_window_material;
            resources.raw_window_acquisition =
                std::make_unique<RawWindowAcquisitionService>(
                    std::move(acquisitionProviders));
            raw.algorithm = [&resources](
                const AuthenticatedRawContext &context,
                const xovm::material::WindowAcquireRequest &request)
                -> std::variant<xovm::material::WindowGrant, CloudApiError> {
                if (!resources.raw_window_acquisition)
                    return CloudApiError{"authority_unavailable"};
                auto result = resources.raw_window_acquisition->acquire(context, request);
                if (const auto *error = std::get_if<BackendError>(&result))
                    return CloudApiError{error->code};
                const auto &committed = std::get<std::vector<std::uint8_t>>(result);
                auto grant = xovm::material::decodeWindowGrant(committed);
                if (!grant || xovm::material::encodeWindowGrant(*grant) != committed)
                    return CloudApiError{"authority_unavailable"};
                return std::move(*grant);
            };
            resources.raw_dispatch = std::make_unique<RawApiDispatch>(CloudApi(std::move(raw)));
            RawServerConfig rawConfig;
            rawConfig.bind_address = resources.config.bind_address;
            rawConfig.port = resources.config.raw_port;
            resources.raw_server = std::make_unique<RawServer>(std::move(rawConfig));
            resources.raw_server->setSessionFactory([&resources](
                const xovm::material::RawHello &hello)
                -> std::variant<RawSession, RawServerError> {
                try {
                    const auto digest = rawHelloDigest(hello);
                    if (!digest) return RawServerError{"invalid_hello"};
                    auto nowResult = resources.providers.trusted_now();
                    if (const auto *error = std::get_if<BackendError>(&nowResult))
                        return RawServerError{error->code};
                    const auto now = std::get<std::uint64_t>(nowResult);

                    auto snapshot = resources.snapshots->acquire();
                    if (!snapshot || !resources.snapshots->ready())
                        return RawServerError{"authority_unavailable"};
                    const auto *build = snapshot->find(hello.build_id);
                    if (!build || build->registration.build_id != hello.build_id ||
                        build->registration.software_id != hello.software_id)
                        return RawServerError{"build_unavailable"};

                    RequestFacts facts;
                    facts.request_id = hex(hello.request_id);
                    facts.request_digest = hex(*digest);
                    facts.software_id = hello.software_id;
                    facts.build_id = hello.build_id;
                    facts.final_artifact_hash = build->final_artifact_hash;
                    facts.type = "session.open";
                    auto reserved = resources.anonymous_policy->reserve(
                        *snapshot, facts, now, 1);
                    if (const auto *error = std::get_if<BackendError>(&reserved))
                        return RawServerError{error->code};
                    auto reservation = std::get<AnonymousPolicy::Reservation>(
                        std::move(reserved));
                    auto issuance = resources.snapshots->beginIssuance(
                        snapshot, hello.build_id);
                    if (!issuance) return RawServerError{"build_unavailable"};

                    auto registrationNowResult = resources.providers.trusted_now();
                    if (const auto *error =
                            std::get_if<BackendError>(&registrationNowResult))
                        return RawServerError{error->code};
                    const auto registrationNow =
                        std::get<std::uint64_t>(registrationNowResult);
                    if (registrationNow < now ||
                        registrationNow >= reservation.grant().validUntilMs())
                        return RawServerError{"authority_unavailable"};
                    RawSessionRegistrationInput registration{
                        .client_nonce = hex(hello.client_nonce),
                        .client_ephemeral_key = hex(hello.client_ephemeral_public)};
                    std::optional<RawSession> liveSession;
                    const auto registered = resources.state->registerRawSession(
                        facts, reservation.grant(), registrationNow, registration,
                        [&resources, &hello, &liveSession, registrationNow,
                         validUntil = reservation.grant().validUntilMs()](
                            std::uint64_t counter)
                            -> std::variant<RawSessionMetadata, BackendError> {
                            constexpr std::uint64_t sessionLifetimeMs = 120000;
                            if (registrationNow >
                                std::numeric_limits<std::uint64_t>::max() -
                                    sessionLifetimeMs)
                                return BackendError{"session_expiry_overflow"};
                            RawSessionConfig sessionConfig;
                            sessionConfig.random_bytes = [&resources](size_t size)
                                -> std::variant<std::vector<uint8_t>, RawSessionError> {
                                auto result = resources.providers.random_bytes(size);
                                if (const auto *error = std::get_if<BackendError>(&result))
                                    return RawSessionError{error->code};
                                const auto &bytes = std::get<Bytes>(result);
                                std::vector<uint8_t> converted;
                                converted.reserve(bytes.size());
                                for (const auto byte : bytes)
                                    converted.push_back(static_cast<uint8_t>(byte));
                                return converted;
                            };
                            sessionConfig.sign = [&resources](
                                std::span<const uint8_t> input)
                                -> std::variant<std::array<uint8_t, 64>, RawSessionError> {
                                auto result = resources.providers.sign(input);
                                if (const auto *error = std::get_if<BackendError>(&result))
                                    return RawSessionError{error->code};
                                return std::get<std::array<uint8_t, 64>>(result);
                            };
                            sessionConfig.trusted_now = [&resources]()
                                -> std::variant<uint64_t, RawSessionError> {
                                auto result = resources.providers.trusted_now();
                                if (const auto *error = std::get_if<BackendError>(&result))
                                    return RawSessionError{error->code};
                                return std::get<uint64_t>(result);
                            };
                            sessionConfig.counter = counter;
                            sessionConfig.expires_at_ms = std::min(
                                registrationNow + sessionLifetimeMs, validUntil);
                            auto accepted = RawSession::accept(hello, sessionConfig);
                            if (const auto *error = std::get_if<RawSessionError>(&accepted))
                                return BackendError{error->code};
                            liveSession.emplace(std::get<RawSession>(std::move(accepted)));
                            auto commitNowResult = resources.providers.trusted_now();
                            if (const auto *error =
                                    std::get_if<BackendError>(&commitNowResult))
                                return *error;
                            const auto commitNow =
                                std::get<std::uint64_t>(commitNowResult);
                            if (commitNow < registrationNow ||
                                commitNow >= sessionConfig.expires_at_ms)
                                return BackendError{"authority_unavailable"};
                            const auto &server = liveSession->serverHello();
                            const auto &context = liveSession->authenticatedContext();
                            return RawSessionMetadata{
                                .session_id = hex(server.session_id),
                                .server_nonce = hex(server.server_nonce),
                                .server_ephemeral_key = hex(server.server_ephemeral_public),
                                .initial_state_commitment =
                                    hex(context.initialStateCommitment()),
                                .key_version = server.key_version,
                                .valid_until_ms = server.expires_at_ms};
                        });
                    if (const auto *error =
                            std::get_if<BackendError>(&registered))
                        return RawServerError{error->code};
                    if (!liveSession || !reservation.commit())
                        return RawServerError{"authority_unavailable"};
                    issuance.finishCommit();
                    return std::move(*liveSession);
                } catch (...) {
                    return RawServerError{"authority_unavailable"};
                }
            });
            resources.raw_server->setFrameHandler([&resources](
                const AuthenticatedRawContext &context,
                const xovm::material::RawFrameHeader &header,
                std::span<const uint8_t> payload)
                -> std::variant<std::vector<uint8_t>, RawSessionError> {
                auto result = resources.raw_dispatch->handle(context, header, payload);
                if (const auto *error = std::get_if<RawApiDispatchError>(&result))
                    return RawSessionError{error->code};
                return std::get<std::vector<uint8_t>>(std::move(result));
            });
            auto rawResult = resources.raw_server->start();
            if (const auto *error = std::get_if<RawServerError>(&rawResult))
                return BackendError{error->code};
        }
        auto result = resources.server->start();
        if (const auto *error = std::get_if<BackendError>(&result)) {
            if (resources.raw_server) {
                resources.raw_server->stop();
                resources.raw_server.reset();
            }
            return *error;
        }
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
    resources.server->setReady(false);
    resources.server->stop();
    if (resources.raw_server) {
        resources.raw_server->stop();
        resources.raw_server.reset();
    }
    return 0;
}

} // namespace

} // namespace xovm::cloud_material

int main() {
    return xovm::cloud_material::run();
}
