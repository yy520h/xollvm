#include "auth_policy.h"
#include "raw_session.h"
#include "raw_window_acquisition_service.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

namespace xovm::cloud_material {
struct RepositoryTestAccess {
    static SnapshotManager::SnapshotHandle snapshot(
        const std::string &buildId, const std::string &softwareId,
        const std::string &artifactHash, const std::string &regionId) {
        auto value = std::shared_ptr<BuildSnapshot>(new BuildSnapshot);
        StoredBuild build;
        build.registration.build_id = buildId;
        build.registration.software_id = softwareId;
        build.registration.verifier_sidecars.emplace(
            regionId, std::vector<std::byte>{std::byte{1}});
        build.final_artifact_hash = artifactHash;
        value->builds_.emplace(buildId, std::move(build));
        return value;
    }
};
} // namespace xovm::cloud_material

namespace {
using namespace xovm::cloud_material;
using namespace xovm::material;

struct TestState {
    unsigned assertions = 0;
    unsigned failures = 0;
    const char *test_name = "";
} state;

bool expect(bool condition, const char *expression, int line) {
    ++state.assertions;
    if (condition) return true;
    ++state.failures;
    std::fprintf(stderr, "line %d: %s failed in %s\n", line, expression,
                 state.test_name);
    return false;
}

#define EXPECT_TRUE(expression) expect(static_cast<bool>(expression), #expression, __LINE__)
#define EXPECT_ERROR(result, expected)                                             \
    do {                                                                           \
        EXPECT_TRUE(std::holds_alternative<BackendError>(result));                  \
        if (const auto *error = std::get_if<BackendError>(&(result)))               \
            EXPECT_TRUE(error->code == (expected));                                 \
    } while (false)
#define TEST(name) static void name()

constexpr char kSoftware[] = "raw.window.test";
constexpr char kArtifact[] =
    "3333333333333333333333333333333333333333333333333333333333333333";

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

RawSession makeRawSession(const DynamicHash &buildId, std::uint64_t expiresAt) {
    std::array<std::uint8_t, 32> clientPrivate{};
    clientPrivate.fill(7);
    EVP_PKEY *clientKey = EVP_PKEY_new_raw_private_key_ex(
        nullptr, "X25519", nullptr, clientPrivate.data(), clientPrivate.size());
    if (!clientKey) throw std::runtime_error("client_key_failed");
    std::array<std::uint8_t, 32> clientPublic{};
    std::size_t publicSize = clientPublic.size();
    const bool publicOk = EVP_PKEY_get_raw_public_key(
        clientKey, clientPublic.data(), &publicSize) == 1 &&
        publicSize == clientPublic.size();
    EVP_PKEY_free(clientKey);
    if (!publicOk) throw std::runtime_error("client_public_failed");

    RawHello hello{};
    hello.version = kRawProtocolVersion;
    hello.software_id = kSoftware;
    hello.build_id = hex(buildId);
    hello.client_nonce.fill(5);
    hello.client_ephemeral_public = clientPublic;
    hello.request_id.fill(6);
    hello.cipher_suite = 1;

    auto call = std::make_shared<unsigned>(0);
    RawSessionConfig config;
    config.random_bytes = [call](std::size_t size)
        -> std::variant<std::vector<std::uint8_t>, RawSessionError> {
        const auto value = static_cast<std::uint8_t>(++*call + 10);
        return std::vector<std::uint8_t>(size, value);
    };
    config.sign = [](std::span<const std::uint8_t>)
        -> std::variant<std::array<std::uint8_t, 64>, RawSessionError> {
        std::array<std::uint8_t, 64> signature{};
        signature.fill(9);
        return signature;
    };
    config.trusted_now = [] {
        return std::variant<std::uint64_t, RawSessionError>{std::uint64_t{1000}};
    };
    config.counter = 1;
    config.key_version = 7;
    config.expires_at_ms = expiresAt;
    auto result = RawSession::accept(hello, config);
    if (const auto *error = std::get_if<RawSessionError>(&result))
        throw std::runtime_error(error->code);
    return std::get<RawSession>(std::move(result));
}

WindowMaterial material(std::uint8_t value) {
    WindowMaterial result;
    result.window.fill(value);
    result.permutation.fill(value);
    result.decode.fill(value);
    result.chaff.fill(value);
    result.integrity.fill(value);
    result.jit.fill(value);
    return result;
}

struct Fixture {
    DynamicHash build_id{};
    DynamicHash region_id{};
    RawSession raw;
    SnapshotManager snapshots;
    AnonymousPolicy policy;
    SessionState sessions;
    std::uint64_t now = 1000;
    unsigned builder_calls = 0;
    bool fail_builder = false;
    RawWindowAcquisitionService service;

    explicit Fixture(std::size_t requestBudget = 32,
                     std::uint64_t contextExpiry = 5000,
                     std::uint64_t policyExpiry = 4000,
                     std::uint64_t ttl = 120000,
                     StateWal *wal = nullptr)
        : build_id([] { DynamicHash value{}; value.fill(0x11); return value; }()),
          region_id([] { DynamicHash value{}; value.fill(0x22); return value; }()),
          raw(makeRawSession(build_id, contextExpiry)),
          snapshots(RepositoryTestAccess::snapshot(
              hex(build_id), kSoftware, kArtifact, hex(region_id))),
          sessions(wal),
          service(RawWindowAcquisitionService::Providers{
              .snapshots = &snapshots,
              .anonymous_policy = &policy,
              .sessions = &sessions,
              .trusted_now = [this] {
                  return std::variant<std::uint64_t, BackendError>{now};
              },
              .build_material = [this](const WindowAcquireRequest &)
                  -> std::variant<WindowMaterial, BackendError> {
                  ++builder_calls;
                  if (fail_builder) return BackendError{"builder_private_detail"};
                  return material(static_cast<std::uint8_t>(0x40 + builder_calls));
              },
              .window_ttl_ms = ttl,
              .rate_budget = 1}) {
        policy.setRule(hex(build_id), AnonymousPolicy::BuildRule{
            .software_id = kSoftware,
            .final_artifact_hash = kArtifact,
            .regions = {hex(region_id)},
            .modes = {"lease"},
            .valid_until_ms = policyExpiry,
            .revision = 0,
            .request_budget = requestBudget,
            .enabled = true});
        openSession(contextExpiry);
    }

    void openSession(std::uint64_t validUntil) {
        RequestFacts facts;
        facts.request_id = std::string(32, 'a');
        facts.request_digest = std::string(64, 'b');
        facts.software_id = kSoftware;
        facts.build_id = hex(build_id);
        facts.final_artifact_hash = kArtifact;
        facts.type = "session.open";
        RelayAuthenticator issuer("raw-window-test-credential", 10000);
        auto grantResult = issuer.authenticate(
            "raw-window-test-credential", facts, now);
        if (!std::holds_alternative<AnonymousGrant>(grantResult))
            throw std::runtime_error("open_grant_failed");
        const auto &grant = std::get<AnonymousGrant>(grantResult);
        const auto opened = sessions.transact(
            facts, grant, now, [&](SessionState::Transaction &transaction) {
                return transaction.openSession(
                    hex(raw.authenticatedContext().sessionId()), "raw-epoch",
                    validUntil, "raw-server-nonce", "raw-server-key",
                    "raw-client-nonce", "raw-client-key");
            });
        if (!std::holds_alternative<StateResult>(opened))
            throw std::runtime_error("open_session_failed");
    }

    WindowAcquireRequest request(std::uint8_t id, std::uint64_t window = 1) const {
        WindowAcquireRequest value;
        value.request_id.fill(id);
        value.build_id = build_id;
        value.region_id = region_id;
        value.generation = 9;
        value.window_id = window;
        value.previous_state_hash = raw.authenticatedContext().initialStateCommitment();
        return value;
    }
};

TEST(success_binds_identity_material_and_minimum_expiry) {
    const auto acquireAndExpiry = [](Fixture &fixture, std::uint8_t id,
                                     std::uint64_t expectedExpiry) {
        const auto request = fixture.request(id);
        auto result = fixture.service.acquire(
            fixture.raw.authenticatedContext(), request);
        EXPECT_TRUE(std::holds_alternative<std::vector<std::uint8_t>>(result));
        EXPECT_TRUE(fixture.builder_calls == 1);
        if (const auto *bytes = std::get_if<std::vector<std::uint8_t>>(&result)) {
            auto grant = decodeWindowGrant(*bytes);
            EXPECT_TRUE(grant.has_value());
            if (grant) {
                EXPECT_TRUE(grant->build_id == request.build_id);
                EXPECT_TRUE(grant->region_id == request.region_id);
                EXPECT_TRUE(grant->session_id ==
                            fixture.raw.authenticatedContext().sessionId());
                EXPECT_TRUE(grant->generation == request.generation);
                EXPECT_TRUE(grant->window_id == request.window_id);
                EXPECT_TRUE(grant->previous_state_hash == request.previous_state_hash);
                EXPECT_TRUE(grant->issued_at_ms == fixture.now);
                EXPECT_TRUE(grant->expires_at_ms == expectedExpiry);
                EXPECT_TRUE(grant->key_version ==
                            fixture.raw.authenticatedContext().keyVersion());
            }
        }
    };

    Fixture ttlMinimum(8, 5000, 3500, 900);
    acquireAndExpiry(ttlMinimum, 1, 1900);
    Fixture contextMinimum(8, 1500, 3500, 900);
    acquireAndExpiry(contextMinimum, 2, 1500);
    Fixture policyMinimum(8, 5000, 1400, 900);
    acquireAndExpiry(policyMinimum, 3, 1400);
}

TEST(exact_retry_returns_cached_bytes_and_spends_one_budget_unit) {
    Fixture fixture(1);
    const auto request = fixture.request(2);
    auto first = fixture.service.acquire(fixture.raw.authenticatedContext(), request);
    auto retry = fixture.service.acquire(fixture.raw.authenticatedContext(), request);
    EXPECT_TRUE(std::holds_alternative<std::vector<std::uint8_t>>(first));
    EXPECT_TRUE(std::holds_alternative<std::vector<std::uint8_t>>(retry));
    EXPECT_TRUE(fixture.builder_calls == 1);
    if (std::holds_alternative<std::vector<std::uint8_t>>(first) &&
        std::holds_alternative<std::vector<std::uint8_t>>(retry))
        EXPECT_TRUE(std::get<std::vector<std::uint8_t>>(first) ==
                    std::get<std::vector<std::uint8_t>>(retry));

    auto different = fixture.request(3);
    different.window_id = 2;
    if (const auto *bytes = std::get_if<std::vector<std::uint8_t>>(&first)) {
        const auto grant = decodeWindowGrant(*bytes);
        if (grant) different.previous_state_hash = grant->next_state_hash;
    }
    auto exhausted = fixture.service.acquire(
        fixture.raw.authenticatedContext(), different);
    EXPECT_ERROR(exhausted, "build_unavailable");
    EXPECT_TRUE(fixture.builder_calls == 1);
}

TEST(builder_failure_releases_budget_for_distinct_request) {
    Fixture fixture(1);
    fixture.fail_builder = true;
    auto failed = fixture.service.acquire(
        fixture.raw.authenticatedContext(), fixture.request(4));
    EXPECT_ERROR(failed, "authority_unavailable");
    EXPECT_TRUE(fixture.builder_calls == 1);

    fixture.fail_builder = false;
    auto distinct = fixture.service.acquire(
        fixture.raw.authenticatedContext(), fixture.request(5));
    EXPECT_TRUE(std::holds_alternative<std::vector<std::uint8_t>>(distinct));
    EXPECT_TRUE(fixture.builder_calls == 2);
}

TEST(malformed_identity_and_genesis_do_not_mutate_state) {
    Fixture fixture;
    auto wrongIdentity = fixture.request(4);
    wrongIdentity.build_id[0] ^= 1;
    auto identityResult = fixture.service.acquire(
        fixture.raw.authenticatedContext(), wrongIdentity);
    EXPECT_ERROR(identityResult, "unauthorized");

    auto wrongGenesis = fixture.request(5);
    wrongGenesis.previous_state_hash[0] ^= 1;
    auto genesisResult = fixture.service.acquire(
        fixture.raw.authenticatedContext(), wrongGenesis);
    EXPECT_ERROR(genesisResult, "window_chain_mismatch");
    EXPECT_TRUE(fixture.builder_calls == 0);

    auto valid = fixture.service.acquire(
        fixture.raw.authenticatedContext(), fixture.request(6));
    EXPECT_TRUE(std::holds_alternative<std::vector<std::uint8_t>>(valid));
    EXPECT_TRUE(fixture.builder_calls == 1);
}

TEST(wal_failure_releases_budget_and_chain_for_distinct_request) {
    const auto path = std::filesystem::temp_directory_path() /
        ("xovm-raw-window-wal-failure-" + std::to_string(::getpid()) + ".wal");
    std::filesystem::remove(path);
    bool failNextSync = false;
    StateWal::IoHooks hooks;
    hooks.sync = [&failNextSync](int) {
        if (!failNextSync) return 0;
        failNextSync = false;
        return -1;
    };
    StateWal wal(path, std::move(hooks));
    Fixture fixture(1, 5000, 4000, 120000, &wal);

    failNextSync = true;
    auto failed = fixture.service.acquire(
        fixture.raw.authenticatedContext(), fixture.request(7));
    EXPECT_ERROR(failed, "authority_unavailable");
    EXPECT_TRUE(fixture.builder_calls == 1);

    auto distinct = fixture.service.acquire(
        fixture.raw.authenticatedContext(), fixture.request(8));
    EXPECT_TRUE(std::holds_alternative<std::vector<std::uint8_t>>(distinct));
    EXPECT_TRUE(fixture.builder_calls == 2);
    if (const auto *bytes = std::get_if<std::vector<std::uint8_t>>(&distinct)) {
        const auto grant = decodeWindowGrant(*bytes);
        EXPECT_TRUE(grant.has_value());
        if (grant) {
            EXPECT_TRUE(grant->window_id == 1);
            EXPECT_TRUE(grant->previous_state_hash ==
                        fixture.raw.authenticatedContext().initialStateCommitment());
        }
    }
    std::filesystem::remove(path);
}

TEST(replay_skip_and_builder_failure_leave_contiguous_chain_unchanged) {
    Fixture fixture;
    auto firstRequest = fixture.request(7);
    auto first = fixture.service.acquire(
        fixture.raw.authenticatedContext(), firstRequest);
    EXPECT_TRUE(std::holds_alternative<std::vector<std::uint8_t>>(first));
    auto firstGrant = std::optional<WindowGrant>{};
    if (const auto *bytes = std::get_if<std::vector<std::uint8_t>>(&first))
        firstGrant = decodeWindowGrant(*bytes);
    EXPECT_TRUE(firstGrant.has_value());
    if (!firstGrant) return;

    auto replay = fixture.request(8, 1);
    auto replayResult = fixture.service.acquire(
        fixture.raw.authenticatedContext(), replay);
    EXPECT_ERROR(replayResult, "window_chain_mismatch");
    EXPECT_TRUE(fixture.builder_calls == 1);

    auto skipped = fixture.request(9, 3);
    skipped.previous_state_hash = firstGrant->next_state_hash;
    auto skippedResult = fixture.service.acquire(
        fixture.raw.authenticatedContext(), skipped);
    EXPECT_ERROR(skippedResult, "window_chain_mismatch");
    EXPECT_TRUE(fixture.builder_calls == 1);

    auto second = fixture.request(10, 2);
    second.previous_state_hash = firstGrant->next_state_hash;
    fixture.fail_builder = true;
    auto builderFailure = fixture.service.acquire(
        fixture.raw.authenticatedContext(), second);
    EXPECT_ERROR(builderFailure, "authority_unavailable");

    fixture.fail_builder = false;
    auto validSecond = fixture.service.acquire(
        fixture.raw.authenticatedContext(), second);
    EXPECT_TRUE(std::holds_alternative<std::vector<std::uint8_t>>(validSecond));
    EXPECT_TRUE(fixture.builder_calls == 3);
    if (const auto *bytes = std::get_if<std::vector<std::uint8_t>>(&validSecond)) {
        const auto grant = decodeWindowGrant(*bytes);
        EXPECT_TRUE(grant.has_value());
        if (grant) {
            EXPECT_TRUE(grant->window_id == 2);
            EXPECT_TRUE(grant->previous_state_hash == firstGrant->next_state_hash);
        }
    }
}

template <typename Test>
void run(const char *name, Test test) {
    const auto before = state.failures;
    state.test_name = name;
    test();
    std::fprintf(state.failures == before ? stdout : stderr, "[%s] %s\n",
                 state.failures == before ? "PASS" : "FAIL", name);
}

} // namespace

int main() {
    run("success_binds_identity_material_and_minimum_expiry",
        success_binds_identity_material_and_minimum_expiry);
    run("exact_retry_returns_cached_bytes_and_spends_one_budget_unit",
        exact_retry_returns_cached_bytes_and_spends_one_budget_unit);
    run("builder_failure_releases_budget_for_distinct_request",
        builder_failure_releases_budget_for_distinct_request);
    run("malformed_identity_and_genesis_do_not_mutate_state",
        malformed_identity_and_genesis_do_not_mutate_state);
    run("wal_failure_releases_budget_and_chain_for_distinct_request",
        wal_failure_releases_budget_and_chain_for_distinct_request);
    run("replay_skip_and_builder_failure_leave_contiguous_chain_unchanged",
        replay_skip_and_builder_failure_leave_contiguous_chain_unchanged);
    std::fprintf(stdout, "6 tests, %u assertions, %u failures\n",
                 state.assertions, state.failures);
    return state.failures == 0 ? 0 : 1;
}
