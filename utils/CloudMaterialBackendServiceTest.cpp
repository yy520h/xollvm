#include "auth_policy.h"
#include "protocol_service.h"
#include "session_state.h"
#include "response_crypto.h"

#include <cstdio>
#include <openssl/evp.h>
#include <future>
#include <thread>
#include <condition_variable>
#include <filesystem>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

namespace xovm::cloud_material {
struct RepositoryTestAccess {
    static SnapshotManager::SnapshotHandle snapshot(const RequestFacts &facts) {
        auto value = std::shared_ptr<BuildSnapshot>(new BuildSnapshot);
        StoredBuild build;
        build.registration.build_id = facts.build_id;
        build.registration.software_id = facts.software_id;
        build.final_artifact_hash = facts.final_artifact_hash;
        value->builds_.emplace(facts.build_id, std::move(build));
        return value;
    }
    static void waitUntilBlocked(SnapshotManager &manager, const std::string &build) {
        manager.waitUntilBlockedForTest(build);
    }
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

constexpr char kBuild[] = "1111111111111111111111111111111111111111111111111111111111111111";
constexpr char kArtifact[] = "3333333333333333333333333333333333333333333333333333333333333333";
constexpr char kRegion[] = "8888888888888888888888888888888888888888888888888888888888888888";

RequestFacts facts(std::string type = "material.issue") {
    RequestFacts result;
    result.request_id = std::string(64, '4');
    result.request_digest = std::string(64, '5');
    result.software_id = "test.software";
    result.build_id = kBuild;
    result.final_artifact_hash = kArtifact;
    result.region_id = kRegion;
    result.mode = "lease";
    result.type = std::move(type);
    return result;
}

RequestFacts rawRegistrationFacts(char request = '4', char digest = '5') {
    auto result = facts("session.open");
    result.request_id = std::string(32, request);
    result.request_digest = std::string(64, digest);
    result.region_id.clear();
    result.mode.clear();
    return result;
}

RawSessionRegistrationInput rawRegistrationInput(char nonce = '6', char key = '7') {
    return {std::string(64, nonce), std::string(64, key)};
}

RawSessionMetadata rawSessionMetadata(char session = '8', char serverNonce = '9',
                                      char serverKey = 'a', char genesis = 'b') {
    return {std::string(32, session), std::string(64, serverNonce),
            std::string(64, serverKey), std::string(64, genesis), 1, 5000};
}

bool hasError(const auto &outcome, std::string_view code) {
    const auto *error = std::get_if<BackendError>(&outcome);
    return error && error->code == code;
}

void openTestSession(SessionState &state, const RequestFacts &material,
                     const AnonymousGrant &materialGrant) {
    auto open = facts("session.open");
    open.build_id = material.build_id;
    open.software_id = material.software_id;
    open.final_artifact_hash = material.final_artifact_hash;
    open.request_id = std::string(64, 'a');
    open.request_digest = std::string(64, 'b');
    RelayAuthenticator issuer("test-relay-credential-that-is-long-enough");
    auto grant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", open, 1000));
    auto opened = state.transact(open, grant, 1000, [&](SessionState::Transaction &tx) {
        return tx.openSession("session-a", "epoch-a", 1900, "server-a", "server-key-a",
                              "client-a", "client-key-a");
    });
    (void)materialGrant;
    if (!std::holds_alternative<StateResult>(opened)) throw std::runtime_error("test_open_failed");
}

TEST(anonymous_policy_denies_by_default) {
    AnonymousPolicy policy;
    BuildSnapshot snapshot;
    auto result = policy.authorize(snapshot, facts(), 1000, 1);
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
}

TEST(anonymous_policy_denies_unregistered_revoked_mismatched_and_expired_builds) {
    AnonymousPolicy policy;
    auto request = facts();
    auto snapshot = RepositoryTestAccess::snapshot(request);
    auto rule = AnonymousPolicy::BuildRule{
        .software_id = request.software_id,
        .final_artifact_hash = request.final_artifact_hash,
        .regions = {request.region_id},
        .modes = {"lease"},
        .valid_until_ms = 2000,
        .revision = 0,
        .request_budget = 4,
        .enabled = true,
    };
    policy.setRule(request.build_id, rule);
    EXPECT_TRUE(std::holds_alternative<AnonymousGrant>(policy.authorize(*snapshot, request, 1000, 1)));

    auto wrongRegion = request;
    wrongRegion.region_id = std::string(64, '9');
    EXPECT_TRUE(std::holds_alternative<BackendError>(policy.authorize(*snapshot, wrongRegion, 1000, 1)));
    auto wrongMode = request;
    wrongMode.mode = "session";
    EXPECT_TRUE(std::holds_alternative<BackendError>(policy.authorize(*snapshot, wrongMode, 1000, 1)));
    EXPECT_TRUE(std::holds_alternative<BackendError>(policy.authorize(*snapshot, request, 2000, 1)));
    EXPECT_TRUE(std::holds_alternative<BackendError>(policy.authorize(*snapshot, request, 1000, 0)));

    rule.enabled = false;
    policy.setRule(request.build_id, rule);
    EXPECT_TRUE(std::holds_alternative<BackendError>(policy.authorize(*snapshot, request, 1000, 1)));
}

TEST(anonymous_policy_authorizes_session_control_without_material_scope_fields) {
    AnonymousPolicy policy;
    auto request = facts("session.open");
    request.region_id.clear();
    request.mode.clear();
    auto snapshot = RepositoryTestAccess::snapshot(request);
    policy.setRule(request.build_id, AnonymousPolicy::BuildRule{
        .software_id = request.software_id,
        .final_artifact_hash = request.final_artifact_hash,
        .regions = {kRegion}, .modes = {"lease"}, .valid_until_ms = 2000,
        .revision = 0, .request_budget = 4, .enabled = true});
    auto result = policy.authorize(*snapshot, request, 1000, 1);
    EXPECT_TRUE(std::holds_alternative<AnonymousGrant>(result));
}

TEST(anonymous_policy_idempotently_accounts_canonical_requests) {
    AnonymousPolicy policy;
    auto request = facts();
    auto snapshot = RepositoryTestAccess::snapshot(request);
    const auto rule = AnonymousPolicy::BuildRule{
        .software_id = request.software_id,
        .final_artifact_hash = request.final_artifact_hash,
        .regions = {request.region_id},
        .modes = {request.mode},
        .valid_until_ms = 2000,
        .revision = 0,
        .request_budget = 1,
        .enabled = true,
    };
    policy.setRule(request.build_id, rule);

    EXPECT_TRUE(std::holds_alternative<AnonymousGrant>(
        policy.authorize(*snapshot, request, 1000, 1)));
    EXPECT_TRUE(std::holds_alternative<AnonymousGrant>(
        policy.authorize(*snapshot, request, 1000, 1)));

    auto conflicting = request;
    conflicting.request_digest = std::string(64, '6');
    const auto conflict = policy.authorize(*snapshot, conflicting, 1000, 1);
    EXPECT_TRUE(std::holds_alternative<BackendError>(conflict));
    if (const auto *error = std::get_if<BackendError>(&conflict))
        EXPECT_TRUE(error->code == "request_conflict");

    auto distinct = request;
    distinct.request_id = std::string(64, '7');
    distinct.request_digest = std::string(64, '8');
    const auto exhausted = policy.authorize(*snapshot, distinct, 1000, 1);
    EXPECT_TRUE(std::holds_alternative<BackendError>(exhausted));
    if (const auto *error = std::get_if<BackendError>(&exhausted))
        EXPECT_TRUE(error->code == "build_unavailable");
}

TEST(anonymous_policy_serializes_concurrent_exact_retries) {
    AnonymousPolicy policy;
    auto request = facts();
    auto snapshot = RepositoryTestAccess::snapshot(request);
    policy.setRule(request.build_id, AnonymousPolicy::BuildRule{
        .software_id = request.software_id,
        .final_artifact_hash = request.final_artifact_hash,
        .regions = {request.region_id}, .modes = {request.mode},
        .valid_until_ms = 2000, .revision = 0, .request_budget = 1,
        .enabled = true});

    std::vector<std::future<std::variant<AnonymousGrant, BackendError>>> retries;
    for (unsigned index = 0; index != 16; ++index) {
        retries.push_back(std::async(std::launch::async, [&] {
            return policy.authorize(*snapshot, request, 1000, 1);
        }));
    }
    for (auto &retry : retries)
        EXPECT_TRUE(std::holds_alternative<AnonymousGrant>(retry.get()));

    auto distinct = request;
    distinct.request_id = std::string(64, '7');
    distinct.request_digest = std::string(64, '8');
    EXPECT_TRUE(std::holds_alternative<BackendError>(
        policy.authorize(*snapshot, distinct, 1000, 1)));
}

TEST(anonymous_policy_cache_is_bounded_and_rule_replacement_resets_it) {
    AnonymousPolicy policy(1);
    auto first = facts();
    auto snapshot = RepositoryTestAccess::snapshot(first);
    const auto rule = AnonymousPolicy::BuildRule{
        .software_id = first.software_id,
        .final_artifact_hash = first.final_artifact_hash,
        .regions = {first.region_id},
        .modes = {first.mode},
        .valid_until_ms = 2000,
        .revision = 0,
        .request_budget = 4,
        .enabled = true,
    };
    policy.setRule(first.build_id, rule);
    EXPECT_TRUE(std::holds_alternative<AnonymousGrant>(
        policy.authorize(*snapshot, first, 1000, 1)));

    auto second = first;
    second.request_id = std::string(64, '7');
    second.request_digest = std::string(64, '8');
    EXPECT_TRUE(std::holds_alternative<BackendError>(
        policy.authorize(*snapshot, second, 1000, 1)));

    policy.setRule(first.build_id, rule);
    EXPECT_TRUE(std::holds_alternative<AnonymousGrant>(
        policy.authorize(*snapshot, second, 1000, 1)));

    AnonymousPolicy replacement(2);
    replacement.setRule(first.build_id, rule);
    policy.replaceWith(std::move(replacement));
    EXPECT_TRUE(std::holds_alternative<AnonymousGrant>(
        policy.authorize(*snapshot, first, 1000, 1)));
    EXPECT_TRUE(std::holds_alternative<AnonymousGrant>(
        policy.authorize(*snapshot, second, 1000, 1)));
}

TEST(anonymous_policy_reservation_rolls_back_and_survives_policy_replacement) {
    AnonymousPolicy policy;
    auto request = facts();
    auto snapshot = RepositoryTestAccess::snapshot(request);
    const auto rule = AnonymousPolicy::BuildRule{
        .software_id = request.software_id,
        .final_artifact_hash = request.final_artifact_hash,
        .regions = {request.region_id},
        .modes = {request.mode},
        .valid_until_ms = 2000,
        .revision = 0,
        .request_budget = 1,
        .enabled = true,
    };
    policy.setRule(request.build_id, rule);

    {
        auto pending = policy.reserve(*snapshot, request, 1000, 1);
        EXPECT_TRUE(std::holds_alternative<AnonymousPolicy::Reservation>(pending));
        auto distinct = request;
        distinct.request_id = std::string(64, '7');
        distinct.request_digest = std::string(64, '8');
        EXPECT_TRUE(std::holds_alternative<BackendError>(
            policy.reserve(*snapshot, distinct, 1000, 1)));
    }

    auto distinct = request;
    distinct.request_id = std::string(64, '7');
    distinct.request_digest = std::string(64, '8');
    auto released = policy.reserve(*snapshot, distinct, 1000, 1);
    EXPECT_TRUE(std::holds_alternative<AnonymousPolicy::Reservation>(released));
    std::get<AnonymousPolicy::Reservation>(std::move(released)).commit();

    policy.setRule(request.build_id, rule);
    auto stale = policy.reserve(*snapshot, request, 1000, 1);
    EXPECT_TRUE(std::holds_alternative<AnonymousPolicy::Reservation>(stale));
    policy.clear();
    auto token = std::get<AnonymousPolicy::Reservation>(std::move(stale));
    EXPECT_TRUE(token.commit());
    EXPECT_TRUE(token.commit());
    EXPECT_TRUE(std::holds_alternative<BackendError>(
        policy.reserve(*snapshot, request, 1000, 1)));

    AnonymousPolicy replacement;
    replacement.setRule(request.build_id, rule);
    policy.replaceWith(std::move(replacement));
    EXPECT_TRUE(std::holds_alternative<AnonymousPolicy::Reservation>(
        policy.reserve(*snapshot, request, 1000, 1)));
}

TEST(relay_authentication_uses_fixed_backend_subject_and_scopes) {
    RelayAuthenticator authenticator("relay-secret-long-enough-for-tests");
    auto grant = authenticator.authenticate("relay-secret-long-enough-for-tests",
                                            facts(), 1000);
    EXPECT_TRUE(std::holds_alternative<AnonymousGrant>(grant));
    if (auto *value = std::get_if<AnonymousGrant>(&grant)) {
        EXPECT_TRUE(value->subjectId().rfind("anonymous:", 0) == 0);
        EXPECT_TRUE(value->subjectId().find(facts().request_id) == std::string::npos);
        EXPECT_TRUE(value->scopes().contains("session.control"));
        EXPECT_TRUE(value->scopes().contains("material.issue"));
        EXPECT_FALSE(value->scopes().contains("admin"));
        EXPECT_TRUE(value->requestDigest() == facts().request_digest);
    }
}

TEST(relay_authentication_rejects_wrong_credential) {
    RelayAuthenticator authenticator("relay-secret-long-enough-for-tests");
    auto result = authenticator.authenticate("wrong-credential", facts(), 1000);
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
}

TEST(raw_session_registration_is_fresh_only_and_anchors_genesis) {
    SessionState sessions;
    const auto request = rawRegistrationFacts();
    RelayAuthenticator issuer("test-relay-credential-that-is-long-enough", 10000);
    const auto grant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", request, 1000));
    unsigned callbacks = 0;
    auto registered = sessions.registerRawSession(
        request, grant, 1000, rawRegistrationInput(), [&](std::uint64_t counter)
            -> std::variant<RawSessionMetadata, BackendError> {
            ++callbacks;
            EXPECT_TRUE(counter == 1);
            return rawSessionMetadata();
        });
    EXPECT_TRUE(std::holds_alternative<RawSessionRegistrationResult>(registered));
    if (const auto *result = std::get_if<RawSessionRegistrationResult>(&registered)) {
        EXPECT_TRUE(result->counter == 1);
        EXPECT_TRUE(result->session == rawSessionMetadata());
    }

    auto replay = sessions.registerRawSession(
        request, grant, 1000, rawRegistrationInput(), [&](std::uint64_t)
            -> std::variant<RawSessionMetadata, BackendError> {
            ++callbacks;
            return rawSessionMetadata('c');
        });
    EXPECT_TRUE(hasError(replay, "replay_detected"));
    EXPECT_TRUE(callbacks == 1);

    auto conflictFacts = request;
    conflictFacts.request_digest = std::string(64, 'c');
    const auto conflictGrant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", conflictFacts, 1000));
    auto conflict = sessions.registerRawSession(
        conflictFacts, conflictGrant, 1000, rawRegistrationInput('d', 'e'),
        [&](std::uint64_t) -> std::variant<RawSessionMetadata, BackendError> {
            ++callbacks;
            return rawSessionMetadata('d');
        });
    EXPECT_TRUE(hasError(conflict, "request_conflict"));
    EXPECT_TRUE(callbacks == 1);

    auto issue = facts();
    issue.request_id = std::string(64, 'd');
    issue.request_digest = std::string(64, 'e');
    const auto issueGrant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", issue, 1000));
    WindowPreflightInput wrong;
    wrong.session_id = std::string(32, '8');
    wrong.region_id = kRegion;
    wrong.generation = 7;
    wrong.window_id = 1;
    wrong.previous_state = std::string(64, 'c');
    wrong.expires_at_ms = 1800;
    WindowFinalizeInput wrongFinalize{std::string(64, 'd'), {std::byte{1}}};
    auto rejected = sessions.transact(issue, issueGrant, 1000,
        [wrong, wrongFinalize](SessionState::Transaction &tx) mutable {
            tx.preflightWindow(std::move(wrong));
            return tx.finalizeWindow(std::move(wrongFinalize));
        });
    EXPECT_TRUE(hasError(rejected, "window_chain_mismatch"));

    issue.request_id = std::string(64, 'f');
    issue.request_digest = std::string(64, '1');
    const auto anchoredGrant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", issue, 1000));
    wrong.previous_state = std::string(64, 'b');
    auto anchored = sessions.transact(issue, anchoredGrant, 1000,
        [wrong, wrongFinalize](SessionState::Transaction &tx) mutable {
            tx.preflightWindow(std::move(wrong));
            return tx.finalizeWindow(std::move(wrongFinalize));
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(anchored));
}

TEST(raw_session_registration_rejects_invalid_metadata_and_collisions) {
    SessionState sessions;
    RelayAuthenticator issuer("test-relay-credential-that-is-long-enough", 10000);
    auto request = rawRegistrationFacts();
    auto grant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", request, 1000));

    auto invalid = sessions.registerRawSession(
        request, grant, 1000, rawRegistrationInput(), [](std::uint64_t)
            -> std::variant<RawSessionMetadata, BackendError> {
            auto metadata = rawSessionMetadata();
            metadata.initial_state_commitment = std::string(64, '0');
            return metadata;
        });
    EXPECT_TRUE(hasError(invalid, "invalid_key"));

    auto first = sessions.registerRawSession(
        request, grant, 1000, rawRegistrationInput(), [](std::uint64_t)
            -> std::variant<RawSessionMetadata, BackendError> {
            return rawSessionMetadata();
        });
    EXPECT_TRUE(std::holds_alternative<RawSessionRegistrationResult>(first));

    request = rawRegistrationFacts('c', 'd');
    grant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", request, 1000));
    auto sameOwnerCollision = sessions.registerRawSession(
        request, grant, 1000, rawRegistrationInput('c', 'd'), [](std::uint64_t)
            -> std::variant<RawSessionMetadata, BackendError> {
            return rawSessionMetadata();
        });
    EXPECT_TRUE(hasError(sameOwnerCollision, "request_conflict"));

    SessionState mismatched;
    auto legacyFacts = facts("session.open");
    legacyFacts.request_id = std::string(64, 'a');
    legacyFacts.request_digest = std::string(64, 'b');
    auto legacyGrant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", legacyFacts, 1000));
    auto legacy = mismatched.transact(legacyFacts, legacyGrant, 1000,
        [](SessionState::Transaction &tx) {
            return tx.openSession(std::string(32, '8'), "legacy-epoch", 5000,
                "legacy-server", "legacy-server-key", "legacy-client", "legacy-client-key");
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(legacy));
    auto other = rawRegistrationFacts();
    other.build_id = std::string(64, '2');
    other.final_artifact_hash = std::string(64, '6');
    auto otherGrant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", other, 1000));
    auto wrongOwnerCollision = mismatched.registerRawSession(
        other, otherGrant, 1000, rawRegistrationInput(), [](std::uint64_t)
            -> std::variant<RawSessionMetadata, BackendError> {
            return rawSessionMetadata();
        });
    EXPECT_TRUE(hasError(wrongOwnerCollision, "unauthorized"));
}

TEST(session_state_is_idempotent_and_rejects_replay_and_reuse) {
    SessionState state;
    auto request = facts();
    RelayAuthenticator issuer("test-relay-credential-that-is-long-enough");
    auto grantResult = issuer.authenticate("test-relay-credential-that-is-long-enough", request, 1000);
    auto grant = std::get<AnonymousGrant>(grantResult);
    openTestSession(state, request, grant);
    auto first = state.transact(request, grant, 1000, [](SessionState::Transaction &tx) {
        return tx.allocate("session-a", "region-a", "client-nonce", "client-key");
    });
    EXPECT_TRUE(std::holds_alternative<StateResult>(first));
    auto retry = state.transact(request, grant, 1000, [](SessionState::Transaction &tx) {
        return tx.allocate("session-a", "region-a", "client-nonce", "client-key");
    });
    EXPECT_TRUE(std::holds_alternative<StateResult>(retry));
    if (std::holds_alternative<StateResult>(first) && std::holds_alternative<StateResult>(retry))
        EXPECT_TRUE(std::get<StateResult>(first) == std::get<StateResult>(retry));
    auto reused = facts();
    reused.request_id = std::string(64, '6');
    reused.request_digest = std::string(64, '7');
    auto replay = state.transact(reused, grant, 1000, [](SessionState::Transaction &tx) {
        return tx.allocate("session-a", "region-a", "client-nonce", "different-key");
    });
    EXPECT_TRUE(std::holds_alternative<BackendError>(replay));
}

TEST(session_state_cached_replies_require_live_matching_session_identity) {
    RelayAuthenticator issuer("test-relay-credential-that-is-long-enough", 10000);
    auto request = facts();
    auto grant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", request, 1000));

    SessionState expiredState;
    openTestSession(expiredState, request, grant);
    auto issued = expiredState.transact(request, grant, 1000,
        [](SessionState::Transaction &tx) {
            return tx.allocate("session-a", kRegion, "issue-nonce", "issue-key");
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(issued));

    auto mismatched = request;
    mismatched.region_id = std::string(64, '9');
    auto mismatchedGrant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", mismatched, 1000));
    bool mismatchCalled = false;
    auto wrongIdentity = expiredState.transact(mismatched, mismatchedGrant, 1000,
        [&](SessionState::Transaction &) {
            mismatchCalled = true;
            return StateResult{};
        });
    EXPECT_FALSE(mismatchCalled);
    EXPECT_TRUE(std::holds_alternative<BackendError>(wrongIdentity));

    bool expiryCalled = false;
    auto expired = expiredState.transact(request, grant, 1900,
        [&](SessionState::Transaction &) {
            expiryCalled = true;
            return StateResult{};
        });
    EXPECT_FALSE(expiryCalled);
    EXPECT_TRUE(std::holds_alternative<BackendError>(expired));

    SessionState closedState;
    openTestSession(closedState, request, grant);
    issued = closedState.transact(request, grant, 1000,
        [](SessionState::Transaction &tx) {
            return tx.allocate("session-a", kRegion, "close-issue-nonce", "close-issue-key");
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(issued));
    auto closeRequest = facts("session.close");
    closeRequest.request_id = std::string(64, 'c');
    closeRequest.request_digest = std::string(64, 'd');
    auto closeGrant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", closeRequest, 1000));
    auto closed = closedState.transact(closeRequest, closeGrant, 1000,
        [](SessionState::Transaction &tx) {
            return tx.closeSession("session-a", "epoch-a", 1100,
                "close-server", "close-server-key", "close-client", "close-client-key");
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(closed));
    bool staleCalled = false;
    auto stale = closedState.transact(request, grant, 1100,
        [&](SessionState::Transaction &) {
            staleCalled = true;
            return StateResult{};
        });
    EXPECT_FALSE(staleCalled);
    EXPECT_TRUE(std::holds_alternative<BackendError>(stale));
    bool closeRetryCalled = false;
    auto closeRetry = closedState.transact(closeRequest, closeGrant, 1100,
        [&](SessionState::Transaction &) {
            closeRetryCalled = true;
            return StateResult{};
        });
    EXPECT_FALSE(closeRetryCalled);
    EXPECT_TRUE(std::holds_alternative<StateResult>(closeRetry));
    if (std::holds_alternative<StateResult>(closeRetry))
        EXPECT_TRUE(std::get<StateResult>(closeRetry).closed);
}

TEST(session_state_capacity_counts_exact_response_bytes_atomically) {
    SessionState state;
    auto request = facts();
    RelayAuthenticator issuer("test-relay-credential-that-is-long-enough", 10000);
    auto grant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", request, 1000));
    openTestSession(state, request, grant);
    auto oversized = state.transact(request, grant, 1000,
        [](SessionState::Transaction &tx) {
            auto result = tx.allocate("session-a", kRegion, "capacity-nonce", "capacity-key");
            tx.setResponse(std::vector<std::byte>(8 * 1024 * 1024, std::byte{0x5a}));
            return result;
        });
    EXPECT_TRUE(std::holds_alternative<BackendError>(oversized));
    if (const auto *error = std::get_if<BackendError>(&oversized))
        EXPECT_TRUE(error->code == "state_capacity");

    auto retry = state.transact(request, grant, 1000,
        [](SessionState::Transaction &tx) {
            auto result = tx.allocate("session-a", kRegion, "capacity-nonce", "capacity-key");
            tx.setResponse({std::byte{0x5a}});
            return result;
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(retry));
}

TEST(session_state_idempotency_key_includes_release_binding) {
    SessionState state;
    auto firstRequest = facts("session.open");
    RelayAuthenticator issuer("test-relay-credential-that-is-long-enough");
    auto firstGrant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", firstRequest, 1000));
    auto first = state.transact(firstRequest, firstGrant, 1000,
        [](SessionState::Transaction &tx) {
            return tx.openSession("session-one", "epoch-one", 5000,
                                  "server-one", "server-key-one", "client-one", "client-key-one");
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(first));
    auto secondRequest = firstRequest;
    secondRequest.software_id = "other.software";
    secondRequest.final_artifact_hash = std::string(64, '9');
    auto secondGrant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", secondRequest, 1000));
    auto second = state.transact(secondRequest, secondGrant, 1000,
        [](SessionState::Transaction &tx) {
            return tx.openSession("session-two", "epoch-two", 5000,
                                  "server-two", "server-key-two", "client-two", "client-key-two");
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(second));
    if (std::holds_alternative<StateResult>(first) && std::holds_alternative<StateResult>(second))
        EXPECT_TRUE(std::get<StateResult>(first).session_id != std::get<StateResult>(second).session_id);
}

TEST(session_state_generations_counters_and_expiry_are_bounded) {
    SessionState state;
    auto request = facts();
    RelayAuthenticator issuer("test-relay-credential-that-is-long-enough", 1000);
    auto grantResult = issuer.authenticate("test-relay-credential-that-is-long-enough", request, 1000);
    auto grant = std::get<AnonymousGrant>(grantResult);
    openTestSession(state, request, grant);
    auto first = state.transact(request, grant, 1000, [](SessionState::Transaction &tx) {
        return tx.allocate("session-a", "region-a", "nonce-a", "key-a");
    });
    auto secondRequest = request;
    secondRequest.request_id = std::string(64, '6');
    secondRequest.request_digest = std::string(64, '7');
    auto secondGrantResult = issuer.authenticate("test-relay-credential-that-is-long-enough",
                                                  secondRequest, 1000);
    auto secondGrant = std::get<AnonymousGrant>(secondGrantResult);
    auto second = state.transact(secondRequest, secondGrant, 1000, [](SessionState::Transaction &tx) {
        return tx.allocate("session-a", "region-a", "nonce-b", "key-b");
    });
    EXPECT_TRUE(std::holds_alternative<StateResult>(first));
    EXPECT_TRUE(std::holds_alternative<StateResult>(second));
    if (std::holds_alternative<StateResult>(first) && std::holds_alternative<StateResult>(second)) {
        EXPECT_TRUE(std::get<StateResult>(second).generation > std::get<StateResult>(first).generation);
        EXPECT_TRUE(std::get<StateResult>(second).counter > std::get<StateResult>(first).counter);
    }
    auto expired = state.transact(facts(), grant, 2000, [](SessionState::Transaction &tx) {
        return tx.allocate("session-c", "region-a", "nonce-c", "key-c");
    });
    EXPECT_TRUE(std::holds_alternative<BackendError>(expired));
}

TEST(session_state_window_chain_is_contiguous_idempotent_and_fail_closed) {
    SessionState sessions;
    auto initial = facts();
    RelayAuthenticator issuer("test-relay-credential-that-is-long-enough", 10000);
    auto initialGrant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", initial, 1000));
    openTestSession(sessions, initial, initialGrant);

    using WindowInput = std::pair<WindowPreflightInput, WindowFinalizeInput>;
    const auto transactWindow = [&](RequestFacts request, WindowInput input,
                                    std::uint64_t now = 1000,
                                    bool *expensive = nullptr) {
        auto grant = std::get<AnonymousGrant>(issuer.authenticate(
            "test-relay-credential-that-is-long-enough", request, 1000));
        return sessions.transact(request, grant, now,
            [input = std::move(input), expensive](SessionState::Transaction &tx) mutable {
                tx.preflightWindow(std::move(input.first));
                if (expensive) *expensive = true;
                return tx.finalizeWindow(std::move(input.second));
            });
    };
    const auto input = [](std::uint64_t window, std::string previous, std::string next,
                          std::string response = "response") {
        WindowPreflightInput preflight;
        preflight.session_id = "session-a";
        preflight.region_id = kRegion;
        preflight.generation = 7;
        preflight.window_id = window;
        preflight.previous_state = std::move(previous);
        preflight.expires_at_ms = 1700;
        WindowFinalizeInput finalize;
        finalize.next_state = std::move(next);
        finalize.encoded_response.assign(
            reinterpret_cast<const std::byte *>(response.data()),
            reinterpret_cast<const std::byte *>(response.data() + response.size()));
        return WindowInput{std::move(preflight), std::move(finalize)};
    };
    const auto request = [](char id, char digest) {
        auto value = facts();
        value.request_id = std::string(64, id);
        value.request_digest = std::string(64, digest);
        return value;
    };

    auto firstRequest = request('c', 'd');
    auto first = transactWindow(firstRequest, input(1, "genesis-state", "state-one", "exact-one"));
    EXPECT_TRUE(std::holds_alternative<StateResult>(first));
    bool retryCalled = false;
    auto firstGrant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", firstRequest, 1000));
    auto retry = sessions.transact(firstRequest, firstGrant, 1000,
        [&](SessionState::Transaction &) {
            retryCalled = true;
            return StateResult{};
        });
    EXPECT_FALSE(retryCalled);
    EXPECT_TRUE(std::holds_alternative<StateResult>(retry));
    if (std::holds_alternative<StateResult>(first) && std::holds_alternative<StateResult>(retry))
        EXPECT_TRUE(std::get<StateResult>(first).response == std::get<StateResult>(retry).response);

    bool expiredRetryCalled = false;
    auto expiredRetry = sessions.transact(firstRequest, firstGrant, 1700,
        [&](SessionState::Transaction &) {
            expiredRetryCalled = true;
            return StateResult{};
        });
    EXPECT_FALSE(expiredRetryCalled);
    EXPECT_TRUE(std::holds_alternative<BackendError>(expiredRetry));

    auto conflictRequest = firstRequest;
    conflictRequest.request_digest = std::string(64, 'e');
    auto conflictGrant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", conflictRequest, 1000));
    auto conflict = sessions.transact(conflictRequest, conflictGrant, 1000,
        [](SessionState::Transaction &) { return StateResult{}; });
    EXPECT_TRUE(std::holds_alternative<BackendError>(conflict));
    if (const auto *error = std::get_if<BackendError>(&conflict))
        EXPECT_TRUE(error->code == "request_conflict");

    bool expensive = false;
    auto duplicate = transactWindow(
        request('f', '1'), input(1, "genesis-state", "duplicate"), 1000, &expensive);
    EXPECT_TRUE(std::holds_alternative<BackendError>(duplicate));
    EXPECT_FALSE(expensive);
    auto skipped = transactWindow(
        request('g', '2'), input(3, "state-one", "skipped"), 1000, &expensive);
    EXPECT_TRUE(std::holds_alternative<BackendError>(skipped));
    EXPECT_FALSE(expensive);
    auto rollback = transactWindow(request('h', '3'), input(0, "state-one", "rollback"));
    EXPECT_TRUE(std::holds_alternative<BackendError>(rollback));

    auto wrongGenerationInput = input(2, "state-one", "wrong-generation");
    wrongGenerationInput.first.generation = 6;
    auto wrongGeneration = transactWindow(
        request('i', '4'), std::move(wrongGenerationInput), 1000, &expensive);
    EXPECT_TRUE(std::holds_alternative<BackendError>(wrongGeneration));
    EXPECT_FALSE(expensive);
    auto wrongState = transactWindow(
        request('j', '5'), input(2, "wrong-state", "wrong-next"), 1000, &expensive);
    EXPECT_TRUE(std::holds_alternative<BackendError>(wrongState));
    EXPECT_FALSE(expensive);
    auto wrongIdentityInput = input(2, "state-one", "wrong-identity");
    wrongIdentityInput.first.region_id = std::string(64, '9');
    auto wrongIdentity = transactWindow(
        request('k', '6'), std::move(wrongIdentityInput), 1000, &expensive);
    EXPECT_TRUE(std::holds_alternative<BackendError>(wrongIdentity));
    EXPECT_FALSE(expensive);
    auto expiredInput = input(2, "state-one", "expired");
    expiredInput.first.expires_at_ms = 1000;
    auto expired = transactWindow(request('l', '7'), std::move(expiredInput));
    EXPECT_TRUE(std::holds_alternative<BackendError>(expired));

    auto abandonedRequest = request('n', '9');
    auto abandonedGrant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", abandonedRequest, 1000));
    auto abandonedInput = input(2, "state-one", "never-finalized");
    auto abandoned = sessions.transact(abandonedRequest, abandonedGrant, 1000,
        [abandonedInput](SessionState::Transaction &tx) mutable {
            tx.preflightWindow(std::move(abandonedInput.first));
            return StateResult{};
        });
    EXPECT_TRUE(hasError(abandoned, "window_invalid"));
    bool abandonedRetryCalled = false;
    auto abandonedRetry = sessions.transact(abandonedRequest, abandonedGrant, 1000,
        [&](SessionState::Transaction &tx) {
            abandonedRetryCalled = true;
            auto retryInput = input(2, "state-one", "state-two", "exact-two");
            tx.preflightWindow(std::move(retryInput.first));
            return tx.finalizeWindow(std::move(retryInput.second));
        });
    EXPECT_TRUE(abandonedRetryCalled);
    EXPECT_TRUE(std::holds_alternative<StateResult>(abandonedRetry));

    auto second = transactWindow(request('m', '8'), input(3, "state-two", "state-three", "exact-three"));
    EXPECT_TRUE(std::holds_alternative<StateResult>(second));
}

TEST(session_state_does_not_cache_failed_commit) {
    SessionState state;
    auto request = facts();
    RelayAuthenticator issuer("test-relay-credential-that-is-long-enough");
    auto grantResult = issuer.authenticate("test-relay-credential-that-is-long-enough", request, 1000);
    auto grant = std::get<AnonymousGrant>(grantResult);
    openTestSession(state, request, grant);
    auto failed = state.transact(request, grant, 1000, [](SessionState::Transaction &tx) {
        tx.allocate("session-a", "region-a", "nonce-a", "key-a");
        throw std::runtime_error("wal_sync_failed");
        return StateResult{};
    });
    EXPECT_TRUE(std::holds_alternative<BackendError>(failed));
    auto retry = state.transact(request, grant, 1000, [](SessionState::Transaction &tx) {
        return tx.allocate("session-a", "region-a", "nonce-a", "key-a");
    });
    EXPECT_TRUE(std::holds_alternative<StateResult>(retry));
}

TEST(session_state_closes_sessions_and_rejects_expired_or_replayed_server_values) {
    SessionState state;
    auto request = facts("session.open");
    RelayAuthenticator issuer("test-relay-credential-that-is-long-enough", 1000);
    auto grant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", request, 1000));
    auto opened = state.transact(request, grant, 1000, [](SessionState::Transaction &tx) {
        return tx.openSession("session-id", "epoch-id", 1800,
                              "server-nonce", "server-key", "client-nonce", "client-key");
    });
    EXPECT_TRUE(std::holds_alternative<StateResult>(opened));
    auto closedRequest = facts("session.close");
    closedRequest.request_id = std::string(64, '6');
    closedRequest.request_digest = std::string(64, '7');
    auto closeGrant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", closedRequest, 1000));
    auto closed = state.transact(closedRequest, closeGrant, 1000,
        [](SessionState::Transaction &tx) {
            return tx.closeSession("session-id", "wrong-epoch", 1100, "server-nonce-2", "server-key-2",
                                   "client-nonce", "client-key");
        });
    EXPECT_TRUE(std::holds_alternative<BackendError>(closed));
    closedRequest.request_id = std::string(64, 'a');
    closedRequest.request_digest = std::string(64, 'b');
    closeGrant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", closedRequest, 1000));
    closed = state.transact(closedRequest, closeGrant, 1000,
        [](SessionState::Transaction &tx) {
            return tx.closeSession("session-id", "epoch-id", 1100, "server-nonce-3", "server-key-3",
                                   "client-nonce-2", "client-key-2");
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(closed));
    auto repeatedServer = facts();
    repeatedServer.request_id = std::string(64, '8');
    repeatedServer.request_digest = std::string(64, '9');
    auto repeatedGrant = std::get<AnonymousGrant>(issuer.authenticate(
        "test-relay-credential-that-is-long-enough", repeatedServer, 1000));
    auto replay = state.transact(repeatedServer, repeatedGrant, 1000,
        [](SessionState::Transaction &tx) {
            return tx.claimServer("server-nonce", "different-server-key");
        });
    EXPECT_TRUE(std::holds_alternative<BackendError>(replay));
}

TEST(protocol_service_holds_issuance_guard_through_durable_commit) {
    RequestFacts input = facts();
    RelayAuthenticator issuer("test-relay-credential-that-is-long-enough");
    auto grantResult = issuer.authenticate("test-relay-credential-that-is-long-enough", input, 1000);
    auto grant = std::get<AnonymousGrant>(grantResult);
    auto snapshot = RepositoryTestAccess::snapshot(input);
    SnapshotManager manager(snapshot);
    std::mutex mutex;
    std::condition_variable condition;
    bool commitEntered = false;
    bool releaseSync = false;
    bool revokeFinished = false;
    const auto walPath = std::filesystem::temp_directory_path() /
        ("xovm-service-durable-" + std::to_string(::getpid()) + ".wal");
    std::filesystem::remove(walPath);
    StateWal::IoHooks hooks;
    hooks.sync = [&](int) {
        std::unique_lock lock(mutex);
        commitEntered = true;
        condition.notify_all();
        condition.wait(lock, [&] { return releaseSync; });
        return 0;
    };
    StateWal wal(walPath, std::move(hooks));
    SessionState sessions(&wal);
    ProtocolService service;
    Request request;
    request.value = {{"request_id", input.request_id}, {"software_id", input.software_id},
        {"build_id", input.build_id}, {"final_artifact_hash", input.final_artifact_hash},
        {"type", input.type}, {"region_id", input.region_id}, {"mode", input.mode}};
    auto issuance = std::async(std::launch::async, [&] {
        return service.handle(request, grant, manager, sessions, 1000,
            [](const Request &, const AnonymousGrant &, SessionState::Transaction &) {
                return std::variant<Bytes, BackendError>{Bytes{std::byte{0x41}}};
            });
    });
    {
        std::unique_lock lock(mutex);
        condition.wait(lock, [&] { return commitEntered; });
    }
    auto revoke = std::async(std::launch::async, [&] {
        const bool result = manager.blockBuildWhile(input.build_id, [&] { return true; });
        std::lock_guard lock(mutex);
        revokeFinished = result;
        condition.notify_all();
    });
    RepositoryTestAccess::waitUntilBlocked(manager, input.build_id);
    EXPECT_FALSE(revoke.wait_for(std::chrono::milliseconds(25)) == std::future_status::ready);
    {
        std::lock_guard lock(mutex);
        releaseSync = true;
        condition.notify_all();
    }
    EXPECT_TRUE(issuance.get().index() == 0);
    revoke.get();
    EXPECT_TRUE(revokeFinished);
    std::filesystem::remove(walPath);
}

TEST(protocol_service_refuses_operation_without_downgrade) {
    ProtocolService service;
    auto input = facts("material.issue");
    input.mode = "operation";
    const auto result = service.authorizeMode(input);
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    if (const auto *error = std::get_if<BackendError>(&result))
        EXPECT_TRUE(error->code == "operation_not_implemented");
}

TEST(response_crypto_matches_xovm2_frame_vectors_and_fails_without_signer) {
    using xovm::cloud_material::frameForTest;
    const std::array<std::uint8_t, 32> transcriptHash{};
    const auto framed = frameForTest("XOVM2/response-key", transcriptHash);
    const std::vector<std::uint8_t> expected{
        0x58,0x4f,0x56,0x4d,0x32,0x2f,0x72,0x65,0x73,0x70,0x6f,0x6e,0x73,0x65,
        0x2d,0x6b,0x65,0x79,0x00,0x00,0x00,0x00,0x20};
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(), framed.begin()));
    SigningMetadata unavailable;
    EXPECT_FALSE(unavailable.available());
}

TEST(response_crypto_seals_canonical_envelope_with_injected_ed25519_signer) {
    std::array<std::uint8_t, 32> serverPrivate{};
    std::array<std::uint8_t, 32> clientPrivate{};
    serverPrivate.fill(9);
    clientPrivate.fill(7);
    EVP_PKEY *clientKey = EVP_PKEY_new_raw_private_key_ex(nullptr, "X25519", nullptr,
        clientPrivate.data(), clientPrivate.size());
    std::array<std::uint8_t, 32> clientPublic{};
    size_t publicSize = clientPublic.size();
    EXPECT_TRUE(clientKey && EVP_PKEY_get_raw_public_key(clientKey, clientPublic.data(),
                                                         &publicSize) == 1);
    EVP_PKEY_free(clientKey);
    EVP_PKEY_CTX *edContext = EVP_PKEY_CTX_new_from_name(nullptr, "ED25519", nullptr);
    EVP_PKEY *edKey = nullptr;
    EXPECT_TRUE(edContext && EVP_PKEY_keygen_init(edContext) == 1 &&
                EVP_PKEY_generate(edContext, &edKey) == 1);
    EVP_PKEY_CTX_free(edContext);
    SignEd25519 signer = [edKey](std::span<const std::uint8_t> input)
        -> std::variant<std::array<std::uint8_t, 64>, BackendError> {
        std::array<std::uint8_t, 64> signature{};
        EVP_MD_CTX *context = EVP_MD_CTX_new();
        size_t size = signature.size();
        const bool ok = context && EVP_DigestSignInit(context, nullptr, nullptr, nullptr, edKey) == 1 &&
            EVP_DigestSign(context, signature.data(), &size, input.data(), input.size()) == 1 &&
            size == signature.size();
        EVP_MD_CTX_free(context);
        return ok ? std::variant<std::array<std::uint8_t, 64>, BackendError>{signature}
                  : std::variant<std::array<std::uint8_t, 64>, BackendError>{BackendError{"sign_failed"}};
    };
    nlohmann::json transcript{{"protocol_version", 2}, {"suite", kProtocolSuite},
                              {"type", "session.open"}, {"payload_hash", std::string(64, '0')}};
    const std::string plaintext = "{\"format_version\":1}";
    auto sealed = sealResponse(transcript,
        {reinterpret_cast<const std::byte *>(plaintext.data()), plaintext.size()},
        clientPublic, serverPrivate, signer);
    EXPECT_TRUE(std::holds_alternative<Bytes>(sealed));
    if (std::holds_alternative<Bytes>(sealed)) {
        const std::string encoded(reinterpret_cast<const char *>(std::get<Bytes>(sealed).data()),
                                  std::get<Bytes>(sealed).size());
        EXPECT_TRUE(encoded.starts_with("{\"ciphertext\":"));
        EXPECT_TRUE(encoded.find("\"transcript\":{\"payload_hash\":") != std::string::npos);
        const auto envelope = nlohmann::json::parse(encoded);
        EXPECT_TRUE(envelope.size() == 4);
        EXPECT_TRUE(envelope.at("transcript").at("payload_hash") == std::string(64, '0'));
    }
    EVP_PKEY_free(edKey);
}

TEST(protocol_service_byte_handler_parses_authenticates_and_fails_closed) {
    ProtocolService service;
    auto result = service.handle(std::span<const std::byte>{}, "wrong");
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    if (const auto *error = std::get_if<BackendError>(&result))
        EXPECT_TRUE(error->code == "invalid_canonical");
}

TEST(protocol_service_control_request_requires_trusted_control_authority) {
    auto input = facts("session.open");
    auto snapshot = RepositoryTestAccess::snapshot(input);
    SnapshotManager snapshots(snapshot);
    SessionState sessions;
    RelayAuthenticator relay("relay-secret-long-enough-for-tests");
    AnonymousPolicy policy;
    policy.setRule(input.build_id, AnonymousPolicy::BuildRule{
        .software_id = input.software_id,
        .final_artifact_hash = input.final_artifact_hash,
        .regions = {kRegion}, .modes = {"lease"},
        .valid_until_ms = 900000, .revision = 0, .request_budget = 100, .enabled = true});
    ProtocolService::Providers providers;
    providers.relay_authenticator = &relay;
    providers.anonymous_policy = &policy;
    providers.snapshots = &snapshots;
    providers.state = &sessions;
    providers.trusted_now = [] {
        return std::variant<std::uint64_t, BackendError>{std::uint64_t{1000}};
    };
    auto randomSequence = std::make_shared<std::uint8_t>(0x21);
    providers.random_bytes = [randomSequence](std::size_t size)
        -> std::variant<Bytes, BackendError> {
        Bytes bytes(size, static_cast<std::byte>((*randomSequence)++));
        return bytes;
    };
    ProtocolService service(std::move(providers));
    const std::string request = "{\"build_id\":\"" + input.build_id +
        "\",\"client_ephemeral_key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"client_nonce\":\"" +
        std::string(64, '2') + "\",\"final_artifact_hash\":\"" + input.final_artifact_hash +
        "\",\"protocol_version\":2,\"request_id\":\"" + std::string(64, '4') +
        "\",\"software_id\":\"" + input.software_id + "\",\"suite\":\"" +
        kProtocolSuite + "\",\"type\":\"session.open\"}";
    const auto bytes = std::span(reinterpret_cast<const std::byte *>(request.data()), request.size());
    auto result = service.handle(bytes, "relay-secret-long-enough-for-tests");
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    if (const auto *error = std::get_if<BackendError>(&result))
        EXPECT_TRUE(error->code == "authority_unavailable");
}

TEST(protocol_service_byte_handler_seals_a_valid_material_request) {
    auto input = facts();
    auto snapshot = RepositoryTestAccess::snapshot(input);
    SnapshotManager snapshots(snapshot);
    SessionState sessions;
    RelayAuthenticator relay("relay-secret-long-enough-for-tests");
    AnonymousPolicy policy;
    policy.setRule(input.build_id, AnonymousPolicy::BuildRule{
        .software_id = input.software_id,
        .final_artifact_hash = input.final_artifact_hash,
        .regions = {input.region_id}, .modes = {input.mode},
        .valid_until_ms = 900000, .revision = 0, .request_budget = 100, .enabled = true});
    const std::array<std::uint8_t, 32> edSeed{};
    EVP_PKEY *edKey = EVP_PKEY_new_raw_private_key_ex(nullptr, "ED25519", nullptr,
        edSeed.data(), edSeed.size());
    ProtocolService::Providers providers;
    providers.relay_authenticator = &relay;
    providers.anonymous_policy = &policy;
    providers.snapshots = &snapshots;
    providers.state = &sessions;
    providers.trusted_now = [] {
        return std::variant<std::uint64_t, BackendError>{std::uint64_t{1000}};
    };
    auto randomSequence = std::make_shared<std::uint8_t>(0x21);
    providers.random_bytes = [randomSequence](std::size_t size)
        -> std::variant<Bytes, BackendError> {
        return Bytes(size, static_cast<std::byte>((*randomSequence)++));
    };
    providers.signing = {"test-key", 1, 100000, 100000};
    providers.sign = [edKey](std::span<const std::uint8_t> message)
        -> std::variant<std::array<std::uint8_t, 64>, BackendError> {
        std::array<std::uint8_t, 64> signature{};
        EVP_MD_CTX *context = EVP_MD_CTX_new();
        size_t size = signature.size();
        const bool ok = context && EVP_DigestSignInit(context, nullptr, nullptr, nullptr, edKey) == 1 &&
            EVP_DigestSign(context, signature.data(), &size, message.data(), message.size()) == 1 &&
            size == signature.size();
        EVP_MD_CTX_free(context);
        return ok ? std::variant<std::array<std::uint8_t, 64>, BackendError>{signature}
                  : std::variant<std::array<std::uint8_t, 64>, BackendError>{BackendError{"sign_failed"}};
    };
    providers.authorize_control = [](const Request &, const RequestFacts &, std::uint64_t)
        -> std::variant<ProtocolService::ControlAuthorization, BackendError> {
        return ProtocolService::ControlAuthorization{std::string(64, '7'), 80000, 60000};
    };
    providers.build_payload = [input](const Request &request, const RequestFacts &facts,
                                        const BuildSnapshot &, SessionState::Transaction &tx)
        -> std::variant<ProtocolService::IssuedPayload, BackendError> {
        const auto sessionId = request.value.at("session_id").get<std::string>();
        const auto allocated = tx.allocate(sessionId, facts.region_id,
                                           "client-nonce", "client-key");
        ProtocolService::IssuedPayload result;
        result.payload = {{"format_version", 1}};
        result.binding = {{"build_id", facts.build_id}};
        result.session_id = sessionId;
        result.counter_epoch = std::string(64, '7');
        result.counter = allocated.counter;
        result.session_valid_until_ms = 50000;
        return result;
    };
    ProtocolService service(std::move(providers));
    auto openFacts = input;
    openFacts.type = "session.open";
    openFacts.request_id = std::string(64, 'a');
    openFacts.request_digest = std::string(64, 'b');
    std::array<std::uint8_t, 32> clientPrivate{};
    clientPrivate.fill(7);
    EVP_PKEY *clientKey = EVP_PKEY_new_raw_private_key_ex(nullptr, "X25519", nullptr,
        clientPrivate.data(), clientPrivate.size());
    std::array<std::uint8_t, 32> clientPublic{};
    size_t clientPublicSize = clientPublic.size();
    EXPECT_TRUE(clientKey && EVP_PKEY_get_raw_public_key(clientKey, clientPublic.data(),
                                                          &clientPublicSize) == 1);
    EVP_PKEY_free(clientKey);
    std::array<unsigned char, 45> clientPublicBase64{};
    EXPECT_TRUE(EVP_EncodeBlock(clientPublicBase64.data(), clientPublic.data(),
                                clientPublic.size()) == 44);
    const std::string openRequest = "{\"build_id\":\"" + input.build_id +
        "\",\"client_ephemeral_key\":\"" +
        std::string(reinterpret_cast<const char *>(clientPublicBase64.data()), 44) +
        "\",\"client_nonce\":\"" + std::string(64, 'a') +
        "\",\"final_artifact_hash\":\"" + input.final_artifact_hash +
        "\",\"protocol_version\":2,\"request_id\":\"" + std::string(64, 'b') +
        "\",\"software_id\":\"" + input.software_id + "\",\"suite\":\"" +
        kProtocolSuite + "\",\"type\":\"session.open\"}";
    auto opened = service.handle(
        std::span(reinterpret_cast<const std::byte *>(openRequest.data()), openRequest.size()),
        "relay-secret-long-enough-for-tests");
    EXPECT_TRUE(std::holds_alternative<Bytes>(opened));
    std::string sessionId(64, '2');
    if (std::holds_alternative<Bytes>(opened)) {
        const auto &response = std::get<Bytes>(opened);
        const auto envelope = nlohmann::json::parse(
            reinterpret_cast<const char *>(response.data()),
            reinterpret_cast<const char *>(response.data() + response.size()));
        EXPECT_TRUE(envelope.at("transcript").at("type") == "session.open");
        EXPECT_TRUE(envelope.at("transcript").at("binding").at("control_valid_for_ms") == 60000);
        EXPECT_TRUE(envelope.at("transcript").at("accept_for_ms") == 60000);
        sessionId = envelope.at("transcript").at("session_id").get<std::string>();
    }
    const std::string replayedOpen = openRequest.substr(0, openRequest.find(
        std::string(64, 'b'))) + std::string(64, 'c') + openRequest.substr(
        openRequest.find(std::string(64, 'b')) + 64);
    auto replayed = service.handle(
        std::span(reinterpret_cast<const std::byte *>(replayedOpen.data()), replayedOpen.size()),
        "relay-secret-long-enough-for-tests");
    EXPECT_TRUE(std::holds_alternative<BackendError>(replayed));
    if (const auto *error = std::get_if<BackendError>(&replayed)) {
        EXPECT_TRUE(error->code == "replay_detected");
    }
    clientPrivate.fill(8);
    clientKey = EVP_PKEY_new_raw_private_key_ex(nullptr, "X25519", nullptr,
        clientPrivate.data(), clientPrivate.size());
    clientPublicSize = clientPublic.size();
    EXPECT_TRUE(clientKey && EVP_PKEY_get_raw_public_key(clientKey, clientPublic.data(),
                                                          &clientPublicSize) == 1);
    EVP_PKEY_free(clientKey);
    EXPECT_TRUE(EVP_EncodeBlock(clientPublicBase64.data(), clientPublic.data(),
                                clientPublic.size()) == 44);
    const std::string request = "{\"build_id\":\"" + input.build_id +
        "\",\"client_ephemeral_key\":\"" +
        std::string(reinterpret_cast<const char *>(clientPublicBase64.data()), 44) +
        "\",\"client_nonce\":\"" +
        std::string(64, 'c') + "\",\"counter_epoch\":\"" + std::string(64, '7') +
        "\",\"engine_abi_hash\":\"" + std::string(64, '8') +
        "\",\"final_artifact_hash\":\"" + input.final_artifact_hash +
        "\",\"mode\":\"lease\",\"previous_generation\":\"0\",\"protocol_version\":2,\"region_id\":\"" +
        input.region_id + "\",\"request_id\":\"" + input.request_id + "\",\"session_id\":\"" +
        sessionId + "\",\"software_id\":\"" + input.software_id +
        "\",\"suite\":\"" + kProtocolSuite + "\",\"type\":\"material.issue\"}";
    const auto requestBytes = std::span(reinterpret_cast<const std::byte *>(request.data()), request.size());
    auto result = service.handle(requestBytes, "relay-secret-long-enough-for-tests");
    EXPECT_TRUE(std::holds_alternative<Bytes>(result));
    if (std::holds_alternative<Bytes>(result)) {
        const auto &encoded = std::get<Bytes>(result);
        const auto envelope = nlohmann::json::parse(reinterpret_cast<const char *>(encoded.data()),
                                                     reinterpret_cast<const char *>(encoded.data() + encoded.size()));
        EXPECT_TRUE(envelope.size() == 4);
        EXPECT_TRUE(envelope.at("transcript").contains("payload_hash"));
    }
    EVP_PKEY_free(edKey);
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
    run("anonymous_policy_denies_by_default", anonymous_policy_denies_by_default);
    run("relay_authentication_uses_fixed_backend_subject_and_scopes",
        relay_authentication_uses_fixed_backend_subject_and_scopes);
    run("anonymous_policy_denies_unregistered_revoked_mismatched_and_expired_builds",
        anonymous_policy_denies_unregistered_revoked_mismatched_and_expired_builds);
    run("anonymous_policy_authorizes_session_control_without_material_scope_fields",
        anonymous_policy_authorizes_session_control_without_material_scope_fields);
    run("anonymous_policy_idempotently_accounts_canonical_requests",
        anonymous_policy_idempotently_accounts_canonical_requests);
    run("anonymous_policy_serializes_concurrent_exact_retries",
        anonymous_policy_serializes_concurrent_exact_retries);
    run("anonymous_policy_cache_is_bounded_and_rule_replacement_resets_it",
        anonymous_policy_cache_is_bounded_and_rule_replacement_resets_it);
    run("anonymous_policy_reservation_rolls_back_and_survives_policy_replacement",
        anonymous_policy_reservation_rolls_back_and_survives_policy_replacement);
    run("relay_authentication_rejects_wrong_credential", relay_authentication_rejects_wrong_credential);
    run("raw_session_registration_is_fresh_only_and_anchors_genesis",
        raw_session_registration_is_fresh_only_and_anchors_genesis);
    run("raw_session_registration_rejects_invalid_metadata_and_collisions",
        raw_session_registration_rejects_invalid_metadata_and_collisions);
    run("session_state_is_idempotent_and_rejects_replay_and_reuse",
        session_state_is_idempotent_and_rejects_replay_and_reuse);
    run("session_state_cached_replies_require_live_matching_session_identity",
        session_state_cached_replies_require_live_matching_session_identity);
    run("session_state_capacity_counts_exact_response_bytes_atomically",
        session_state_capacity_counts_exact_response_bytes_atomically);
    run("session_state_idempotency_key_includes_release_binding",
        session_state_idempotency_key_includes_release_binding);
    run("session_state_generations_counters_and_expiry_are_bounded",
        session_state_generations_counters_and_expiry_are_bounded);
    run("session_state_window_chain_is_contiguous_idempotent_and_fail_closed",
        session_state_window_chain_is_contiguous_idempotent_and_fail_closed);
    run("session_state_does_not_cache_failed_commit", session_state_does_not_cache_failed_commit);
    run("session_state_closes_sessions_and_rejects_expired_or_replayed_server_values",
        session_state_closes_sessions_and_rejects_expired_or_replayed_server_values);
    run("protocol_service_holds_issuance_guard_through_durable_commit",
        protocol_service_holds_issuance_guard_through_durable_commit);
    run("protocol_service_refuses_operation_without_downgrade",
        protocol_service_refuses_operation_without_downgrade);
    run("response_crypto_matches_xovm2_frame_vectors_and_fails_without_signer",
        response_crypto_matches_xovm2_frame_vectors_and_fails_without_signer);
    run("response_crypto_seals_canonical_envelope_with_injected_ed25519_signer",
        response_crypto_seals_canonical_envelope_with_injected_ed25519_signer);
    run("protocol_service_byte_handler_parses_authenticates_and_fails_closed",
        protocol_service_byte_handler_parses_authenticates_and_fails_closed);
    run("protocol_service_control_request_requires_trusted_control_authority",
        protocol_service_control_request_requires_trusted_control_authority);
    run("protocol_service_byte_handler_seals_a_valid_material_request",
        protocol_service_byte_handler_seals_a_valid_material_request);
    std::fprintf(stdout, "25 tests, %u assertions, %u failures\n", state.assertions, state.failures);
    return state.failures == 0 ? 0 : 1;
}
