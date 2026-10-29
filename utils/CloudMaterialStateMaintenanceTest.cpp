#include "auth_policy.h"
#include "checkpoint.h"
#include "session_state.h"
#include "state_maintenance.h"
#include "state_wal.h"

#include <cstdio>
#include <filesystem>
#include <string>
#include <unistd.h>

namespace {
using namespace xovm::cloud_material;

struct TestState {
    unsigned assertions = 0;
    unsigned failures = 0;
    const char *test_name = "";
};

TestState testState;

bool expect(bool condition, const char *expression, int line) {
    ++testState.assertions;
    if (condition) return true;
    ++testState.failures;
    std::fprintf(stderr, "line %d: %s failed in %s\n", line, expression,
                 testState.test_name);
    return false;
}

#define EXPECT_TRUE(expression) expect(static_cast<bool>(expression), #expression, __LINE__)
#define EXPECT_FALSE(expression) expect(!static_cast<bool>(expression), "!(" #expression ")", __LINE__)
#define TEST(name) static void name()

std::filesystem::path stateDirectory(const char *name) {
    return std::filesystem::temp_directory_path() /
        (std::string("xovm-state-maintenance-") + name + "-" +
         std::to_string(static_cast<long long>(::getpid())));
}

RequestFacts facts(char request) {
    RequestFacts value;
    value.request_id = std::string(64, request);
    value.request_digest = std::string(64, request == 'f' ? 'e' : request + 1);
    value.software_id = "test.software";
    value.build_id = std::string(64, 'b');
    value.final_artifact_hash = std::string(64, 'a');
    value.type = "session.open";
    return value;
}

AnonymousGrant grantFor(const RequestFacts &request) {
    RelayAuthenticator authenticator("maintenance-test-relay-secret-value", 100000);
    return std::get<AnonymousGrant>(authenticator.authenticate(
        "maintenance-test-relay-secret-value", request, 1000));
}

void addReply(SessionState &state, char requestId, std::uint64_t validUntil) {
    const auto request = facts(requestId);
    const auto grant = grantFor(request);
    const auto result = state.transact(
        request, grant, 1000,
        [requestId, validUntil](SessionState::Transaction &transaction) {
            transaction.setResponse(
                {std::byte{'e'}, std::byte{'x'}, std::byte{'a'}, std::byte{'c'},
                 static_cast<std::byte>(requestId)});
            return transaction.openSession(
                std::string("session-") + requestId,
                std::string("epoch-") + requestId, validUntil,
                std::string("server-nonce-") + requestId,
                std::string("server-key-") + requestId,
                std::string("client-nonce-") + requestId,
                std::string("client-key-") + requestId);
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(result));
}

TEST(empty_state_does_not_create_checkpoint_or_wal) {
    const auto directory = stateDirectory("empty");
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory);
    std::filesystem::permissions(directory, std::filesystem::perms::owner_all);
    auto locked = ProcessLock::acquireExistingPrivate(directory);
    EXPECT_TRUE(std::holds_alternative<ProcessLock>(locked));
    auto lock = std::get<ProcessLock>(std::move(locked));
    unsigned calls = 0;
    const auto result = runOfflineStateMaintenance(directory, [&] {
        ++calls;
        return std::variant<std::uint64_t, BackendError>(std::uint64_t{5000});
    }, lock);
    EXPECT_TRUE(std::holds_alternative<StateMaintenanceResult>(result));
    if (const auto *value = std::get_if<StateMaintenanceResult>(&result))
        EXPECT_TRUE(*value == StateMaintenanceResult{});
    EXPECT_TRUE(calls == 1);
    EXPECT_FALSE(std::filesystem::exists(directory / "checkpoint.bin"));
    EXPECT_FALSE(std::filesystem::exists(directory / "state.wal"));
    std::filesystem::remove_all(directory);
}

TEST(one_pass_reclaims_and_rotates_latest_state) {
    const auto directory = stateDirectory("reclaim");
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory);
    std::filesystem::permissions(directory, std::filesystem::perms::owner_all);
    const auto walPath = directory / "state.wal";
    {
        StateWal wal(walPath);
        SessionState state(&wal);
        addReply(state, '1', 5000);
    }

    auto locked = ProcessLock::acquireExistingPrivate(directory);
    EXPECT_TRUE(std::holds_alternative<ProcessLock>(locked));
    auto lock = std::get<ProcessLock>(std::move(locked));
    unsigned calls = 0;
    const auto result = runOfflineStateMaintenance(directory, [&] {
        ++calls;
        return std::variant<std::uint64_t, BackendError>(std::uint64_t{5000});
    }, lock);
    EXPECT_TRUE(std::holds_alternative<StateMaintenanceResult>(result));
    if (const auto *value = std::get_if<StateMaintenanceResult>(&result)) {
        EXPECT_TRUE(value->records_retired == 1);
        EXPECT_TRUE(value->response_bytes_reclaimed == 5);
        EXPECT_TRUE(value->sequence == 2);
        EXPECT_FALSE(value->more_work);
    }
    EXPECT_TRUE(calls == 1);
    EXPECT_FALSE(std::filesystem::exists(walPath));

    Checkpoint checkpoint(directory / "checkpoint.bin", walPath);
    const auto recovered = checkpoint.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (const auto *latest = std::get_if<RecoveredState>(&recovered)) {
        EXPECT_TRUE(latest->records.size() == 1);
        SessionState state;
        EXPECT_TRUE(std::holds_alternative<std::monostate>(state.restore(*latest)));
        bool callbackCalled = false;
        const auto request = facts('1');
        const auto replay = state.transact(
            request, grantFor(request), 5000,
            [&](SessionState::Transaction &) {
                callbackCalled = true;
                return StateResult{};
            });
        const auto *error = std::get_if<BackendError>(&replay);
        EXPECT_TRUE(error && error->code == "request_retired");
        EXPECT_FALSE(callbackCalled);
    }
    std::filesystem::remove_all(directory);
}

TEST(zero_reclamation_rotates_existing_wal_without_new_sequence) {
    const auto directory = stateDirectory("rotate");
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory);
    std::filesystem::permissions(directory, std::filesystem::perms::owner_all);
    const auto walPath = directory / "state.wal";
    {
        StateWal wal(walPath);
        SessionState state(&wal);
        addReply(state, '2', 5000);
    }
    auto locked = ProcessLock::acquireExistingPrivate(directory);
    EXPECT_TRUE(std::holds_alternative<ProcessLock>(locked));
    auto lock = std::get<ProcessLock>(std::move(locked));
    const auto result = runOfflineStateMaintenance(directory, [] {
        return std::variant<std::uint64_t, BackendError>(std::uint64_t{4999});
    }, lock);
    EXPECT_TRUE(std::holds_alternative<StateMaintenanceResult>(result));
    if (const auto *value = std::get_if<StateMaintenanceResult>(&result)) {
        EXPECT_TRUE(value->records_retired == 0);
        EXPECT_TRUE(value->sequence == 1);
        EXPECT_FALSE(value->more_work);
    }
    EXPECT_TRUE(std::filesystem::exists(directory / "checkpoint.bin"));
    EXPECT_FALSE(std::filesystem::exists(walPath));
    std::filesystem::remove_all(directory);
}

template <typename Test>
void run(const char *name, Test test) {
    const unsigned before = testState.failures;
    testState.test_name = name;
    test();
    std::fprintf(testState.failures == before ? stdout : stderr, "[%s] %s\n",
                 testState.failures == before ? "PASS" : "FAIL", name);
}

} // namespace

int main() {
    run("empty_state_does_not_create_checkpoint_or_wal",
        empty_state_does_not_create_checkpoint_or_wal);
    run("one_pass_reclaims_and_rotates_latest_state",
        one_pass_reclaims_and_rotates_latest_state);
    run("zero_reclamation_rotates_existing_wal_without_new_sequence",
        zero_reclamation_rotates_existing_wal_without_new_sequence);
    std::fprintf(stdout, "3 tests, %u assertions, %u failures\n",
                 testState.assertions, testState.failures);
    return testState.failures == 0 ? 0 : 1;
}
