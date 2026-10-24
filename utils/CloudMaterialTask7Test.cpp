#include "auth_policy.h"
#include "checkpoint.h"
#include "session_state.h"
#include "state_wal.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <string_view>
#include <unistd.h>
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

std::filesystem::path pathFor(const char *name) {
    return std::filesystem::temp_directory_path() /
        (std::string("xovm-task7-") + name + "-" + std::to_string(::getpid()));
}

std::vector<std::byte> bytes(std::string_view value) {
    std::vector<std::byte> result;
    for (const auto byte : value) result.push_back(static_cast<std::byte>(byte));
    return result;
}

RequestFacts issueFacts() {
    RequestFacts facts;
    facts.request_id = std::string(64, '1');
    facts.request_digest = std::string(64, '2');
    facts.software_id = "test.software";
    facts.build_id = std::string(64, '3');
    facts.final_artifact_hash = std::string(64, '4');
    facts.region_id = std::string(64, '5');
    facts.mode = "lease";
    facts.type = "material.issue";
    return facts;
}

RequestFacts openFactsFor(const RequestFacts &material) {
    auto facts = material;
    facts.request_id = std::string(64, 'a');
    facts.request_digest = std::string(64, 'b');
    facts.type = "session.open";
    facts.region_id.clear();
    facts.mode.clear();
    return facts;
}

TEST(restart_replays_exact_response_from_backup_copy) {
    const auto directory = pathFor("restart");
    const auto backup = pathFor("restart-backup");
    std::filesystem::remove_all(directory);
    std::filesystem::remove_all(backup);
    std::filesystem::create_directories(directory);
    std::filesystem::create_directories(backup);
    const auto walPath = directory / "state.wal";
    const auto backupWal = backup / "state.wal";
    StateWal wal(walPath);
    SessionState first(&wal);
    const auto facts = issueFacts();
    RelayAuthenticator authenticator("task7-relay-credential-long-enough", 100000);
    const auto openFacts = openFactsFor(facts);
    const auto openGrant = std::get<AnonymousGrant>(authenticator.authenticate(
        "task7-relay-credential-long-enough", openFacts, 1000));
    auto opened = first.transact(openFacts, openGrant, 1000,
        [](SessionState::Transaction &tx) {
            return tx.openSession("session-id", "epoch-id", 50000,
                                  "server-nonce", "server-key", "client-nonce", "client-key");
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(opened));
    const auto grant = std::get<AnonymousGrant>(authenticator.authenticate(
        "task7-relay-credential-long-enough", facts, 1000));
    const auto expected = bytes("task7-exact-response");
    auto result = first.transact(facts, grant, 1000, [&](SessionState::Transaction &tx) {
        auto stateResult = tx.allocate("session-id", facts.region_id, "issue-client-nonce",
                                      "issue-client-key");
        tx.setResponse(expected);
        return stateResult;
    });
    EXPECT_TRUE(std::holds_alternative<StateResult>(result));
    std::filesystem::copy_file(walPath, backupWal, std::filesystem::copy_options::overwrite_existing);
    StateWal restoredWal(backupWal);
    SessionState restarted(&restoredWal);
    auto recoveredWal = restoredWal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recoveredWal));
    if (std::holds_alternative<RecoveredState>(recoveredWal)) {
        EXPECT_TRUE(std::holds_alternative<std::monostate>(
            restarted.restore(std::get<RecoveredState>(recoveredWal))));
        bool callbackCalled = false;
        auto retry = restarted.transact(facts, grant, 1000,
            [&](SessionState::Transaction &) {
                callbackCalled = true;
                return StateResult{};
            });
        EXPECT_FALSE(callbackCalled);
        EXPECT_TRUE(std::holds_alternative<StateResult>(retry));
        if (std::holds_alternative<StateResult>(retry))
            EXPECT_TRUE(std::get<StateResult>(retry).response == expected);
    }
    std::filesystem::remove_all(directory);
    std::filesystem::remove_all(backup);
}

TEST(checkpoint_backup_restore_keeps_sequence_continuity) {
    const auto directory = pathFor("checkpoint");
    const auto backup = pathFor("checkpoint-backup");
    std::filesystem::remove_all(directory);
    std::filesystem::remove_all(backup);
    std::filesystem::create_directories(directory);
    std::filesystem::create_directories(backup);
    const auto walPath = directory / "state.wal";
    const auto checkpointPath = directory / "checkpoint.bin";
    StateWal wal(walPath);
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(
        wal.appendAndSync(1, StateDelta{bytes("state-one")}, bytes("response-one"))));
    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (std::holds_alternative<RecoveredState>(recovered)) {
        Checkpoint checkpoint(checkpointPath, walPath);
        EXPECT_TRUE(std::holds_alternative<std::uint64_t>(
            checkpoint.writeAtomic(std::get<RecoveredState>(recovered), 1)));
        std::filesystem::copy_file(checkpointPath, backup / "checkpoint.bin");
        if (std::filesystem::exists(walPath))
            std::filesystem::copy_file(walPath, backup / "state.wal");
        std::filesystem::remove(checkpointPath);
        std::filesystem::remove(walPath);
        Checkpoint restored(backup / "checkpoint.bin", backup / "state.wal");
        auto state = restored.recover();
        EXPECT_TRUE(std::holds_alternative<RecoveredState>(state));
        if (std::holds_alternative<RecoveredState>(state)) {
            EXPECT_TRUE(std::get<RecoveredState>(state).last_sequence == 1);
            StateWal continued(backup / "state.wal", {}, 1);
            EXPECT_TRUE(std::holds_alternative<std::uint64_t>(
                continued.appendAndSync(2, StateDelta{bytes("state-two")}, bytes("response-two"))));
        }
    }
    std::filesystem::remove_all(directory);
    std::filesystem::remove_all(backup);
}

TEST(disk_full_write_does_not_publish_state) {
    const auto path = pathFor("disk-full");
    std::filesystem::remove(path);
    StateWal::IoHooks hooks;
    hooks.write = [](int, std::span<const std::byte>) -> ssize_t { return -1; };
    StateWal wal(path, std::move(hooks));
    SessionState stateStore(&wal);
    const auto facts = issueFacts();
    RelayAuthenticator authenticator("task7-relay-credential-long-enough", 100000);
    const auto grant = std::get<AnonymousGrant>(authenticator.authenticate(
        "task7-relay-credential-long-enough", facts, 1000));
    auto failed = stateStore.transact(facts, grant, 1000, [](SessionState::Transaction &tx) {
        return tx.allocate("session-id", std::string(64, '5'), "nonce", "key");
    });
    EXPECT_TRUE(std::holds_alternative<BackendError>(failed));
    EXPECT_FALSE(std::filesystem::exists(path) && std::filesystem::file_size(path) != 0);
    std::filesystem::remove(path);
}

TEST(credential_rotation_accepts_only_the_new_credential) {
    const auto facts = issueFacts();
    RelayAuthenticator oldAuthenticator("task7-old-relay-credential-long-enough", 100000);
    RelayAuthenticator newAuthenticator("task7-new-relay-credential-long-enough", 100000);
    EXPECT_TRUE(std::holds_alternative<AnonymousGrant>(oldAuthenticator.authenticate(
        "task7-old-relay-credential-long-enough", facts, 1000)));
    EXPECT_TRUE(std::holds_alternative<BackendError>(newAuthenticator.authenticate(
        "task7-old-relay-credential-long-enough", facts, 1000)));
    EXPECT_TRUE(std::holds_alternative<BackendError>(oldAuthenticator.authenticate(
        "task7-new-relay-credential-long-enough", facts, 1000)));
    EXPECT_TRUE(std::holds_alternative<AnonymousGrant>(newAuthenticator.authenticate(
        "task7-new-relay-credential-long-enough", facts, 1000)));
}

TEST(wal_append_measurement_is_reported) {
    const auto path = pathFor("performance");
    std::filesystem::remove(path);
    StateWal wal(path);
    constexpr unsigned records = 100;
    const auto started = std::chrono::steady_clock::now();
    for (unsigned sequence = 1; sequence <= records; ++sequence) {
        EXPECT_TRUE(std::holds_alternative<std::uint64_t>(wal.appendAndSync(
            sequence, StateDelta{bytes("bounded-state")}, bytes("bounded-response"))));
    }
    const auto elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started).count();
    std::fprintf(stdout, "task7_wal_append_records=%u elapsed_seconds=%.6f records_per_second=%.2f\n",
                 records, elapsed, records / (elapsed > 0 ? elapsed : 1.0));
    std::filesystem::remove(path);
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
    run("restart_replays_exact_response_from_backup_copy",
        restart_replays_exact_response_from_backup_copy);
    run("checkpoint_backup_restore_keeps_sequence_continuity",
        checkpoint_backup_restore_keeps_sequence_continuity);
    run("disk_full_write_does_not_publish_state", disk_full_write_does_not_publish_state);
    run("credential_rotation_accepts_only_the_new_credential",
        credential_rotation_accepts_only_the_new_credential);
    run("wal_append_measurement_is_reported", wal_append_measurement_is_reported);
    std::fprintf(stdout, "5 tests, %u assertions, %u failures\n",
                 state.assertions, state.failures);
    return state.failures == 0 ? 0 : 1;
}
