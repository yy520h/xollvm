#include "state_wal.h"
#include "checkpoint.h"
#include "session_state.h"

#include <cstdio>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

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

std::filesystem::path pathFor(const char *name) {
    return std::filesystem::temp_directory_path() /
        (std::string("xovm-cloud-material-") + name + "-" + std::to_string(::getpid()) + ".wal");
}

StateDelta delta(std::string_view value) {
    StateDelta result;
    result.bytes.reserve(value.size());
    for (unsigned char byte : value) result.bytes.push_back(static_cast<std::byte>(byte));
    return result;
}

std::vector<std::byte> bytes(std::string_view value) {
    std::vector<std::byte> result;
    result.reserve(value.size());
    for (unsigned char byte : value) result.push_back(static_cast<std::byte>(byte));
    return result;
}

std::vector<std::byte> readBytes(const std::filesystem::path &path) {
    std::ifstream file(path, std::ios::binary);
    file.seekg(0, std::ios::end);
    const auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<std::byte> result(static_cast<std::size_t>(size));
    file.read(reinterpret_cast<char *>(result.data()), result.size());
    return result;
}

std::uint64_t readBigEndian64(std::span<const std::byte> data, std::size_t offset) {
    std::uint64_t result = 0;
    for (unsigned index = 0; index < 8; ++index)
        result = (result << 8) | std::to_integer<std::uint8_t>(data[offset + index]);
    return result;
}

TEST(wal_appends_and_recovers_exact_delta_and_response) {
    const auto path = pathFor("exact");
    std::filesystem::remove(path);
    StateWal wal(path);
    const auto response = bytes("response-one");
    const auto committed = wal.appendAndSync(1, delta("delta-one"), response);
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(committed));
    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (std::holds_alternative<RecoveredState>(recovered)) {
        const auto &state = std::get<RecoveredState>(recovered);
        EXPECT_TRUE(state.last_sequence == 1);
        EXPECT_TRUE(state.records.size() == 1);
        EXPECT_TRUE(state.records[0].delta.bytes == delta("delta-one").bytes);
        EXPECT_TRUE(state.records[0].response == response);
    }
    std::filesystem::remove(path);
}

TEST(wal_rejects_duplicate_and_out_of_order_sequence) {
    const auto path = pathFor("sequence");
    std::filesystem::remove(path);
    StateWal wal(path);
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(wal.appendAndSync(1, delta("a"), bytes("r"))));
    auto duplicate = wal.appendAndSync(1, delta("b"), bytes("r2"));
    EXPECT_TRUE(std::holds_alternative<BackendError>(duplicate));
    auto gap = wal.appendAndSync(3, delta("c"), bytes("r3"));
    EXPECT_TRUE(std::holds_alternative<BackendError>(gap));
    std::filesystem::remove(path);
}

TEST(wal_rejects_record_over_limit) {
    const auto path = pathFor("limit");
    std::filesystem::remove(path);
    StateWal wal(path);
    StateDelta oversized;
    oversized.bytes.resize(kMaxWalPayload + 1);
    auto result = wal.appendAndSync(1, oversized, {});
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    std::filesystem::remove(path);
}

TEST(wal_rejects_short_write_before_sync) {
    const auto path = pathFor("short-write");
    std::filesystem::remove(path);
    StateWal::IoHooks hooks;
    hooks.write = [](int, std::span<const std::byte> data) {
        return static_cast<ssize_t>(data.size() - 1);
    };
    bool synced = false;
    hooks.sync = [&synced](int) {
        synced = true;
        return 0;
    };
    StateWal wal(path, std::move(hooks));
    auto result = wal.appendAndSync(1, delta("delta"), bytes("response"));
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    EXPECT_FALSE(synced);
    std::filesystem::remove(path);
}

TEST(wal_rejects_sync_failure) {
    const auto path = pathFor("sync-failure");
    std::filesystem::remove(path);
    StateWal::IoHooks hooks;
    hooks.sync = [](int) { return -1; };
    StateWal wal(path, std::move(hooks));
    auto result = wal.appendAndSync(1, delta("delta"), bytes("response"));
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    std::filesystem::remove(path);
}

TEST(wal_sync_failure_rolls_back_uncommitted_frame_for_retry) {
    const auto path = pathFor("sync-retry");
    std::filesystem::remove(path);
    unsigned syncCalls = 0;
    StateWal::IoHooks hooks;
    hooks.sync = [&syncCalls](int) { return ++syncCalls == 1 ? -1 : 0; };
    StateWal wal(path, std::move(hooks));
    auto first = wal.appendAndSync(1, delta("delta"), bytes("response"));
    EXPECT_TRUE(std::holds_alternative<BackendError>(first));
    auto retry = wal.appendAndSync(1, delta("delta"), bytes("response"));
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(retry));
    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (std::holds_alternative<RecoveredState>(recovered))
        EXPECT_TRUE(std::get<RecoveredState>(recovered).records.size() == 1);
    std::filesystem::remove(path);
}

TEST(wal_rejects_complete_checksum_corruption) {
    const auto path = pathFor("checksum");
    std::filesystem::remove(path);
    StateWal wal(path);
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(wal.appendAndSync(1, delta("delta"), bytes("response"))));
    {
        std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
        file.seekp(-1, std::ios::end);
        char value = 0;
        file.write(&value, 1);
    }
    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<BackendError>(recovered));
    std::filesystem::remove(path);
}

TEST(wal_truncates_partial_final_header) {
    const auto path = pathFor("partial-header");
    std::filesystem::remove(path);
    StateWal wal(path);
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(wal.appendAndSync(1, delta("delta"), bytes("response"))));
    const auto completeSize = std::filesystem::file_size(path);
    {
        std::ofstream file(path, std::ios::binary | std::ios::app);
        const std::array<char, 3> partial{'X', 'W', 'A'};
        file.write(partial.data(), partial.size());
    }
    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (std::holds_alternative<RecoveredState>(recovered))
        EXPECT_TRUE(std::get<RecoveredState>(recovered).last_sequence == 1);
    EXPECT_TRUE(std::filesystem::file_size(path) == completeSize);
    std::filesystem::remove(path);
}

TEST(wal_truncates_partial_final_body) {
    const auto path = pathFor("partial-body");
    std::filesystem::remove(path);
    StateWal wal(path);
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(wal.appendAndSync(1, delta("one"), bytes("response-one"))));
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(wal.appendAndSync(2, delta("two"), bytes("response-two"))));
    const auto dataBeforeTruncate = readBytes(path);
    const auto firstFrameSize = readBigEndian64(dataBeforeTruncate, 8);
    const auto completeSize = std::filesystem::file_size(path);
    std::filesystem::resize_file(path, completeSize - 1);
    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (std::holds_alternative<RecoveredState>(recovered)) {
        const auto &state = std::get<RecoveredState>(recovered);
        EXPECT_TRUE(state.last_sequence == 1);
        EXPECT_TRUE(state.records.size() == 1);
    }
    EXPECT_TRUE(std::filesystem::file_size(path) == firstFrameSize);
    EXPECT_TRUE(firstFrameSize < completeSize);
    std::filesystem::remove(path);
}

TEST(wal_rejects_interior_corruption) {
    const auto path = pathFor("interior-corruption");
    std::filesystem::remove(path);
    StateWal wal(path);
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(wal.appendAndSync(1, delta("one"), bytes("response-one"))));
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(wal.appendAndSync(2, delta("two"), bytes("response-two"))));
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(wal.appendAndSync(3, delta("three"), bytes("response-three"))));
    auto data = readBytes(path);
    const auto firstFrameSize = readBigEndian64(data, 8);
    data[static_cast<std::size_t>(firstFrameSize) + 40] ^= std::byte{1};
    {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        file.write(reinterpret_cast<const char *>(data.data()), data.size());
    }
    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<BackendError>(recovered));
    std::filesystem::remove(path);
}

TEST(checkpoint_round_trips_and_retires_covered_wal) {
    const auto walPath = pathFor("checkpoint-wal");
    const auto checkpointPath = pathFor("checkpoint");
    std::filesystem::remove(walPath);
    std::filesystem::remove(checkpointPath);
    StateWal wal(walPath);
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(
        wal.appendAndSync(1, delta("delta"), bytes("response"))));
    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (std::holds_alternative<RecoveredState>(recovered)) {
        Checkpoint checkpoint(checkpointPath, walPath);
        auto written = checkpoint.writeAtomic(std::get<RecoveredState>(recovered), 1);
        EXPECT_TRUE(std::holds_alternative<std::uint64_t>(written));
        EXPECT_FALSE(std::filesystem::exists(walPath));
        auto loaded = checkpoint.recover();
        EXPECT_TRUE(std::holds_alternative<RecoveredState>(loaded));
        if (std::holds_alternative<RecoveredState>(loaded)) {
            EXPECT_TRUE(std::get<RecoveredState>(loaded).last_sequence == 1);
            EXPECT_TRUE(std::get<RecoveredState>(loaded).records[0].response == bytes("response"));
        }
    }
    std::filesystem::remove(walPath);
    std::filesystem::remove(checkpointPath);
}

TEST(checkpoint_rejects_sequence_ahead_of_state) {
    const auto checkpointPath = pathFor("checkpoint-ahead");
    const auto walPath = pathFor("checkpoint-ahead-wal");
    std::filesystem::remove(checkpointPath);
    std::filesystem::remove(walPath);
    Checkpoint checkpoint(checkpointPath, walPath);
    auto result = checkpoint.writeAtomic(RecoveredState{}, 1);
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    std::filesystem::remove(checkpointPath);
}

TEST(checkpoint_rejects_non_monotonic_state_before_write) {
    const auto checkpointPath = pathFor("checkpoint-non-monotonic");
    const auto walPath = pathFor("checkpoint-non-monotonic-wal");
    std::filesystem::remove(checkpointPath);
    std::filesystem::remove(walPath);
    RecoveredState state;
    state.last_sequence = 2;
    state.records = {{2, delta("two"), bytes("response-two")},
                     {1, delta("one"), bytes("response-one")}};
    Checkpoint checkpoint(checkpointPath, walPath);
    auto result = checkpoint.writeAtomic(state, 2);
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    EXPECT_FALSE(std::filesystem::exists(checkpointPath));
    std::filesystem::remove(checkpointPath);
    std::filesystem::remove(walPath);
}

TEST(checkpoint_recovery_falls_back_to_wal_before_first_checkpoint) {
    const auto checkpointPath = pathFor("checkpoint-before-first");
    const auto walPath = pathFor("checkpoint-before-first-wal");
    std::filesystem::remove(checkpointPath);
    std::filesystem::remove(walPath);
    StateWal wal(walPath);
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(
        wal.appendAndSync(1, delta("delta"), bytes("response"))));
    Checkpoint checkpoint(checkpointPath, walPath);
    auto recovered = checkpoint.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (std::holds_alternative<RecoveredState>(recovered)) {
        EXPECT_TRUE(std::get<RecoveredState>(recovered).last_sequence == 1);
        EXPECT_TRUE(std::get<RecoveredState>(recovered).records.size() == 1);
    }
    std::filesystem::remove(checkpointPath);
    std::filesystem::remove(walPath);
}

TEST(checkpoint_directory_sync_failure_precedes_wal_retirement) {
    const auto checkpointPath = pathFor("checkpoint-directory-sync-failure");
    const auto walPath = pathFor("checkpoint-directory-sync-failure-wal");
    std::filesystem::remove(checkpointPath);
    std::filesystem::remove(walPath);
    StateWal wal(walPath);
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(
        wal.appendAndSync(1, delta("delta"), bytes("response"))));
    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (std::holds_alternative<RecoveredState>(recovered)) {
        Checkpoint::IoHooks hooks;
        hooks.syncDirectory = [](const char *) { return -1; };
        Checkpoint checkpoint(checkpointPath, walPath, std::move(hooks));
        auto result = checkpoint.writeAtomic(std::get<RecoveredState>(recovered), 1);
        EXPECT_TRUE(std::holds_alternative<BackendError>(result));
        EXPECT_TRUE(std::filesystem::exists(checkpointPath));
        EXPECT_TRUE(std::filesystem::exists(walPath));
    }
    std::filesystem::remove(checkpointPath);
    std::filesystem::remove(walPath);
}

TEST(checkpoint_retirement_sync_failure_keeps_published_checkpoint) {
    const auto checkpointPath = pathFor("checkpoint-retirement-sync-failure");
    const auto walPath = pathFor("checkpoint-retirement-sync-failure-wal");
    std::filesystem::remove(checkpointPath);
    std::filesystem::remove(walPath);
    StateWal wal(walPath);
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(
        wal.appendAndSync(1, delta("delta"), bytes("response"))));
    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (std::holds_alternative<RecoveredState>(recovered)) {
        unsigned syncCalls = 0;
        Checkpoint::IoHooks hooks;
        hooks.syncDirectory = [&syncCalls](const char *) { return ++syncCalls == 1 ? 0 : -1; };
        Checkpoint checkpoint(checkpointPath, walPath, std::move(hooks));
        auto result = checkpoint.writeAtomic(std::get<RecoveredState>(recovered), 1);
        EXPECT_TRUE(std::holds_alternative<BackendError>(result));
        EXPECT_TRUE(std::filesystem::exists(checkpointPath));
        EXPECT_FALSE(std::filesystem::exists(walPath));
        auto restarted = checkpoint.recover();
        EXPECT_TRUE(std::holds_alternative<RecoveredState>(restarted));
    }
    std::filesystem::remove(checkpointPath);
    std::filesystem::remove(walPath);
}

TEST(checkpoint_short_write_removes_private_temporary_file) {
    const auto checkpointPath = pathFor("checkpoint-short-write");
    const auto walPath = pathFor("checkpoint-short-write-wal");
    std::filesystem::remove(checkpointPath);
    std::filesystem::remove(walPath);
    StateWal wal(walPath);
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(
        wal.appendAndSync(1, delta("delta"), bytes("response"))));
    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (std::holds_alternative<RecoveredState>(recovered)) {
        Checkpoint::IoHooks hooks;
        hooks.write = [](int, std::span<const std::byte> data) {
            return static_cast<ssize_t>(data.size() - 1);
        };
        Checkpoint checkpoint(checkpointPath, walPath, std::move(hooks));
        auto result = checkpoint.writeAtomic(std::get<RecoveredState>(recovered), 1);
        EXPECT_TRUE(std::holds_alternative<BackendError>(result));
        EXPECT_FALSE(std::filesystem::exists(checkpointPath));
        EXPECT_TRUE(std::filesystem::exists(walPath));
    }
    std::filesystem::remove(checkpointPath);
    std::filesystem::remove(walPath);
}

TEST(checkpoint_rename_failure_preserves_wal) {
    const auto walPath = pathFor("checkpoint-rename-failure-wal");
    const auto checkpointPath = pathFor("checkpoint-rename-failure");
    std::filesystem::remove(walPath);
    std::filesystem::remove(checkpointPath);
    StateWal wal(walPath);
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(
        wal.appendAndSync(1, delta("delta"), bytes("response"))));
    Checkpoint::IoHooks hooks;
    hooks.rename = [](const char *, const char *) {
        errno = EIO;
        return -1;
    };
    Checkpoint checkpoint(checkpointPath, walPath, std::move(hooks));
    auto result = checkpoint.writeAtomic(std::get<RecoveredState>(wal.recover()), 1);
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    EXPECT_TRUE(std::filesystem::exists(walPath));
    EXPECT_FALSE(std::filesystem::exists(checkpointPath));
    std::filesystem::remove(walPath);
    std::filesystem::remove(checkpointPath);
}

TEST(checkpoint_recovery_ignores_covered_wal_after_retirement_failure) {
    const auto walPath = pathFor("checkpoint-retirement-failure-wal");
    const auto checkpointPath = pathFor("checkpoint-retirement-failure");
    std::filesystem::remove(walPath);
    std::filesystem::remove(checkpointPath);
    StateWal wal(walPath);
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(
        wal.appendAndSync(1, delta("delta"), bytes("response"))));
    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (std::holds_alternative<RecoveredState>(recovered)) {
        Checkpoint::IoHooks hooks;
        hooks.unlink = [](const char *) {
            errno = EIO;
            return -1;
        };
        Checkpoint checkpoint(checkpointPath, walPath, std::move(hooks));
        auto result = checkpoint.writeAtomic(std::get<RecoveredState>(recovered), 1);
        EXPECT_TRUE(std::holds_alternative<BackendError>(result));
        EXPECT_TRUE(std::filesystem::exists(checkpointPath));
        EXPECT_TRUE(std::filesystem::exists(walPath));
        auto restarted = checkpoint.recover();
        EXPECT_TRUE(std::holds_alternative<RecoveredState>(restarted));
        if (std::holds_alternative<RecoveredState>(restarted)) {
            EXPECT_TRUE(std::get<RecoveredState>(restarted).last_sequence == 1);
            EXPECT_TRUE(std::get<RecoveredState>(restarted).records.size() == 1);
        }
    }
    std::filesystem::remove(walPath);
    std::filesystem::remove(checkpointPath);
}

TEST(wal_continues_after_checkpoint_sequence) {
    const auto walPath = pathFor("checkpoint-continue-wal");
    const auto checkpointPath = pathFor("checkpoint-continue");
    std::filesystem::remove(walPath);
    std::filesystem::remove(checkpointPath);
    StateWal wal(walPath);
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(
        wal.appendAndSync(1, delta("one"), bytes("one-response"))));
    auto state = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(state));
    if (std::holds_alternative<RecoveredState>(state)) {
        Checkpoint checkpoint(checkpointPath, walPath);
        EXPECT_TRUE(std::holds_alternative<std::uint64_t>(
            checkpoint.writeAtomic(std::get<RecoveredState>(state), 1)));
        StateWal continued(walPath, {}, 1);
        auto appended = continued.appendAndSync(2, delta("two"), bytes("two-response"));
        EXPECT_TRUE(std::holds_alternative<std::uint64_t>(appended));
        auto recovered = continued.recover();
        EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
        if (std::holds_alternative<RecoveredState>(recovered)) {
            EXPECT_TRUE(std::get<RecoveredState>(recovered).last_sequence == 2);
            EXPECT_TRUE(std::get<RecoveredState>(recovered).records.size() == 1);
        }
        auto merged = checkpoint.recover();
        EXPECT_TRUE(std::holds_alternative<RecoveredState>(merged));
        if (std::holds_alternative<RecoveredState>(merged)) {
            EXPECT_TRUE(std::get<RecoveredState>(merged).last_sequence == 2);
            EXPECT_TRUE(std::get<RecoveredState>(merged).records.size() == 2);
        }
    }
    std::filesystem::remove(walPath);
    std::filesystem::remove(checkpointPath);
}

TEST(session_state_recovers_exact_cached_response_from_wal) {
    const auto path = pathFor("session-recovery");
    std::filesystem::remove(path);
    StateWal wal(path);
    SessionState state(&wal);
    RequestFacts openFacts;
    openFacts.request_id = std::string(64, '1');
    openFacts.request_digest = std::string(64, '2');
    openFacts.software_id = "test.software";
    openFacts.build_id = std::string(64, '3');
    openFacts.final_artifact_hash = std::string(64, '4');
    openFacts.type = "session.open";
    RelayAuthenticator authenticator("wal-relay-credential-long-enough", 100000);
    auto openGrant = std::get<AnonymousGrant>(authenticator.authenticate(
        "wal-relay-credential-long-enough", openFacts, 1000));
    auto opened = state.transact(openFacts, openGrant, 1000,
        [](SessionState::Transaction &tx) {
            return tx.openSession("session-id", "epoch-id", 50000,
                                  "server-nonce", "server-key", "client-nonce", "client-key");
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(opened));
    RequestFacts issueFacts = openFacts;
    issueFacts.request_id = std::string(64, '5');
    issueFacts.request_digest = std::string(64, '6');
    issueFacts.type = "material.issue";
    issueFacts.region_id = std::string(64, '7');
    issueFacts.mode = "lease";
    auto issueGrant = std::get<AnonymousGrant>(authenticator.authenticate(
        "wal-relay-credential-long-enough", issueFacts, 1000));
    const auto response = bytes("exact-response");
    auto issued = state.transact(issueFacts, issueGrant, 1000,
        [&](SessionState::Transaction &tx) {
            auto result = tx.allocate("session-id", issueFacts.region_id, "issue-nonce", "issue-key");
            tx.setResponse(response);
            return result;
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(issued));
    SessionState restarted(&wal);
    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (std::holds_alternative<RecoveredState>(recovered)) {
        EXPECT_TRUE(std::holds_alternative<std::monostate>(restarted.restore(
            std::get<RecoveredState>(recovered))));
        bool called = false;
        auto retry = restarted.transact(issueFacts, issueGrant, 1000,
            [&](SessionState::Transaction &) {
                called = true;
                return StateResult{};
            });
        EXPECT_FALSE(called);
        EXPECT_TRUE(std::holds_alternative<StateResult>(retry));
        if (std::holds_alternative<StateResult>(issued) &&
            std::holds_alternative<StateResult>(retry)) {
            EXPECT_TRUE(std::get<StateResult>(retry).response == response);
            EXPECT_TRUE(std::get<StateResult>(retry).counter ==
                        std::get<StateResult>(issued).counter);
        }
    }
    std::filesystem::remove(path);
}

TEST(session_state_does_not_publish_when_wal_sync_fails) {
    const auto path = pathFor("session-sync-failure");
    std::filesystem::remove(path);
    StateWal::IoHooks hooks;
    hooks.sync = [](int) { return -1; };
    StateWal wal(path, std::move(hooks));
    SessionState state(&wal);
    RequestFacts facts;
    facts.request_id = std::string(64, '1');
    facts.request_digest = std::string(64, '2');
    facts.software_id = "test.software";
    facts.build_id = std::string(64, '3');
    facts.final_artifact_hash = std::string(64, '4');
    facts.type = "session.open";
    RelayAuthenticator authenticator("wal-relay-credential-long-enough", 100000);
    auto grant = std::get<AnonymousGrant>(authenticator.authenticate(
        "wal-relay-credential-long-enough", facts, 1000));
    unsigned calls = 0;
    auto failed = state.transact(facts, grant, 1000, [&](SessionState::Transaction &tx) {
        ++calls;
        return tx.openSession("session-id", "epoch-id", 50000,
                              "server-nonce", "server-key", "client-nonce", "client-key");
    });
    EXPECT_TRUE(std::holds_alternative<BackendError>(failed));
    auto retried = state.transact(facts, grant, 1000, [&](SessionState::Transaction &tx) {
        ++calls;
        return tx.openSession("session-id", "epoch-id", 50000,
                              "server-nonce-2", "server-key-2", "client-nonce-2", "client-key-2");
    });
    EXPECT_TRUE(std::holds_alternative<BackendError>(retried));
    EXPECT_TRUE(calls == 2);
    std::filesystem::remove(path);
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
    run("wal_appends_and_recovers_exact_delta_and_response",
        wal_appends_and_recovers_exact_delta_and_response);
    run("wal_rejects_duplicate_and_out_of_order_sequence",
        wal_rejects_duplicate_and_out_of_order_sequence);
    run("wal_rejects_record_over_limit", wal_rejects_record_over_limit);
    run("wal_rejects_short_write_before_sync", wal_rejects_short_write_before_sync);
    run("wal_rejects_sync_failure", wal_rejects_sync_failure);
    run("wal_sync_failure_rolls_back_uncommitted_frame_for_retry",
        wal_sync_failure_rolls_back_uncommitted_frame_for_retry);
    run("wal_rejects_complete_checksum_corruption",
        wal_rejects_complete_checksum_corruption);
    run("wal_truncates_partial_final_header", wal_truncates_partial_final_header);
    run("wal_truncates_partial_final_body", wal_truncates_partial_final_body);
    run("wal_rejects_interior_corruption", wal_rejects_interior_corruption);
    run("checkpoint_round_trips_and_retires_covered_wal",
        checkpoint_round_trips_and_retires_covered_wal);
    run("checkpoint_rejects_sequence_ahead_of_state",
        checkpoint_rejects_sequence_ahead_of_state);
    run("checkpoint_rejects_non_monotonic_state_before_write",
        checkpoint_rejects_non_monotonic_state_before_write);
    run("checkpoint_recovery_falls_back_to_wal_before_first_checkpoint",
        checkpoint_recovery_falls_back_to_wal_before_first_checkpoint);
    run("checkpoint_directory_sync_failure_precedes_wal_retirement",
        checkpoint_directory_sync_failure_precedes_wal_retirement);
    run("checkpoint_retirement_sync_failure_keeps_published_checkpoint",
        checkpoint_retirement_sync_failure_keeps_published_checkpoint);
    run("checkpoint_short_write_removes_private_temporary_file",
        checkpoint_short_write_removes_private_temporary_file);
    run("checkpoint_rename_failure_preserves_wal", checkpoint_rename_failure_preserves_wal);
    run("checkpoint_recovery_ignores_covered_wal_after_retirement_failure",
        checkpoint_recovery_ignores_covered_wal_after_retirement_failure);
    run("wal_continues_after_checkpoint_sequence", wal_continues_after_checkpoint_sequence);
    run("session_state_recovers_exact_cached_response_from_wal",
        session_state_recovers_exact_cached_response_from_wal);
    run("session_state_does_not_publish_when_wal_sync_fails",
        session_state_does_not_publish_when_wal_sync_fails);
    std::fprintf(stdout, "22 tests, %u assertions, %u failures\n",
                 state.assertions, state.failures);
    return state.failures == 0 ? 0 : 1;
}
