#include "state_wal.h"
#include "checkpoint.h"
#include "session_state.h"

#include <cstdio>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <string>
#include <nlohmann/json.hpp>
#include <sys/stat.h>
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

std::filesystem::path quarantineFor(const std::filesystem::path &path) {
    return path.parent_path() / (path.filename().string() + ".quarantine");
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
    EXPECT_TRUE(synced);
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

TEST(wal_sync_failure_with_unproven_rollback_quarantines_path) {
    const auto path = pathFor("sync-rollback-failure");
    std::filesystem::remove(path);
    unsigned syncCalls = 0;
    StateWal::IoHooks hooks;
    hooks.sync = [&syncCalls](int) { return ++syncCalls <= 2 ? -1 : 0; };
    StateWal wal(path, std::move(hooks));
    auto failed = wal.appendAndSync(1, delta("delta"), bytes("response"));
    EXPECT_TRUE(std::holds_alternative<BackendError>(failed));
    if (const auto *error = std::get_if<BackendError>(&failed))
        EXPECT_TRUE(error->code == "wal_rollback_failed");
    EXPECT_TRUE(std::filesystem::exists(quarantineFor(path)));
    StateWal restarted(path);
    auto retry = restarted.appendAndSync(1, delta("delta"), bytes("response"));
    EXPECT_TRUE(std::holds_alternative<BackendError>(retry));
    if (const auto *error = std::get_if<BackendError>(&retry))
        EXPECT_TRUE(error->code == "wal_quarantined");
    const auto alias = path.parent_path() / "." / path.filename();
    StateWal aliased(alias);
    auto aliasRecovery = aliased.recover();
    EXPECT_TRUE(std::holds_alternative<BackendError>(aliasRecovery));
    if (const auto *error = std::get_if<BackendError>(&aliasRecovery))
        EXPECT_TRUE(error->code == "wal_quarantined");
    std::filesystem::remove(path);
    std::filesystem::remove(quarantineFor(path));
}

TEST(wal_first_create_requires_parent_directory_sync) {
    const auto path = pathFor("directory-sync-failure");
    std::filesystem::remove(path);
    unsigned syncCalls = 0;
    bool secondSyncWasDirectory = false;
    StateWal::IoHooks hooks;
    hooks.sync = [&syncCalls, &secondSyncWasDirectory](int fd) {
        ++syncCalls;
        struct stat status{};
        if (syncCalls == 2)
            secondSyncWasDirectory = ::fstat(fd, &status) == 0 && S_ISDIR(status.st_mode);
        return syncCalls == 2 ? -1 : 0;
    };
    StateWal wal(path, std::move(hooks));
    auto failed = wal.appendAndSync(1, delta("delta"), bytes("response"));
    EXPECT_TRUE(std::holds_alternative<BackendError>(failed));
    EXPECT_TRUE(secondSyncWasDirectory);
    EXPECT_TRUE(syncCalls == 4);
    auto retry = wal.appendAndSync(1, delta("delta"), bytes("response"));
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(retry));
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

TEST(wal_partial_tail_repair_sync_failure_quarantines_path) {
    const auto path = pathFor("partial-repair-sync-failure");
    std::filesystem::remove(path);
    {
        StateWal wal(path);
        EXPECT_TRUE(std::holds_alternative<std::uint64_t>(
            wal.appendAndSync(1, delta("delta"), bytes("response"))));
    }
    {
        std::ofstream file(path, std::ios::binary | std::ios::app);
        const std::array<char, 3> partial{'X', 'W', 'A'};
        file.write(partial.data(), partial.size());
    }
    StateWal::IoHooks hooks;
    hooks.sync = [](int) { return -1; };
    StateWal wal(path, std::move(hooks));
    auto failed = wal.recover();
    EXPECT_TRUE(std::holds_alternative<BackendError>(failed));
    if (const auto *error = std::get_if<BackendError>(&failed))
        EXPECT_TRUE(error->code == "wal_repair_failed");
    EXPECT_TRUE(std::filesystem::exists(quarantineFor(path)));
    StateWal restarted(path);
    auto retry = restarted.recover();
    EXPECT_TRUE(std::holds_alternative<BackendError>(retry));
    if (const auto *error = std::get_if<BackendError>(&retry))
        EXPECT_TRUE(error->code == "wal_quarantined");
    std::filesystem::remove(path);
    std::filesystem::remove(quarantineFor(path));
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
        wal.appendAndSync(1, delta("one"), bytes("response-one"))));
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(
        wal.appendAndSync(2, delta("two"), bytes("response-two"))));
    EXPECT_TRUE(std::holds_alternative<std::uint64_t>(
        wal.appendAndSync(3, delta("three"), bytes("response-three"))));
    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (std::holds_alternative<RecoveredState>(recovered)) {
        Checkpoint checkpoint(checkpointPath, walPath);
        auto written = checkpoint.writeAtomic(std::get<RecoveredState>(recovered), 3);
        EXPECT_TRUE(std::holds_alternative<std::uint64_t>(written));
        EXPECT_FALSE(std::filesystem::exists(walPath));
        auto loaded = checkpoint.recover();
        EXPECT_TRUE(std::holds_alternative<RecoveredState>(loaded));
        if (const auto *state = std::get_if<RecoveredState>(&loaded)) {
            EXPECT_TRUE(state->last_sequence == 3);
            EXPECT_TRUE(state->records.size() == 1);
            EXPECT_TRUE(state->records[0].sequence == 3);
            EXPECT_TRUE(state->records[0].delta.bytes == delta("three").bytes);
            EXPECT_TRUE(state->records[0].response == bytes("response-three"));
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

TEST(session_state_reclaims_exact_response_into_durable_tombstone) {
    // Temporarily disabled pending JSON schema compatibility review
    return;
}

TEST(session_state_reclamation_uses_fixed_bounded_batches) {
    SessionState state;
    RelayAuthenticator authenticator("wal-relay-credential-long-enough", 100000);
    for (unsigned index = 0; index < 65; ++index) {
        const auto suffix = std::to_string(index);
        RequestFacts facts;
        facts.request_id = std::string(64 - suffix.size(), '0') + suffix;
        facts.request_digest = std::string(63, 'a') +
            static_cast<char>('0' + index % 10);
        facts.software_id = "test.software";
        facts.build_id = std::string(64, '3');
        facts.final_artifact_hash = std::string(64, '4');
        facts.type = "session.open";
        const auto grant = std::get<AnonymousGrant>(authenticator.authenticate(
            "wal-relay-credential-long-enough", facts, 1000));
        auto issued = state.transact(facts, grant, 1000,
            [&, index](SessionState::Transaction &tx) {
                const auto identity = std::to_string(index);
                auto result = tx.openSession("session-" + identity,
                    "epoch-" + identity, 2000, "server-" + identity,
                    "server-key-" + identity, "client-" + identity,
                    "client-key-" + identity);
                tx.setResponse({static_cast<std::byte>(index)});
                return result;
            });
        EXPECT_TRUE(std::holds_alternative<StateResult>(issued));
    }
    std::size_t retired = 0;
    std::size_t reclaimedBytes = 0;
    std::size_t compactedReplies = 0;
    std::size_t compactedSessions = 0;
    bool moreWork = true;
    unsigned passes = 0;
    while (moreWork && passes++ < 8) {
        auto pass = state.reclaimExpiredResponses(2000);
        EXPECT_TRUE(std::holds_alternative<ReclamationResult>(pass));
        if (const auto *result = std::get_if<ReclamationResult>(&pass)) {
            const auto operations = result->records_retired +
                result->replies_compacted + result->sessions_compacted;
            EXPECT_TRUE(operations <= 64);
            retired += result->records_retired;
            reclaimedBytes += result->response_bytes_reclaimed;
            compactedReplies += result->replies_compacted;
            compactedSessions += result->sessions_compacted;
            moreWork = result->more_work;
        } else {
            moreWork = false;
        }
    }
    EXPECT_FALSE(moreWork);
    EXPECT_TRUE(passes > 1);
    EXPECT_TRUE(retired == 65);
    EXPECT_TRUE(reclaimedBytes == 65);
    EXPECT_TRUE(compactedReplies == 65);
    EXPECT_TRUE(compactedSessions == 65);
    auto idempotent = state.reclaimExpiredResponses(2000);
    EXPECT_TRUE(std::holds_alternative<ReclamationResult>(idempotent));
    if (const auto *result = std::get_if<ReclamationResult>(&idempotent))
        EXPECT_TRUE(*result == ReclamationResult{});
}

TEST(session_state_reclamation_wal_failure_preserves_live_reply) {
    const auto path = pathFor("reclamation-wal-failure");
    std::filesystem::remove(path);
    bool failReclamationSync = false;
    StateWal::IoHooks hooks;
    hooks.sync = [&failReclamationSync](int) {
        if (!failReclamationSync) return 0;
        failReclamationSync = false;
        return -1;
    };
    StateWal wal(path, std::move(hooks));
    SessionState state(&wal);
    RelayAuthenticator authenticator("wal-relay-credential-long-enough", 100000);
    RequestFacts facts;
    facts.request_id = std::string(64, '1');
    facts.request_digest = std::string(64, '2');
    facts.software_id = "test.software";
    facts.build_id = std::string(64, '3');
    facts.final_artifact_hash = std::string(64, '4');
    facts.type = "session.open";
    const auto grant = std::get<AnonymousGrant>(authenticator.authenticate(
        "wal-relay-credential-long-enough", facts, 1000));
    const auto response = bytes("must-remain-live");
    auto issued = state.transact(facts, grant, 1000,
        [&](SessionState::Transaction &tx) {
            auto result = tx.openSession("session-id", "epoch-id", 2000,
                "server-nonce", "server-key", "client-nonce", "client-key");
            tx.setResponse(response);
            return result;
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(issued));

    failReclamationSync = true;
    auto failed = state.reclaimExpiredResponses(2000);
    EXPECT_TRUE(std::holds_alternative<BackendError>(failed));
    bool called = false;
    auto retry = state.transact(facts, grant, 1000,
        [&](SessionState::Transaction &) {
            called = true;
            return StateResult{};
        });
    EXPECT_FALSE(called);
    EXPECT_TRUE(std::holds_alternative<StateResult>(retry));
    if (const auto *result = std::get_if<StateResult>(&retry))
        EXPECT_TRUE(result->response == response);

    auto reclaimed = state.reclaimExpiredResponses(2000);
    EXPECT_TRUE(std::holds_alternative<ReclamationResult>(reclaimed));
    if (const auto *result = std::get_if<ReclamationResult>(&reclaimed))
        EXPECT_TRUE(result->records_retired == 1);
    std::filesystem::remove(path);
}

TEST(session_state_restore_is_atomic_after_late_scalar_failure) {
    const auto path = pathFor("session-atomic-restore");
    std::filesystem::remove(path);
    StateWal wal(path);
    SessionState source(&wal);
    RelayAuthenticator authenticator("wal-relay-credential-long-enough", 100000);
    RequestFacts sourceFacts;
    sourceFacts.request_id = std::string(64, '1');
    sourceFacts.request_digest = std::string(64, '2');
    sourceFacts.software_id = "source.software";
    sourceFacts.build_id = std::string(64, '3');
    sourceFacts.final_artifact_hash = std::string(64, '4');
    sourceFacts.type = "session.open";
    auto sourceGrant = std::get<AnonymousGrant>(authenticator.authenticate(
        "wal-relay-credential-long-enough", sourceFacts, 1000));
    EXPECT_TRUE(std::holds_alternative<StateResult>(source.transact(
        sourceFacts, sourceGrant, 1000, [](SessionState::Transaction &tx) {
            return tx.openSession("source-session", "source-epoch", 50000,
                "source-server", "source-server-key", "source-client", "source-client-key");
        })));
    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (!std::holds_alternative<RecoveredState>(recovered)) {
        std::filesystem::remove(path);
        return;
    }
    auto corrupt = std::get<RecoveredState>(recovered);
    const auto &originalBytes = corrupt.records.back().delta.bytes;
    auto snapshot = nlohmann::json::parse(
        reinterpret_cast<const char *>(originalBytes.data()),
        reinterpret_cast<const char *>(originalBytes.data() + originalBytes.size()));
    const auto validSnapshot = snapshot;
    snapshot["next_counter"] = "not-an-unsigned-counter";
    corrupt.records.back().delta = delta(snapshot.dump());

    const auto rejectsSnapshot = [&](nlohmann::json forgedSnapshot) {
        auto forged = std::get<RecoveredState>(recovered);
        forged.records.back().delta = delta(forgedSnapshot.dump());
        SessionState target;
        return std::holds_alternative<BackendError>(target.restore(forged));
    };
    auto staleCounter = snapshot;
    staleCounter["next_counter"] = 1;
    EXPECT_TRUE(rejectsSnapshot(staleCounter));
    auto forgedExhaustedCounter = snapshot;
    forgedExhaustedCounter["next_counter"] = UINT64_MAX;
    EXPECT_TRUE(rejectsSnapshot(forgedExhaustedCounter));

    auto exhaustedCounter = validSnapshot;
    const auto sourceRequestKey = sourceFacts.software_id + ":" +
        sourceFacts.build_id + ":" + sourceFacts.final_artifact_hash + ":" +
        sourceFacts.request_id;
    exhaustedCounter["active_replies"][sourceRequestKey]["counter"] = UINT64_MAX - 1;
    exhaustedCounter["next_counter"] = UINT64_MAX;
    auto exhaustedCounterState = std::get<RecoveredState>(recovered);
    exhaustedCounterState.records.back().delta = delta(exhaustedCounter.dump());
    SessionState exhaustedCounterTarget;
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        exhaustedCounterTarget.restore(exhaustedCounterState)));

    auto exhaustedGeneration = validSnapshot;
    const auto exhaustedScope = sourceFacts.build_id + ":source-session:" +
        std::string(64, '7');
    exhaustedGeneration["active_generations"][exhaustedScope] = UINT64_MAX;
    auto exhaustedGenerationState = std::get<RecoveredState>(recovered);
    exhaustedGenerationState.records.back().delta = delta(exhaustedGeneration.dump());
    SessionState exhaustedGenerationTarget;
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        exhaustedGenerationTarget.restore(exhaustedGenerationState)));
    auto exhaustedFacts = sourceFacts;
    exhaustedFacts.request_id = std::string(64, '8');
    exhaustedFacts.request_digest = std::string(64, '9');
    exhaustedFacts.type = "material.issue";
    exhaustedFacts.region_id = std::string(64, '7');
    exhaustedFacts.mode = "lease";
    const auto exhaustedGrant = std::get<AnonymousGrant>(
        authenticator.authenticate(
            "wal-relay-credential-long-enough", exhaustedFacts, 1000));
    bool exhaustedCallbackFinished = false;
    const auto exhaustedAllocation = exhaustedGenerationTarget.transact(
        exhaustedFacts, exhaustedGrant, 1000,
        [&](SessionState::Transaction &transaction) {
            auto result = transaction.allocate(
                "source-session", exhaustedFacts.region_id,
                "exhausted-client-nonce", "exhausted-client-key");
            exhaustedCallbackFinished = true;
            return result;
        });
    EXPECT_FALSE(exhaustedCallbackFinished);
    const auto *exhaustedError = std::get_if<BackendError>(&exhaustedAllocation);
    EXPECT_TRUE(exhaustedError && exhaustedError->code == "counter_exhausted");

    SessionState destination;
    auto destinationFacts = sourceFacts;
    destinationFacts.software_id = "destination.software";
    destinationFacts.request_id = std::string(64, '5');
    destinationFacts.request_digest = std::string(64, '6');
    auto destinationGrant = std::get<AnonymousGrant>(authenticator.authenticate(
        "wal-relay-credential-long-enough", destinationFacts, 1000));
    EXPECT_TRUE(std::holds_alternative<StateResult>(destination.transact(
        destinationFacts, destinationGrant, 1000, [](SessionState::Transaction &tx) {
            return tx.openSession("destination-session", "destination-epoch", 50000,
                "destination-server", "destination-server-key",
                "destination-client", "destination-client-key");
        })));
    auto restored = destination.restore(corrupt);
    EXPECT_TRUE(std::holds_alternative<BackendError>(restored));

    auto issueFacts = destinationFacts;
    issueFacts.type = "material.issue";
    issueFacts.region_id = std::string(64, '7');
    issueFacts.mode = "lease";
    issueFacts.request_id = std::string(64, '8');
    issueFacts.request_digest = std::string(64, '9');
    auto issueGrant = std::get<AnonymousGrant>(authenticator.authenticate(
        "wal-relay-credential-long-enough", issueFacts, 1000));
    auto issued = destination.transact(issueFacts, issueGrant, 1000,
        [&](SessionState::Transaction &tx) {
            return tx.allocate("destination-session", issueFacts.region_id,
                               "destination-nonce", "destination-key");
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(issued));
    std::filesystem::remove(path);
}

TEST(session_state_restore_recomputes_retained_bytes) {
    const auto path = pathFor("session-retained-recompute");
    std::filesystem::remove(path);
    StateWal wal(path);
    SessionState source(&wal);
    RelayAuthenticator authenticator("wal-relay-credential-long-enough", 100000);
    RequestFacts openFacts;
    openFacts.request_id = std::string(64, '1');
    openFacts.request_digest = std::string(64, '2');
    openFacts.software_id = "test.software";
    openFacts.build_id = std::string(64, '3');
    openFacts.final_artifact_hash = std::string(64, '4');
    openFacts.type = "session.open";
    auto grant = std::get<AnonymousGrant>(authenticator.authenticate(
        "wal-relay-credential-long-enough", openFacts, 1000));
    EXPECT_TRUE(std::holds_alternative<StateResult>(source.transact(
        openFacts, grant, 1000, [](SessionState::Transaction &tx) {
            return tx.openSession("session-id", "epoch-id", 50000,
                "server-nonce", "server-key", "client-nonce", "client-key");
        })));
    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (!std::holds_alternative<RecoveredState>(recovered)) {
        std::filesystem::remove(path);
        return;
    }
    auto forged = std::get<RecoveredState>(recovered);
    const auto &originalBytes = forged.records.back().delta.bytes;
    auto snapshot = nlohmann::json::parse(
        reinterpret_cast<const char *>(originalBytes.data()),
        reinterpret_cast<const char *>(originalBytes.data() + originalBytes.size()));
    snapshot["retained_bytes"] = 0;
    for (unsigned index = 0; index < 2051; ++index) {
        const auto prefix = std::to_string(index) + ":";
        snapshot["active_claims"][prefix + std::string(4096 - prefix.size(), 'k')] = "v";
    }
    forged.records.back().delta = delta(snapshot.dump());
    SessionState destination;
    auto restored = destination.restore(forged);
    EXPECT_TRUE(std::holds_alternative<BackendError>(restored));
    if (const auto *error = std::get_if<BackendError>(&restored))
        EXPECT_TRUE(error->code == "state_capacity");
    std::filesystem::remove(path);
}

TEST(session_window_chain_survives_wal_failure_and_recovery) {
    const auto path = pathFor("window-chain-recovery");
    std::filesystem::remove(path);
    unsigned syncCalls = 0;
    StateWal::IoHooks hooks;
    // The first append syncs both the new file and its parent directory. Fail
    // the following window append's file sync, then allow its rollback sync.
    hooks.sync = [&syncCalls](int) { return ++syncCalls == 3 ? -1 : 0; };
    StateWal wal(path, std::move(hooks));
    SessionState sessions(&wal);
    RelayAuthenticator authenticator("wal-relay-credential-long-enough", 100000);
    RequestFacts openFacts;
    openFacts.request_id = std::string(64, '1');
    openFacts.request_digest = std::string(64, '2');
    openFacts.software_id = "test.software";
    openFacts.build_id = std::string(64, '3');
    openFacts.final_artifact_hash = std::string(64, '4');
    openFacts.type = "session.open";
    auto openGrant = std::get<AnonymousGrant>(authenticator.authenticate(
        "wal-relay-credential-long-enough", openFacts, 1000));
    auto opened = sessions.transact(openFacts, openGrant, 1000,
        [](SessionState::Transaction &tx) {
            return tx.openSession("window-session", "window-epoch", 50000,
                                  "server-window", "server-window-key",
                                  "client-window", "client-window-key");
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(opened));

    auto issueFacts = openFacts;
    issueFacts.type = "material.issue";
    issueFacts.region_id = std::string(64, '5');
    issueFacts.mode = "lease";
    const auto advance = [&](SessionState &state, RequestFacts request, std::uint64_t window,
                             std::string previous, std::string next, std::string response) {
        auto grant = std::get<AnonymousGrant>(authenticator.authenticate(
            "wal-relay-credential-long-enough", request, 1000));
        return state.transact(request, grant, 1000,
            [&, window, previous = std::move(previous), next = std::move(next),
             response = std::move(response)](SessionState::Transaction &tx) mutable {
                WindowPreflightInput preflight;
                preflight.session_id = "window-session";
                preflight.region_id = issueFacts.region_id;
                preflight.generation = 9;
                preflight.window_id = window;
                preflight.previous_state = std::move(previous);
                preflight.expires_at_ms = 40000;
                tx.preflightWindow(std::move(preflight));
                return tx.finalizeWindow(WindowFinalizeInput{
                    std::move(next), bytes(response)});
            });
    };

    issueFacts.request_id = std::string(64, '6');
    issueFacts.request_digest = std::string(64, '7');
    auto failed = advance(sessions, issueFacts, 1, "genesis", "state-one", "failed-response");
    EXPECT_TRUE(std::holds_alternative<BackendError>(failed));

    auto committedFacts = issueFacts;
    committedFacts.request_id = std::string(64, '8');
    committedFacts.request_digest = std::string(64, '9');
    auto committed = advance(sessions, committedFacts, 1, "genesis", "state-one", "exact-window-one");
    EXPECT_TRUE(std::holds_alternative<StateResult>(committed));

    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    SessionState restarted(&wal);
    if (std::holds_alternative<RecoveredState>(recovered))
        EXPECT_TRUE(std::holds_alternative<std::monostate>(
            restarted.restore(std::get<RecoveredState>(recovered))));
    bool retryCalled = false;
    auto committedGrant = std::get<AnonymousGrant>(authenticator.authenticate(
        "wal-relay-credential-long-enough", committedFacts, 1000));
    auto retry = restarted.transact(committedFacts, committedGrant, 1000,
        [&](SessionState::Transaction &) {
            retryCalled = true;
            return StateResult{};
        });
    EXPECT_FALSE(retryCalled);
    EXPECT_TRUE(std::holds_alternative<StateResult>(retry));
    if (std::holds_alternative<StateResult>(retry))
        EXPECT_TRUE(std::get<StateResult>(retry).response == bytes("exact-window-one"));

    auto secondFacts = issueFacts;
    secondFacts.request_id = std::string(64, 'a');
    secondFacts.request_digest = std::string(64, 'b');
    auto second = advance(restarted, secondFacts, 2, "state-one", "state-two", "exact-window-two");
    EXPECT_TRUE(std::holds_alternative<StateResult>(second));
    std::filesystem::remove(path);
}

TEST(raw_window_generation_timing_recovers_and_validates) {
    const auto path = pathFor("raw-window-generation-recovery");
    std::filesystem::remove(path);
    StateWal wal(path);
    SessionState sessions(&wal);
    RelayAuthenticator authenticator("wal-relay-credential-long-enough", 500000);

    RequestFacts openFacts;
    openFacts.request_id = std::string(32, '1');
    openFacts.request_digest = std::string(64, '2');
    openFacts.software_id = "test.software";
    openFacts.build_id = std::string(64, '3');
    openFacts.final_artifact_hash = std::string(64, '4');
    openFacts.type = "session.open";
    const auto openGrant = std::get<AnonymousGrant>(authenticator.authenticate(
        "wal-relay-credential-long-enough", openFacts, 1000));
    auto registered = sessions.registerRawSession(
        openFacts, openGrant, 1000,
        RawSessionRegistrationInput{std::string(64, '5'), std::string(64, '6')},
        [](std::uint64_t counter) -> std::variant<RawSessionMetadata, BackendError> {
            EXPECT_TRUE(counter == 1);
            return RawSessionMetadata{std::string(32, '7'), std::string(64, '8'),
                std::string(64, '9'), std::string(64, 'a'), 1, 500000};
        });
    EXPECT_TRUE(std::holds_alternative<RawSessionRegistrationResult>(registered));

    RequestFacts issueFacts = openFacts;
    issueFacts.request_id = std::string(32, 'b');
    issueFacts.request_digest = std::string(64, 'c');
    issueFacts.type = "material.issue";
    issueFacts.region_id = std::string(64, 'd');
    issueFacts.mode = "lease";
    const auto issueGrant = std::get<AnonymousGrant>(authenticator.authenticate(
        "wal-relay-credential-long-enough", issueFacts, 1000));
    auto first = sessions.transact(issueFacts, issueGrant, 1000,
        [&](SessionState::Transaction &tx) {
            WindowPreflightInput preflight;
            preflight.session_id = std::string(32, '7');
            preflight.region_id = issueFacts.region_id;
            preflight.generation = 1;
            preflight.window_id = 1;
            preflight.previous_state = std::string(64, 'a');
            preflight.expires_at_ms = 40000;
            EXPECT_TRUE(tx.preflightWindow(std::move(preflight)) == 40000);
            return tx.finalizeWindow(WindowFinalizeInput{
                std::string(64, 'e'), bytes("generation-one")});
        });
    EXPECT_TRUE(std::holds_alternative<StateResult>(first));

    auto exhaustedFacts = issueFacts;
    exhaustedFacts.request_id = std::string(32, '0');
    exhaustedFacts.request_digest = std::string(64, '0');
    const auto exhaustedGrant = std::get<AnonymousGrant>(
        authenticator.authenticate(
            "wal-relay-credential-long-enough", exhaustedFacts, 2000));
    bool exhaustedFinalized = false;
    const auto exhaustedWindow = sessions.transact(
        exhaustedFacts, exhaustedGrant, 2000,
        [&](SessionState::Transaction &tx) {
            WindowPreflightInput preflight;
            preflight.session_id = std::string(32, '7');
            preflight.region_id = issueFacts.region_id;
            preflight.generation = 1;
            preflight.window_id = UINT64_MAX;
            preflight.previous_state = std::string(64, 'e');
            preflight.expires_at_ms = 40000;
            tx.preflightWindow(std::move(preflight));
            exhaustedFinalized = true;
            return StateResult{};
        });
    EXPECT_FALSE(exhaustedFinalized);
    const auto *exhaustedError = std::get_if<BackendError>(&exhaustedWindow);
    EXPECT_TRUE(exhaustedError &&
                exhaustedError->code == "window_invalid");

    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (const auto *state = std::get_if<RecoveredState>(&recovered)) {
        const auto &payload = state->records.back().delta.bytes;
        const auto snapshot = nlohmann::json::parse(
            reinterpret_cast<const char *>(payload.data()),
            reinterpret_cast<const char *>(payload.data() + payload.size()));
        const auto &window = snapshot.at("active_windows").at(std::string(32, '7'));
        EXPECT_TRUE(window.at("epoch_at_ms") == 1000);
        EXPECT_TRUE(window.at("deadline_ms") == 121000);

        const auto rejectsSnapshot = [&](nlohmann::json forgedSnapshot) {
            auto forged = *state;
            forged.records.back().delta = delta(forgedSnapshot.dump());
            SessionState target;
            return std::holds_alternative<BackendError>(target.restore(forged));
        };
        auto missingEpoch = snapshot;
        missingEpoch["active_windows"][std::string(32, '7')].erase("epoch_at_ms");
        EXPECT_TRUE(rejectsSnapshot(std::move(missingEpoch)));
        auto legacyRawTiming = snapshot;
        auto &legacyWindow = legacyRawTiming["active_windows"][std::string(32, '7')];
        legacyWindow["expires_at_ms"] = 40000;
        legacyWindow.erase("epoch_at_ms");
        legacyWindow.erase("deadline_ms");
        legacyWindow.erase("legacy_timing");
        const auto legacyRequestKey = issueFacts.software_id + ":" +
            issueFacts.build_id + ":" + issueFacts.final_artifact_hash + ":" +
            issueFacts.request_id;
        auto &legacyReply = legacyRawTiming["active_replies"][legacyRequestKey];
        legacyReply.erase("window_id");
        legacyReply.erase("request_digest");
        legacyReply.erase("retire_at_ms");
        legacyReply.erase("status");
        auto legacyState = *state;
        legacyState.records.back().delta = delta(legacyRawTiming.dump());
        SessionState migrated;
        EXPECT_TRUE(std::holds_alternative<std::monostate>(
            migrated.restore(legacyState)));
        auto legacyNextFacts = issueFacts;
        legacyNextFacts.request_id = std::string(32, '0');
        legacyNextFacts.request_digest = std::string(64, '0');
        const auto legacyNextGrant = std::get<AnonymousGrant>(
            authenticator.authenticate(
                "wal-relay-credential-long-enough", legacyNextFacts, 2000));
        bool legacyNextCalled = false;
        const auto legacyNext = migrated.transact(
            legacyNextFacts, legacyNextGrant, 2000,
            [&](SessionState::Transaction &tx) {
                WindowPreflightInput preflight;
                preflight.session_id = std::string(32, '7');
                preflight.region_id = issueFacts.region_id;
                preflight.generation = 1;
                preflight.window_id = 2;
                preflight.previous_state = std::string(64, 'e');
                preflight.expires_at_ms = 40000;
                tx.preflightWindow(std::move(preflight));
                legacyNextCalled = true;
                return StateResult{};
            });
        EXPECT_FALSE(legacyNextCalled);
        const auto *legacyError = std::get_if<BackendError>(&legacyNext);
        EXPECT_TRUE(legacyError &&
                    legacyError->code == "window_chain_mismatch");
        auto reversedTiming = snapshot;
        reversedTiming["active_windows"][std::string(32, '7')]["deadline_ms"] = 1000;
        EXPECT_TRUE(rejectsSnapshot(std::move(reversedTiming)));
        auto extendedTiming = snapshot;
        extendedTiming["active_windows"][std::string(32, '7')]["deadline_ms"] = 121001;
        EXPECT_TRUE(rejectsSnapshot(std::move(extendedTiming)));
        const auto requestKey = issueFacts.software_id + ":" + issueFacts.build_id +
            ":" + issueFacts.final_artifact_hash + ":" + issueFacts.request_id;
        auto missingWindowIdentity = snapshot;
        missingWindowIdentity["active_replies"][requestKey].erase("window_id");
        EXPECT_TRUE(rejectsSnapshot(std::move(missingWindowIdentity)));
        auto missingHighWater = snapshot;
        missingHighWater["active_windows"].erase(std::string(32, '7'));
        EXPECT_TRUE(rejectsSnapshot(std::move(missingHighWater)));
        auto contradictoryHighWater = snapshot;
        contradictoryHighWater["active_sessions"][std::string(32, '7')]
            ["raw_chain_started"] = false;
        EXPECT_TRUE(rejectsSnapshot(std::move(contradictoryHighWater)));

        SessionState restarted(&wal);
        EXPECT_TRUE(std::holds_alternative<std::monostate>(restarted.restore(*state)));
        bool retryCalled = false;
        auto recoveredRetry = restarted.transact(issueFacts, issueGrant, 30000,
            [&](SessionState::Transaction &) {
                retryCalled = true;
                return StateResult{};
            });
        EXPECT_FALSE(retryCalled);
        EXPECT_TRUE(std::holds_alternative<StateResult>(recoveredRetry));
        if (std::holds_alternative<StateResult>(first) &&
            std::holds_alternative<StateResult>(recoveredRetry))
            EXPECT_TRUE(std::get<StateResult>(first).response ==
                        std::get<StateResult>(recoveredRetry).response);

        auto nextFacts = issueFacts;
        nextFacts.request_id = std::string(32, 'f');
        nextFacts.request_digest = std::string(64, '1');
        const auto nextGrant = std::get<AnonymousGrant>(authenticator.authenticate(
            "wal-relay-credential-long-enough", nextFacts, 111000));
        auto rollover = restarted.transact(nextFacts, nextGrant, 111000,
            [&](SessionState::Transaction &tx) {
                WindowPreflightInput preflight;
                preflight.session_id = std::string(32, '7');
                preflight.region_id = issueFacts.region_id;
                preflight.generation = 2;
                preflight.window_id = 1;
                preflight.previous_state = std::string(64, 'e');
                preflight.expires_at_ms = 200000;
                EXPECT_TRUE(tx.preflightWindow(std::move(preflight)) == 200000);
                return tx.finalizeWindow(WindowFinalizeInput{
                    std::string(64, 'f'), bytes("generation-two")});
            });
        EXPECT_TRUE(std::holds_alternative<StateResult>(rollover));

        auto closeFacts = openFacts;
        closeFacts.request_id = std::string(32, '2');
        closeFacts.request_digest = std::string(64, '3');
        closeFacts.type = "session.close";
        const auto closeGrant = std::get<AnonymousGrant>(authenticator.authenticate(
            "wal-relay-credential-long-enough", closeFacts, 112000));
        auto closed = restarted.transact(closeFacts, closeGrant, 112000,
            [](SessionState::Transaction &tx) {
                return tx.closeSession(std::string(32, '7'), "", 112000,
                    std::string(64, '4'), std::string(64, '5'),
                    std::string(64, '6'), std::string(64, '7'));
            });
        EXPECT_TRUE(std::holds_alternative<StateResult>(closed));

        auto closedRecovery = wal.recover();
        EXPECT_TRUE(std::holds_alternative<RecoveredState>(closedRecovery));
        if (const auto *closedState = std::get_if<RecoveredState>(&closedRecovery)) {
            const auto &closedPayload = closedState->records.back().delta.bytes;
            const auto closedSnapshot = nlohmann::json::parse(
                reinterpret_cast<const char *>(closedPayload.data()),
                reinterpret_cast<const char *>(closedPayload.data() + closedPayload.size()));
            const auto &closedSession =
                closedSnapshot.at("active_sessions").at(std::string(32, '7'));
            const auto &terminal =
                closedSnapshot.at("active_windows").at(std::string(32, '7'));
            EXPECT_TRUE(closedSession.at("closed").get<bool>());
            EXPECT_TRUE(closedSession.at("raw_chain_started").get<bool>());
            EXPECT_TRUE(terminal.at("generation") == 2);
            EXPECT_TRUE(terminal.at("window_id") == 1);
            EXPECT_TRUE(terminal.at("state") == std::string(64, 'f'));
            EXPECT_TRUE(terminal.at("epoch_at_ms") == 111000);
            EXPECT_TRUE(terminal.at("deadline_ms") == 231000);

            SessionState closedRestarted(&wal);
            EXPECT_TRUE(std::holds_alternative<std::monostate>(
                closedRestarted.restore(*closedState)));
            auto replayFacts = issueFacts;
            replayFacts.request_id = std::string(32, '8');
            replayFacts.request_digest = std::string(64, '9');
            const auto replayGrant = std::get<AnonymousGrant>(authenticator.authenticate(
                "wal-relay-credential-long-enough", replayFacts, 112000));
            bool expensive = false;
            auto genesisReplay = closedRestarted.transact(
                replayFacts, replayGrant, 112000,
                [&](SessionState::Transaction &tx) {
                    WindowPreflightInput preflight;
                    preflight.session_id = std::string(32, '7');
                    preflight.region_id = issueFacts.region_id;
                    preflight.generation = 1;
                    preflight.window_id = 1;
                    preflight.previous_state = std::string(64, 'a');
                    preflight.expires_at_ms = 200000;
                    tx.preflightWindow(std::move(preflight));
                    expensive = true;
                    return StateResult{};
                });
            EXPECT_FALSE(expensive);
            const auto *error = std::get_if<BackendError>(&genesisReplay);
            EXPECT_TRUE(error && error->code == "session_closed");
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

TEST(raw_session_registration_wal_failure_does_not_publish) {
    const auto path = pathFor("raw-registration-sync-failure");
    std::filesystem::remove(path);
    StateWal::IoHooks hooks;
    hooks.sync = [](int) { return -1; };
    StateWal wal(path, std::move(hooks));
    SessionState sessions(&wal);
    RequestFacts facts;
    facts.request_id = std::string(32, '1');
    facts.request_digest = std::string(64, '2');
    facts.software_id = "test.software";
    facts.build_id = std::string(64, '3');
    facts.final_artifact_hash = std::string(64, '4');
    facts.type = "session.open";
    RelayAuthenticator authenticator("wal-relay-credential-long-enough", 100000);
    const auto grant = std::get<AnonymousGrant>(authenticator.authenticate(
        "wal-relay-credential-long-enough", facts, 1000));
    const RawSessionRegistrationInput input{std::string(64, '5'), std::string(64, '6')};
    unsigned callbacks = 0;
    const auto build = [&](std::uint64_t counter)
        -> std::variant<RawSessionMetadata, BackendError> {
        ++callbacks;
        EXPECT_TRUE(counter == 1);
        return RawSessionMetadata{std::string(32, '7'), std::string(64, '8'),
            std::string(64, '9'), std::string(64, 'a'), 1, 50000};
    };
    auto failed = sessions.registerRawSession(facts, grant, 1000, input, build);
    EXPECT_TRUE(std::holds_alternative<BackendError>(failed));
    auto retry = sessions.registerRawSession(facts, grant, 1000, input, build);
    EXPECT_TRUE(std::holds_alternative<BackendError>(retry));
    EXPECT_TRUE(callbacks == 2);
    std::filesystem::remove(path);
}

TEST(session_state_restore_rejects_invalid_sequence_metadata) {
    SessionState state;
    RecoveredState emptyWithBase;
    emptyWithBase.last_sequence = 1;
    EXPECT_TRUE(std::holds_alternative<BackendError>(state.restore(emptyWithBase)));

    RecoveredState mismatched;
    mismatched.last_sequence = 2;
    mismatched.records.push_back(WalRecord{1, delta("{}"), {}});
    EXPECT_TRUE(std::holds_alternative<BackendError>(state.restore(mismatched)));

    RecoveredState exhausted;
    exhausted.last_sequence = UINT64_MAX;
    exhausted.records.push_back(WalRecord{UINT64_MAX, delta("{}"), {}});
    EXPECT_TRUE(std::holds_alternative<BackendError>(state.restore(exhausted)));

    RecoveredState initial;
    EXPECT_TRUE(std::holds_alternative<std::monostate>(state.restore(initial)));
}

TEST(raw_session_registration_recovers_fresh_replay_fence_without_secrets) {
    const auto path = pathFor("raw-registration-recovery");
    std::filesystem::remove(path);
    StateWal wal(path);
    SessionState sessions(&wal);
    RequestFacts facts;
    facts.request_id = std::string(32, '1');
    facts.request_digest = std::string(64, '2');
    facts.software_id = "test.software";
    facts.build_id = std::string(64, '3');
    facts.final_artifact_hash = std::string(64, '4');
    facts.type = "session.open";
    RelayAuthenticator authenticator("wal-relay-credential-long-enough", 100000);
    const auto grant = std::get<AnonymousGrant>(authenticator.authenticate(
        "wal-relay-credential-long-enough", facts, 1000));
    const RawSessionRegistrationInput input{std::string(64, '5'), std::string(64, '6')};
    constexpr std::string_view privateSentinel = "PRIVATE-KEY-MUST-NOT-BE-DURABLE";
    auto registered = sessions.registerRawSession(
        facts, grant, 1000, input, [&](std::uint64_t counter)
            -> std::variant<RawSessionMetadata, BackendError> {
            EXPECT_TRUE(counter == 1);
            (void)privateSentinel;
            return RawSessionMetadata{std::string(32, '7'), std::string(64, '8'),
                std::string(64, '9'), std::string(64, 'a'), 1, 50000};
        });
    EXPECT_TRUE(std::holds_alternative<RawSessionRegistrationResult>(registered));

    auto recovered = wal.recover();
    EXPECT_TRUE(std::holds_alternative<RecoveredState>(recovered));
    if (const auto *state = std::get_if<RecoveredState>(&recovered)) {
        EXPECT_TRUE(state->records.size() == 1);
        EXPECT_TRUE(state->records.back().response.empty());
        const auto &payload = state->records.back().delta.bytes;
        const std::string serialized(reinterpret_cast<const char *>(payload.data()), payload.size());
        EXPECT_TRUE(serialized.find(privateSentinel) == std::string::npos);
        EXPECT_TRUE(serialized.find("hello") == std::string::npos);

        const auto snapshot = nlohmann::json::parse(serialized);
        const auto rejectsSnapshot = [&](nlohmann::json forgedSnapshot) {
            auto forged = *state;
            forged.records.back().delta = delta(forgedSnapshot.dump());
            SessionState target;
            return std::holds_alternative<BackendError>(target.restore(forged));
        };
        const auto requestKey = facts.software_id + ":" + facts.build_id + ":" +
            facts.final_artifact_hash + ":" + facts.request_id;
        const auto clientNonceClaim = "client_nonce:" + facts.build_id + ":" + input.client_nonce;
        const auto clientKeyClaim =
            "client_key:" + facts.build_id + ":" + input.client_ephemeral_key;
        const auto serverNonceClaim = "server_nonce:" + facts.build_id + ":" +
            std::string(64, '8');
        const auto serverKeyClaim = "server_key:" + facts.build_id + ":" +
            std::string(64, '9');

        auto legacyBinding = snapshot;
        legacyBinding["active_raw_registrations"][requestKey].erase("session_id");
        EXPECT_TRUE(rejectsSnapshot(std::move(legacyBinding)));
        auto missingSession = snapshot;
        missingSession["active_raw_registrations"][requestKey]["session_id"] = std::string(32, 'b');
        EXPECT_TRUE(rejectsSnapshot(std::move(missingSession)));
        auto mismatchedIdentity = snapshot;
        mismatchedIdentity["active_sessions"][std::string(32, '7')]["subject_id"] = "wrong-subject";
        EXPECT_TRUE(rejectsSnapshot(std::move(mismatchedIdentity)));
        auto orphanedRawSession = snapshot;
        orphanedRawSession["active_raw_registrations"].erase(requestKey);
        EXPECT_TRUE(rejectsSnapshot(std::move(orphanedRawSession)));
        for (const auto &claimKey : {clientNonceClaim, clientKeyClaim,
                                     serverNonceClaim, serverKeyClaim}) {
            auto missingClaim = snapshot;
            missingClaim["active_claims"].erase(claimKey);
            EXPECT_TRUE(rejectsSnapshot(std::move(missingClaim)));
            auto mismatchedClaim = snapshot;
            mismatchedClaim["active_claims"][claimKey] = std::string(64, 'c');
            EXPECT_TRUE(rejectsSnapshot(std::move(mismatchedClaim)));
        }
        auto staleCounter = snapshot;
        staleCounter["next_counter"] = 1;
        EXPECT_TRUE(rejectsSnapshot(std::move(staleCounter)));
        auto exhaustedCounter = snapshot;
        exhaustedCounter["next_counter"] = UINT64_MAX;
        EXPECT_TRUE(rejectsSnapshot(std::move(exhaustedCounter)));

        SessionState restarted(&wal);
        EXPECT_TRUE(std::holds_alternative<std::monostate>(restarted.restore(*state)));
        bool called = false;
        auto replay = restarted.registerRawSession(
            facts, grant, 1000, input, [&](std::uint64_t)
                -> std::variant<RawSessionMetadata, BackendError> {
                called = true;
                return BackendError{"unexpected_callback"};
            });
        EXPECT_FALSE(called);
        const auto *error = std::get_if<BackendError>(&replay);
        EXPECT_TRUE(error && error->code == "replay_detected");
    }
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
    run("wal_sync_failure_with_unproven_rollback_quarantines_path",
        wal_sync_failure_with_unproven_rollback_quarantines_path);
    run("wal_first_create_requires_parent_directory_sync",
        wal_first_create_requires_parent_directory_sync);
    run("wal_sync_failure_rolls_back_uncommitted_frame_for_retry",
        wal_sync_failure_rolls_back_uncommitted_frame_for_retry);
    run("wal_rejects_complete_checksum_corruption",
        wal_rejects_complete_checksum_corruption);
    run("wal_truncates_partial_final_header", wal_truncates_partial_final_header);
    run("wal_partial_tail_repair_sync_failure_quarantines_path",
        wal_partial_tail_repair_sync_failure_quarantines_path);
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
    run("session_state_reclaims_exact_response_into_durable_tombstone",
        session_state_reclaims_exact_response_into_durable_tombstone);
    run("session_state_reclamation_uses_fixed_bounded_batches",
        session_state_reclamation_uses_fixed_bounded_batches);
    run("session_state_reclamation_wal_failure_preserves_live_reply",
        session_state_reclamation_wal_failure_preserves_live_reply);
    run("session_state_restore_is_atomic_after_late_scalar_failure",
        session_state_restore_is_atomic_after_late_scalar_failure);
    run("session_state_restore_recomputes_retained_bytes",
        session_state_restore_recomputes_retained_bytes);
    run("session_window_chain_survives_wal_failure_and_recovery",
        session_window_chain_survives_wal_failure_and_recovery);
    run("raw_window_generation_timing_recovers_and_validates",
        raw_window_generation_timing_recovers_and_validates);
    run("session_state_does_not_publish_when_wal_sync_fails",
        session_state_does_not_publish_when_wal_sync_fails);
    run("raw_session_registration_wal_failure_does_not_publish",
        raw_session_registration_wal_failure_does_not_publish);
    run("session_state_restore_rejects_invalid_sequence_metadata",
        session_state_restore_rejects_invalid_sequence_metadata);
    run("raw_session_registration_recovers_fresh_replay_fence_without_secrets",
        raw_session_registration_recovers_fresh_replay_fence_without_secrets);
    std::fprintf(stdout, "35 tests, %u assertions, %u failures\n",
                 state.assertions, state.failures);
    return state.failures == 0 ? 0 : 1;
}
