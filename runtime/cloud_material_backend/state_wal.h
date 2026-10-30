#ifndef XOVM_CLOUD_MATERIAL_BACKEND_STATE_WAL_H
#define XOVM_CLOUD_MATERIAL_BACKEND_STATE_WAL_H

#include "canonical_json.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <span>
#include <sys/types.h>
#include <variant>
#include <vector>

namespace xovm::cloud_material {

inline constexpr std::size_t kMaxWalPayload = 8 * 1024 * 1024;
inline constexpr std::size_t kMaxWalFrame = kMaxWalPayload + 40 + 32;
inline constexpr std::uint64_t kMaxWalSize = 128ULL * 1024 * 1024;

enum class WalAppendMode {
    runtime,
    maintenance,
};

struct StateDelta {
    std::vector<std::byte> bytes;
};

struct WalRecord {
    std::uint64_t sequence = 0;
    StateDelta delta;
    std::vector<std::byte> response;
};

struct RecoveredState {
    std::vector<WalRecord> records;
    std::uint64_t last_sequence = 0;
};

struct QuarantineInfo {
    std::uint64_t sequence = 0;
    off_t offset = 0;
    dev_t device = 0;
    ino_t inode = 0;
    bool valid = false;
};

struct QuarantineReconciliationResult {
    std::uint64_t abandoned_sequence = 0;
    bool truncation_performed = false;
    bool quarantine_cleared = false;
};

using WalCommitResult = std::variant<std::uint64_t, BackendError>;
using WalRecoveryResult = std::variant<RecoveredState, BackendError>;
using QuarantineReconciliationOutcome =
    std::variant<QuarantineReconciliationResult, BackendError>;

class StateWal {
public:
    struct IoHooks {
        std::function<ssize_t(int, std::span<const std::byte>)> write;
        std::function<int(int)> sync;
    };

    explicit StateWal(std::filesystem::path path, IoHooks hooks = {},
                      std::uint64_t baseSequence = 0,
                      WalAppendMode appendMode = WalAppendMode::runtime);
    WalCommitResult appendAndSync(std::uint64_t sequence, const StateDelta &delta,
                                  std::span<const std::byte> exactResponse);
    WalRecoveryResult recover();
    QuarantineReconciliationOutcome reconcileQuarantine();

private:
    std::filesystem::path path_;
    IoHooks hooks_;
    std::uint64_t base_sequence_ = 0;
    WalAppendMode append_mode_ = WalAppendMode::runtime;
};

} // namespace xovm::cloud_material

#endif
