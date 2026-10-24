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

using WalCommitResult = std::variant<std::uint64_t, BackendError>;
using WalRecoveryResult = std::variant<RecoveredState, BackendError>;

class StateWal {
public:
    struct IoHooks {
        std::function<ssize_t(int, std::span<const std::byte>)> write;
        std::function<int(int)> sync;
    };

    explicit StateWal(std::filesystem::path path, IoHooks hooks = {},
                      std::uint64_t baseSequence = 0);
    WalCommitResult appendAndSync(std::uint64_t sequence, const StateDelta &delta,
                                  std::span<const std::byte> exactResponse);
    WalRecoveryResult recover();

private:
    std::filesystem::path path_;
    IoHooks hooks_;
    std::uint64_t base_sequence_ = 0;
};

} // namespace xovm::cloud_material

#endif
