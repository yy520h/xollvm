#ifndef XOVM_CLOUD_MATERIAL_BACKEND_CHECKPOINT_H
#define XOVM_CLOUD_MATERIAL_BACKEND_CHECKPOINT_H

#include "state_wal.h"

#include <filesystem>
#include <functional>

namespace xovm::cloud_material {

using CheckpointResult = std::variant<std::uint64_t, BackendError>;

class Checkpoint {
public:
    struct IoHooks {
        std::function<ssize_t(int, std::span<const std::byte>)> write;
        std::function<int(int)> sync;
        std::function<int(const char *, const char *)> rename;
        std::function<int(const char *)> unlink;
        std::function<int(const char *)> syncDirectory;
    };

    Checkpoint(std::filesystem::path path, std::filesystem::path walPath,
               IoHooks hooks = {});
    CheckpointResult writeAtomic(const RecoveredState &state, std::uint64_t sequence);
    WalRecoveryResult recover() const;

private:
    std::filesystem::path path_;
    std::filesystem::path wal_path_;
    IoHooks hooks_;
};

} // namespace xovm::cloud_material

#endif
