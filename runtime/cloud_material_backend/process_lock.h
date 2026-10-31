#ifndef XOVM_CLOUD_MATERIAL_BACKEND_PROCESS_LOCK_H
#define XOVM_CLOUD_MATERIAL_BACKEND_PROCESS_LOCK_H

#include "canonical_json.h"

#include <filesystem>
#include <variant>

namespace xovm::cloud_material {

class ProcessLock {
public:
    ProcessLock() = delete;
    ProcessLock(const ProcessLock &) = delete;
    ProcessLock &operator=(const ProcessLock &) = delete;
    ProcessLock(ProcessLock &&other) noexcept;
    ProcessLock &operator=(ProcessLock &&other) noexcept;
    ~ProcessLock();

    static std::variant<ProcessLock, BackendError> acquire(
        const std::filesystem::path &stateDir);
    const std::filesystem::path &path() const { return path_; }

private:
    ProcessLock(std::filesystem::path path, int fd);
    std::filesystem::path path_;
    int fd_ = -1;
};

} // namespace xovm::cloud_material

#endif
