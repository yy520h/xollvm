#include "process_lock.h"

#include <cerrno>
#include <fcntl.h>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace xovm::cloud_material {
namespace {

void closeFd(int &fd) {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

} // namespace

ProcessLock::ProcessLock(std::filesystem::path path, int fd)
    : path_(std::move(path)), fd_(fd) {}

ProcessLock::ProcessLock(ProcessLock &&other) noexcept
    : path_(std::move(other.path_)), fd_(other.fd_) {
    other.fd_ = -1;
}

ProcessLock &ProcessLock::operator=(ProcessLock &&other) noexcept {
    if (this == &other) return *this;
    closeFd(fd_);
    path_ = std::move(other.path_);
    fd_ = other.fd_;
    other.fd_ = -1;
    return *this;
}

ProcessLock::~ProcessLock() {
    closeFd(fd_);
}

std::variant<ProcessLock, BackendError> ProcessLock::acquire(
    const std::filesystem::path &stateDir) {
    try {
        if (stateDir.empty()) return BackendError{"lock_invalid_state_dir"};
        const bool existed = std::filesystem::exists(stateDir);
        std::filesystem::create_directories(stateDir);
        if (!existed)
            std::filesystem::permissions(
                stateDir, std::filesystem::perms::owner_all,
                std::filesystem::perm_options::replace);
        const auto path = stateDir / ".xovm.lock";
        const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0) return BackendError{"lock_open_failed"};
        if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
            const auto code = errno == EWOULDBLOCK || errno == EAGAIN
                ? "lock_busy" : "lock_acquire_failed";
            ::close(fd);
            return BackendError{code};
        }
        const std::string diagnostic = std::to_string(::getpid()) + "\n";
        if (::ftruncate(fd, 0) != 0 ||
            ::write(fd, diagnostic.data(), diagnostic.size()) !=
                static_cast<ssize_t>(diagnostic.size())) {
            ::flock(fd, LOCK_UN);
            ::close(fd);
            return BackendError{"lock_metadata_failed"};
        }
        return ProcessLock(path, fd);
    } catch (...) {
        return BackendError{"lock_acquire_failed"};
    }
}

std::variant<ProcessLock, BackendError> ProcessLock::acquireExistingPrivate(
    const std::filesystem::path &stateDir) {
    try {
        if (stateDir.empty()) return BackendError{"lock_invalid_state_dir"};
        struct stat directory{};
        if (::lstat(stateDir.c_str(), &directory) != 0)
            return BackendError{"lock_state_dir_missing"};
        if (!S_ISDIR(directory.st_mode) || S_ISLNK(directory.st_mode))
            return BackendError{"lock_state_dir_invalid"};
        if (directory.st_uid != ::geteuid() ||
            (directory.st_mode & (S_IRWXG | S_IRWXO)) != 0 ||
            (directory.st_mode & (S_IRUSR | S_IWUSR | S_IXUSR)) !=
                (S_IRUSR | S_IWUSR | S_IXUSR))
            return BackendError{"lock_state_dir_not_private"};

        const auto path = stateDir / ".xovm.lock";
        const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC |
                              O_NOFOLLOW, 0600);
        if (fd < 0) return BackendError{"lock_open_failed"};
        struct stat lockStatus{};
        if (::fstat(fd, &lockStatus) != 0 || !S_ISREG(lockStatus.st_mode) ||
            lockStatus.st_uid != ::geteuid() ||
            (lockStatus.st_mode & 0777) != 0600) {
            ::close(fd);
            return BackendError{"lock_file_invalid"};
        }
        if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
            const auto code = errno == EWOULDBLOCK || errno == EAGAIN
                ? "lock_busy" : "lock_acquire_failed";
            ::close(fd);
            return BackendError{code};
        }
        const std::string diagnostic = std::to_string(::getpid()) + "\n";
        if (::ftruncate(fd, 0) != 0 ||
            ::write(fd, diagnostic.data(), diagnostic.size()) !=
                static_cast<ssize_t>(diagnostic.size())) {
            ::flock(fd, LOCK_UN);
            ::close(fd);
            return BackendError{"lock_metadata_failed"};
        }
        return ProcessLock(path, fd);
    } catch (...) {
        return BackendError{"lock_acquire_failed"};
    }
}

} // namespace xovm::cloud_material
