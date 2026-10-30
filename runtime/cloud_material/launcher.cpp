#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "launcher.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <array>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <utility>

#include <dirent.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace xovm::material {
namespace {

bool setCloseOnExec(int fd) {
    const int flags = ::fcntl(fd, F_GETFD);
    return flags >= 0 && ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

void reap(pid_t pid) {
    if (pid <= 0) return;
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
}

int openPidfd(pid_t pid) {
#if defined(SYS_pidfd_open)
    const int fd = static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
    if (fd >= 0 && !setCloseOnExec(fd)) {
        ::close(fd);
        return -1;
    }
    return fd;
#else
    (void)pid;
    return -1;
#endif
}

bool signalChild(int pidfd, pid_t pid, int signal) {
#if defined(SYS_pidfd_send_signal)
    if (pidfd >= 0)
        return ::syscall(SYS_pidfd_send_signal, pidfd, signal, nullptr, 0) == 0 ||
               errno == ESRCH;
#else
    (void)pidfd;
#endif
    return pid <= 0 || ::kill(pid, signal) == 0 || errno == ESRCH;
}

bool singleThreadedProcess() {
    DIR *directory = ::opendir("/proc/self/task");
    if (!directory) return false;
    size_t tasks = 0;
    while (dirent *entry = ::readdir(directory)) {
        char *end = nullptr;
        errno = 0;
        const long value = std::strtol(entry->d_name, &end, 10);
        if (errno == 0 && end != entry->d_name && *end == '\0' && value > 0)
            ++tasks;
    }
    const bool closed = ::closedir(directory) == 0;
    return closed && tasks == 1;
}

bool closeInheritedDescriptors(int keep_fd) {
    DIR *directory = ::opendir("/proc/self/fd");
    if (!directory) return false;
    const int directory_fd = ::dirfd(directory);
    bool ok = true;
    while (dirent *entry = ::readdir(directory)) {
        char *end = nullptr;
        errno = 0;
        const long value = std::strtol(entry->d_name, &end, 10);
        if (errno != 0 || end == entry->d_name || *end != '\0' ||
            value < 0 || value > INT_MAX)
            continue;
        const int fd = static_cast<int>(value);
        if (fd <= STDERR_FILENO || fd == keep_fd || fd == directory_fd) continue;
        if (::close(fd) != 0 && errno != EBADF) ok = false;
    }
    if (::closedir(directory) != 0) ok = false;
    return ok;
}

class NonceGuard {
public:
    explicit NonceGuard(std::array<uint8_t, 32> &nonce) : nonce_(nonce) {}
    ~NonceGuard() { OPENSSL_cleanse(nonce_.data(), nonce_.size()); }

private:
    std::array<uint8_t, 32> &nonce_;
};

} // namespace

Launcher::Child::~Child() {
    if (pid_ > 0 && !waited_) {
        terminate();
        reap(pid_);
    }
    if (pidfd_ >= 0) ::close(pidfd_);
}

Launcher::Child::Child(Child &&other) noexcept
    : pid_(std::exchange(other.pid_, -1)),
      pidfd_(std::exchange(other.pidfd_, -1)),
      channel_(std::move(other.channel_)),
      waited_(std::exchange(other.waited_, true)) {}

Launcher::Child &Launcher::Child::operator=(Child &&other) noexcept {
    if (this != &other) {
        if (pid_ > 0 && !waited_) {
            terminate();
            reap(pid_);
        }
        if (pidfd_ >= 0) ::close(pidfd_);
        pid_ = std::exchange(other.pid_, -1);
        pidfd_ = std::exchange(other.pidfd_, -1);
        channel_ = std::move(other.channel_);
        waited_ = std::exchange(other.waited_, true);
    }
    return *this;
}

bool Launcher::Child::challenge(uint64_t challenge_counter,
                                uint64_t generation) {
    if (pid_ <= 0 || waited_) return false;
    return channel_.challenge(challenge_counter, generation);
}

int Launcher::Child::wait() {
    if (pid_ <= 0 || waited_) return -1;
    int status = 0;
    pid_t result;
    do {
        result = ::waitpid(pid_, &status, 0);
    } while (result < 0 && errno == EINTR);
    waited_ = true;
    channel_.close();
    pid_ = -1;
    if (pidfd_ >= 0) {
        ::close(pidfd_);
        pidfd_ = -1;
    }
    if (result <= 0 || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

void Launcher::Child::terminate() {
    channel_.close();
    if (pid_ > 0 && !waited_) (void)signalChild(pidfd_, pid_, SIGKILL);
}

std::optional<Launcher::Child> Launcher::start(const StartOptions &options) {
    if (!singleThreadedProcess()) return std::nullopt;
    GuardianChannelHello hello = options.hello;
    NonceGuard nonce_guard(hello.boot_nonce);
    if (hello.format_version != kDynamicVmFormatVersion ||
        hello.session_id == std::array<uint8_t, 16>{} ||
        hello.generation == 0 || hello.challenge_counter == 0 ||
        hello.previous_state_digest == DynamicHash{} ||
        options.current_window_id == 0 ||
        RAND_bytes(hello.boot_nonce.data(), hello.boot_nonce.size()) != 1)
        return std::nullopt;
#ifdef XOVM_GUARDIAN_TESTING
    if (!options.worker) return std::nullopt;
#endif

    int sockets[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0)
        return std::nullopt;
    if (!setCloseOnExec(sockets[0]) || !setCloseOnExec(sockets[1])) {
        ::close(sockets[0]);
        ::close(sockets[1]);
        return std::nullopt;
    }
    const pid_t parent_pid = ::getpid();
    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(sockets[0]);
        ::close(sockets[1]);
        return std::nullopt;
    }
    if (pid == 0) {
        ::close(sockets[0]);
        if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
            ::getppid() != parent_pid ||
            !closeInheritedDescriptors(sockets[1])) {
            OPENSSL_cleanse(hello.boot_nonce.data(), hello.boot_nonce.size());
            _exit(125);
        }
        auto worker = GuardianChannel::adopt(
            sockets[1], GuardianChannel::Role::Worker, hello.boot_nonce,
            hello.session_id, parent_pid);
        OPENSSL_cleanse(hello.boot_nonce.data(), hello.boot_nonce.size());
        if (!worker) {
            ::close(sockets[1]);
            _exit(126);
        }
        if (!worker->workerHandshake(hello, options.current_window_id))
            _exit(126);
#ifdef XOVM_GUARDIAN_TESTING
        const int status = runTestWorker(options, *worker);
#else
        const int status = runWorker(*worker);
#endif
        worker->close();
        _exit(status >= 0 && status <= 255 ? status : 127);
    }

    ::close(sockets[1]);
    const int pidfd = openPidfd(pid);
    auto guardian = GuardianChannel::adopt(
        sockets[0], GuardianChannel::Role::Guardian, hello.boot_nonce,
        hello.session_id, pid);
    if (!guardian ||
        !guardian->guardianHandshake(hello, options.current_window_id)) {
        if (!guardian) ::close(sockets[0]);
        (void)signalChild(pidfd, pid, SIGKILL);
        reap(pid);
        if (pidfd >= 0) ::close(pidfd);
        return std::nullopt;
    }
    return Child(pid, pidfd, std::move(*guardian));
}

int Launcher::runWorker(GuardianChannel &channel) {
    return channel.receiveShutdown() ? 0 : 126;
}

#ifdef XOVM_GUARDIAN_TESTING
int Launcher::runTestWorker(const StartOptions &options,
                            GuardianChannel &channel) {
    return options.worker(channel);
}
#endif

std::optional<ProcessIdentityProof> Launcher::Child::captureProcessIdentity() const {
    if (pid_ <= 0) return std::nullopt;

    ProcessIdentityProof proof;
    proof.pid = pid_;

    // Get process credentials using /proc/[pid]/status
    const auto status_path = "/proc/" + std::to_string(pid_) + "/status";
    std::ifstream status_file(status_path);
    if (!status_file.is_open()) return std::nullopt;

    std::string line;
    bool uid_found = false, gid_found = false;

    while (std::getline(status_file, line)) {
        if (line.find("Uid:") == 0) {
            std::istringstream iss(line);
            std::string key;
            iss >> key;  // "Uid:"
            iss >> proof.uid;
            uid_found = true;
        } else if (line.find("Gid:") == 0) {
            std::istringstream iss(line);
            std::string key;
            iss >> key;  // "Gid:"
            iss >> proof.gid;
            gid_found = true;
        }
    }

    if (!uid_found || !gid_found) return std::nullopt;

    // Get process start ticks from /proc/[pid]/stat
    const auto stat_path = "/proc/" + std::to_string(pid_) + "/stat";
    std::ifstream stat_file(stat_path);
    if (!stat_file.is_open()) return std::nullopt;

    std::string stat_line;
    if (!std::getline(stat_file, stat_line)) return std::nullopt;

    // Parse stat file - find the closing ) of the command name
    const size_t end_name = stat_line.rfind(')');
    if (end_name == std::string::npos || end_name + 2 >= stat_line.size())
        return std::nullopt;

    // Extract fields after command name
    std::istringstream fields(stat_line.substr(end_name + 2));
    std::string field;

    // Skip to field 20 (starttime) - that's 19 fields after the closing )
    for (size_t index = 0; index < 19; ++index) {
        if (!(fields >> field)) return std::nullopt;
    }

    // Now read starttime
    if (!(fields >> field)) return std::nullopt;

    try {
        size_t used = 0;
        proof.start_ticks = std::stoull(field, &used);
        if (used != field.size() || proof.start_ticks == 0)
            return std::nullopt;
    } catch (...) {
        return std::nullopt;
    }

    return proof;
}

bool Launcher::Child::verifyProcessIdentity(const ProcessIdentityProof &proof) const {
    if (proof.pid != pid_) return false;
    if (pid_ <= 0) return false;

    // Verify UID/GID haven't changed
    uid_t current_uid = 0;
    gid_t current_gid = 0;

    const auto status_path = "/proc/" + std::to_string(pid_) + "/status";
    std::ifstream status_file(status_path);
    if (!status_file.is_open()) return false;

    std::string line;
    bool uid_matched = false, gid_matched = false;

    while (std::getline(status_file, line)) {
        if (line.find("Uid:") == 0) {
            std::istringstream iss(line);
            std::string key;
            iss >> key;  // "Uid:"
            iss >> current_uid;
            uid_matched = (current_uid == proof.uid);
        } else if (line.find("Gid:") == 0) {
            std::istringstream iss(line);
            std::string key;
            iss >> key;  // "Gid:"
            iss >> current_gid;
            gid_matched = (current_gid == proof.gid);
        }
    }

    if (!uid_matched || !gid_matched) return false;

    // Verify start ticks (process hasn't been replaced)
    const auto stat_path = "/proc/" + std::to_string(pid_) + "/stat";
    std::ifstream stat_file(stat_path);
    if (!stat_file.is_open()) return false;

    std::string stat_line;
    if (!std::getline(stat_file, stat_line)) return false;

    const size_t end_name = stat_line.rfind(')');
    if (end_name == std::string::npos || end_name + 2 >= stat_line.size())
        return false;

    std::istringstream fields(stat_line.substr(end_name + 2));
    std::string field;

    // Skip to field 20 (starttime)
    for (size_t index = 0; index < 19; ++index) {
        if (!(fields >> field)) return false;
    }

    if (!(fields >> field)) return false;

    try {
        size_t used = 0;
        const uint64_t current_ticks = std::stoull(field, &used);
        if (used != field.size() || current_ticks != proof.start_ticks)
            return false;
    } catch (...) {
        return false;
    }

    return true;
}

FdIntegrityStatus Launcher::Child::checkFdIntegrity() const {
    FdIntegrityStatus status;
    status.descriptor_intact = channel_.established();
    status.socket_valid = !channel_.poisoned();
    status.replacement_detected = false;
    return status;
}

RenewalFailureState Launcher::Child::renewalState() const {
    return renewal_state_.load(std::memory_order_acquire);
}

bool Launcher::Child::transitionRenewalState(RenewalFailureState next_state) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    const auto current = renewal_state_.load(std::memory_order_relaxed);

    // Validate state transitions
    switch (current) {
        case RenewalFailureState::Active:
            if (next_state != RenewalFailureState::RenewalDue &&
                next_state != RenewalFailureState::Active)
                return false;
            break;
        case RenewalFailureState::RenewalDue:
            if (next_state != RenewalFailureState::RenewalFailed &&
                next_state != RenewalFailureState::Active)
                return false;
            break;
        case RenewalFailureState::RenewalFailed:
            if (next_state != RenewalFailureState::ProtectedEntryBlocked)
                return false;
            break;
        case RenewalFailureState::ProtectedEntryBlocked:
            return false;  // Terminal state
    }

    renewal_state_.store(next_state, std::memory_order_release);
    return true;
}

bool Launcher::Child::canEnterProtectedEntry() const {
    const auto state = renewalState();
    return state != RenewalFailureState::ProtectedEntryBlocked;
}

} // namespace xovm::material
