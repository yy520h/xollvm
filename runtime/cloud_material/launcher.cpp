#include "launcher.h"

#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <algorithm>

namespace xovm::material {

std::optional<Launcher::Child> Launcher::start(std::array<uint8_t, 32> boot_nonce,
                                               uint64_t process_identity,
                                               const StartOptions &options) {
    if (!options.worker || process_identity == 0 ||
        std::all_of(boot_nonce.begin(), boot_nonce.end(),
                    [](uint8_t byte) { return byte == 0; }))
        return std::nullopt;
    int sockets[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) != 0) return std::nullopt;
    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(sockets[0]);
        ::close(sockets[1]);
        return std::nullopt;
    }
    if (pid == 0) {
        ::close(sockets[0]);
        const int status = options.worker(sockets[1]);
        ::close(sockets[1]);
        _exit(status);
    }
    ::close(sockets[1]);
    return Child{pid, sockets[0]};
}

int Launcher::Child::wait() const {
    if (pid <= 0) return -1;
    int status = 0;
    if (::waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

} // namespace xovm::material
