#ifndef XOVM_LAUNCHER_H
#define XOVM_LAUNCHER_H

#include "guardian_channel.h"

#include <optional>
#include <functional>
#include <sys/types.h>

namespace xovm::material {

class Launcher {
public:
    struct Child {
        pid_t pid = -1;
        int guardian_fd = -1;
        int wait() const;
    };

    struct StartOptions {
        std::function<int(int)> worker;
    };

    static std::optional<Child> start(std::array<uint8_t, 32> boot_nonce,
                                      uint64_t process_identity,
                                      const StartOptions &options);

    static std::optional<GuardianChannel> createWorkerChannel(
        std::array<uint8_t, 32> boot_nonce, uint64_t process_identity,
        const GuardianChannelHello &hello) {
        GuardianChannel channel(boot_nonce, process_identity);
        if (!channel.handshake(hello)) return std::nullopt;
        channel.authorizeFromLauncher();
        return channel;
    }

    static bool validateWorkerEntry(const GuardianChannel &channel) {
        return channel.established() && channel.launcher_authorized_ && channel.processIdentity() != 0;
    }
};

} // namespace xovm::material

#endif
