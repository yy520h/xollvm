#ifndef XOVM_LAUNCHER_H
#define XOVM_LAUNCHER_H

#include "guardian_channel.h"

#include <cstdint>
#include <optional>

#ifdef XOVM_GUARDIAN_TESTING
#include <functional>
#endif

#include <sys/types.h>

namespace xovm::material {

class Launcher {
public:
    struct StartOptions {
        GuardianChannelHello hello;
        uint64_t current_window_id = 0;
#ifdef XOVM_GUARDIAN_TESTING
        std::function<int(GuardianChannel &)> worker;
#endif
    };

    class Child {
    public:
        Child() = default;
        ~Child();
        Child(Child &&other) noexcept;
        Child &operator=(Child &&other) noexcept;
        Child(const Child &) = delete;
        Child &operator=(const Child &) = delete;

        pid_t pid() const { return pid_; }
        GuardianChannel &channel() { return channel_; }
        const GuardianChannel &channel() const { return channel_; }
        bool challenge(uint64_t challenge_counter, uint64_t generation);
        int wait();
        void terminate();

    private:
        Child(pid_t pid, int pidfd, GuardianChannel channel)
            : pid_(pid), pidfd_(pidfd), channel_(std::move(channel)) {}

        pid_t pid_ = -1;
        int pidfd_ = -1;
        GuardianChannel channel_;
        bool waited_ = false;
        friend class Launcher;
    };

    static std::optional<Child> start(const StartOptions &options);

private:
    static int runWorker(GuardianChannel &channel);
#ifdef XOVM_GUARDIAN_TESTING
    static int runTestWorker(const StartOptions &options,
                             GuardianChannel &channel);
#endif
};

} // namespace xovm::material

#endif
