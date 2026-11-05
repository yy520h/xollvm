#ifndef XOVM_LAUNCHER_H
#define XOVM_LAUNCHER_H

#include "guardian_channel.h"

#include <cstdint>
#include <optional>
#include <atomic>
#include <mutex>

#ifdef XOVM_GUARDIAN_TESTING
#include <functional>
#endif

#include <sys/types.h>

namespace xovm::material {

// Process identity proof for production-level verification
struct ProcessIdentityProof {
    pid_t pid = -1;
    uid_t uid = 0;
    gid_t gid = 0;
    uint64_t start_ticks = 0;
    dev_t cwd_device = 0;
    ino_t cwd_inode = 0;

    bool operator==(const ProcessIdentityProof &other) const = default;
};

// Result of FD integrity verification
struct FdIntegrityStatus {
    bool descriptor_intact = false;
    bool socket_valid = false;
    bool replacement_detected = false;
};

// Renewal failure state transition
enum class RenewalFailureState : uint8_t {
    Active = 0,
    RenewalDue = 1,
    RenewalFailed = 2,
    ProtectedEntryBlocked = 3,
};

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

        // Production-level process identity verification
        std::optional<ProcessIdentityProof> captureProcessIdentity() const;
        bool verifyProcessIdentity(const ProcessIdentityProof &proof) const;

        // FD integrity verification with replacement detection
        FdIntegrityStatus checkFdIntegrity() const;

        // Renewal failure state management
        RenewalFailureState renewalState() const;
        bool transitionRenewalState(RenewalFailureState next_state);
        bool canEnterProtectedEntry() const;

        int wait();
        void terminate();

    private:
        Child(pid_t pid, int pidfd, GuardianChannel channel)
            : pid_(pid), pidfd_(pidfd), channel_(std::move(channel)) {}

        pid_t pid_ = -1;
        int pidfd_ = -1;
        GuardianChannel channel_;
        ProcessIdentityProof captured_identity_;
        std::atomic<RenewalFailureState> renewal_state_{RenewalFailureState::Active};
        mutable std::mutex state_mutex_;
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
