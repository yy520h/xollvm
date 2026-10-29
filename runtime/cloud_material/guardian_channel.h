#ifndef XOVM_GUARDIAN_CHANNEL_H
#define XOVM_GUARDIAN_CHANNEL_H

#include "dynamic_vm_schema.h"

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>

#include <sys/types.h>

namespace xovm::material {

class Launcher;
struct GuardianChannelState;

struct GuardianGeneration {
    GuardianGeneration() = default;
    ~GuardianGeneration();
    GuardianGeneration(GuardianGeneration &&other) noexcept;
    GuardianGeneration &operator=(GuardianGeneration &&other) noexcept;
    GuardianGeneration(const GuardianGeneration &) = delete;
    GuardianGeneration &operator=(const GuardianGeneration &) = delete;

    std::array<uint8_t, 16> request_id{};
    uint64_t sent_at_ns = 0;
    DynamicHash artifact_hash{};
    WindowGrant grant;
    std::array<uint8_t, 32> grant_key{};
};

class GuardianChannel {
public:
    enum class Role : uint8_t { Guardian = 1, Worker = 2 };

    GuardianChannel() = default;
    ~GuardianChannel();
    GuardianChannel(GuardianChannel &&other) noexcept;
    GuardianChannel &operator=(GuardianChannel &&other) noexcept;
    GuardianChannel(const GuardianChannel &) = delete;
    GuardianChannel &operator=(const GuardianChannel &) = delete;

    bool challenge(uint64_t challenge_counter, uint64_t generation);
    bool serveChallenge();
    bool installGeneration(GuardianGeneration generation);
    std::optional<GuardianGeneration> receiveGeneration();
    bool shutdown();
    bool receiveShutdown();
    bool established() const;
    bool poisoned() const;
    Role role() const;
    pid_t peerPid() const;
    uint64_t processIdentity() const;
    void close();

private:
    explicit GuardianChannel(std::shared_ptr<GuardianChannelState> state);
    static std::optional<GuardianChannel> adopt(
        int fd, Role role, const std::array<uint8_t, 32> &boot_nonce,
        const std::array<uint8_t, 16> &session_id, pid_t peer_pid);

    bool guardianHandshake(const GuardianChannelHello &hello,
                           uint64_t current_window_id);
    bool workerHandshake(const GuardianChannelHello &hello,
                         uint64_t current_window_id);
    std::shared_ptr<GuardianChannelState> livenessState() const;

    std::shared_ptr<GuardianChannelState> state_;

    friend class Launcher;
    friend class LeaseState;
};

class LeasePin {
public:
    LeasePin() = default;
    LeasePin(LeasePin &&) noexcept = default;
    LeasePin &operator=(LeasePin &&) noexcept = default;
    LeasePin(const LeasePin &) = delete;
    LeasePin &operator=(const LeasePin &) = delete;

    uint64_t generation() const;
    uint64_t deadlineNs() const;
    explicit operator bool() const;

private:
    struct Generation {
        const uint64_t number;
        const uint64_t deadline_ns;
    };

    explicit LeasePin(std::shared_ptr<const Generation> generation,
                      pid_t owner_pid)
        : generation_(std::move(generation)), owner_pid_(owner_pid) {}

    std::shared_ptr<const Generation> generation_;
    pid_t owner_pid_ = -1;
    friend class LeaseState;
};

class LeaseState {
public:
#ifdef XOVM_GUARDIAN_TESTING
    explicit LeaseState(uint64_t lease_ns);
    LeaseState(uint64_t lease_ns, const GuardianChannel &channel);
#else
    explicit LeaseState(const GuardianChannel &channel);
#endif

    std::optional<LeasePin> acquire(uint64_t sent_ns, uint64_t generation,
                                    uint64_t now_ns,
                                    uint64_t grant_expires_at_ns);
    bool renewIfDue(uint64_t now_ns);
    void markRenewalFailed();
    std::optional<LeasePin> pin(uint64_t now_ns) const;
    uint64_t deadlineNs() const;
    uint64_t renewAtNs() const;
    bool needsRenewal() const;

private:
    bool channelAlive() const;

    const uint64_t lease_ns_;
    const pid_t owner_pid_;
    mutable std::mutex mutex_;
    uint64_t highest_generation_ = 0;
    uint64_t renew_at_ns_ = 0;
    bool renewal_due_ = false;
    bool renewal_failed_ = false;
    std::shared_ptr<const LeasePin::Generation> current_;
    std::weak_ptr<GuardianChannelState> channel_;
    bool channel_bound_ = false;
};

} // namespace xovm::material

#endif
