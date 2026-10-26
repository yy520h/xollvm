#ifndef XOVM_GUARDIAN_CHANNEL_H
#define XOVM_GUARDIAN_CHANNEL_H

#include "dynamic_vm_schema.h"

#include <array>
#include <cstdint>
#include <optional>

namespace xovm::material {

class GuardianChannel {
public:
    GuardianChannel(std::array<uint8_t, 32> boot_nonce, uint64_t process_identity)
        : boot_nonce_(boot_nonce), process_identity_(process_identity) {}

    bool handshake(const GuardianChannelHello &hello);
    bool challenge(uint64_t challenge_counter, uint64_t generation);
    bool established() const { return established_; }
    uint64_t processIdentity() const { return process_identity_; }

private:
    std::array<uint8_t, 32> boot_nonce_{};
    uint64_t process_identity_ = 0;
    uint64_t last_challenge_ = 0;
    uint64_t generation_ = 0;
    bool established_ = false;
    bool launcher_authorized_ = false;

    void authorizeFromLauncher() { launcher_authorized_ = true; }
    friend class Launcher;
};

class LeaseState {
public:
    explicit LeaseState(uint64_t lease_ns) : lease_ns_(lease_ns) {}

    bool acquire(uint64_t sent_ns, uint64_t generation);
    bool renewIfDue(uint64_t now_ns);
    bool pin(uint64_t now_ns) const;
    void release() { pinned_ = false; }
    uint64_t deadlineNs() const { return deadline_ns_; }
    uint64_t renewAtNs() const { return renew_at_ns_; }
    bool needsRenewal() const { return renewal_due_; }

private:
    uint64_t lease_ns_ = 0;
    uint64_t generation_ = 0;
    uint64_t highest_generation_ = 0;
    uint64_t deadline_ns_ = 0;
    uint64_t renew_at_ns_ = 0;
    bool pinned_ = false;
    bool renewal_due_ = false;
};

} // namespace xovm::material

#endif
