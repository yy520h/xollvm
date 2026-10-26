#include "guardian_channel.h"

namespace xovm::material {

bool GuardianChannel::handshake(const GuardianChannelHello &hello) {
    if (established_ || hello.format_version != kDynamicVmFormatVersion ||
        hello.boot_nonce != boot_nonce_ || process_identity_ == 0 ||
        hello.challenge_counter == 0 || hello.generation == 0 ||
        hello.session_id == std::array<uint8_t, 16>{} ||
        hello.previous_state_digest == DynamicHash{})
        return false;
    generation_ = hello.generation;
    last_challenge_ = hello.challenge_counter - 1;
    established_ = true;
    return true;
}

bool GuardianChannel::challenge(uint64_t challenge_counter, uint64_t generation) {
    if (!established_ || generation != generation_ || challenge_counter <= last_challenge_)
        return false;
    last_challenge_ = challenge_counter;
    return true;
}

bool LeaseState::acquire(uint64_t sent_ns, uint64_t generation) {
    if (!lease_ns_ || generation == 0 || generation <= highest_generation_ ||
        sent_ns > UINT64_MAX - lease_ns_ ||
        (pinned_ && sent_ns >= deadline_ns_ && generation <= generation_)) return false;
    highest_generation_ = generation;
    generation_ = generation;
    deadline_ns_ = sent_ns + lease_ns_;
    renew_at_ns_ = lease_ns_ > 10000000000ULL ? deadline_ns_ - 10000000000ULL : sent_ns;
    renewal_due_ = false;
    pinned_ = true;
    return true;
}

bool LeaseState::renewIfDue(uint64_t now_ns) {
    if (!pinned_ || now_ns < renew_at_ns_) return false;
    renewal_due_ = true;
    return true;
}

bool LeaseState::pin(uint64_t now_ns) const {
    return pinned_ && (now_ns < deadline_ns_ || renewal_due_);
}

} // namespace xovm::material
