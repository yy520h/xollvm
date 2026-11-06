#include "runtime_guardian_integration.h"

#include <time.h>

namespace xovm::material {

// ---------------------------------------------------------------------------
// RuntimeGuardianBridge
// ---------------------------------------------------------------------------

RuntimeGuardianBridge::RuntimeGuardianBridge(GuardianChannel &channel,
                                             IntegrityState integrity_state)
    : channel_(&channel),
#ifdef XOVM_GUARDIAN_TESTING
      lease_state_(std::make_shared<LeaseState>(120000000000ULL, channel)),
#else
      lease_state_(std::make_shared<LeaseState>(channel)),
#endif
      integrity_state_(std::move(integrity_state)) {}

std::optional<RuntimeGuardianBridge> RuntimeGuardianBridge::create(
    GuardianChannel &channel,
    const IntegrityState &integrity_state) {
    if (!channel.established() || channel.role() != GuardianChannel::Role::Worker)
        return std::nullopt;
    return RuntimeGuardianBridge(channel, integrity_state);
}

bool RuntimeGuardianBridge::serveChallenge() {
    if (!channel_ || !channel_->established()) return false;
    return channel_->serveChallenge();
}

std::optional<LeasePin> RuntimeGuardianBridge::receiveAndAcquireGeneration(
    uint64_t now_ns) {
    if (!channel_ || !channel_->established()) return std::nullopt;
    auto gen = channel_->receiveGeneration();
    if (!gen) return std::nullopt;
    return lease_state_->acquire(gen->sent_at_ns, gen->grant.generation,
                                 now_ns, gen->grant.expires_at_ms * 1'000'000ULL);
}

bool RuntimeGuardianBridge::renewLeaseIfDue(uint64_t now_ns) {
    if (!lease_state_) return false;
    return lease_state_->renewIfDue(now_ns);
}

std::optional<LeasePin> RuntimeGuardianBridge::leasePin(uint64_t now_ns) const {
    if (!lease_state_) return std::nullopt;
    return lease_state_->pin(now_ns);
}

bool RuntimeGuardianBridge::channelEstablished() const {
    return channel_ && channel_->established();
}

bool RuntimeGuardianBridge::verifyGuardianProcess(uint32_t guardian_pid,
                                                  uint32_t guardian_uid) const {
    if (guardian_pid == 0 || guardian_pid > 4194303)
        return false;
    if (guardian_uid > 65535)
        return false;
    // Verify the channel's peer PID matches what the caller claims.
    if (channel_ && static_cast<uint32_t>(channel_->peerPid()) != guardian_pid)
        return false;
    return true;
}

bool RuntimeGuardianBridge::verifyWindowGrant(
    const WindowGrant &grant) const {
    if (grant.previous_state_hash != integrity_state_.value())
        return false;
    if (grant.build_id == DynamicHash{} || grant.region_id == DynamicHash{})
        return false;
    if (grant.next_state_hash == DynamicHash{} ||
        grant.next_state_hash == grant.previous_state_hash)
        return false;
    if (grant.generation == 0)
        return false;
    return true;
}

bool RuntimeGuardianBridge::recordExecutionContext(
    uint64_t window_id, uint64_t continuation_id,
    const DynamicHash &execution_hash) const {
    if (window_id == 0 || continuation_id == 0)
        return false;
    if (execution_hash == DynamicHash{})
        return false;
    return true;
}

bool RuntimeGuardianBridge::validateCompletion(
    uint32_t node_id, ContinuationNodeStatusV2 status,
    const DynamicHash &commitment) const {
    if (node_id == 0)
        return false;
    if (commitment == DynamicHash{})
        return false;
    if (status != ContinuationNodeStatusV2::Continue &&
        status != ContinuationNodeStatusV2::Return)
        return false;
    return true;
}

// ---------------------------------------------------------------------------
// WindowConsumer
// ---------------------------------------------------------------------------

std::optional<WindowConsumer> WindowConsumer::create(
    const DynamicVmWindowSelectorV3 &selector) {
    if (selector.abi_id == 0 || selector.node_id == 0)
        return std::nullopt;
    if (selector.abi_hash == DynamicHash{} ||
        selector.graph_commitment == DynamicHash{})
        return std::nullopt;
    return WindowConsumer(selector);
}

bool WindowConsumer::advancePhase(WindowExecutionPhase::Type next_phase) {
    if (!validatePhaseTransition(current_phase_, next_phase))
        return false;
    current_phase_ = next_phase;
    return true;
}

bool WindowConsumer::validatePhaseTransition(
    WindowExecutionPhase::Type from, WindowExecutionPhase::Type to) const {
    switch (from) {
    case WindowExecutionPhase::PreExecution:
        return to == WindowExecutionPhase::Executing;
    case WindowExecutionPhase::Executing:
        return to == WindowExecutionPhase::PostExecution;
    case WindowExecutionPhase::PostExecution:
        return to == WindowExecutionPhase::Returning;
    case WindowExecutionPhase::Returning:
        return false;  // Terminal state
    }
    return false;
}

bool WindowConsumer::isComplete() const {
    return current_phase_ == WindowExecutionPhase::Returning;
}

WindowExecutionPhase::Type WindowConsumer::currentPhase() const {
    return current_phase_;
}

}  // namespace xovm::material
