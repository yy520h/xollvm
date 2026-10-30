#include "runtime_guardian_integration.h"

namespace xovm::material {

std::optional<RuntimeGuardianBridge> RuntimeGuardianBridge::create(
    const IntegrityState &integrity_state) {
    return RuntimeGuardianBridge(integrity_state);
}

bool RuntimeGuardianBridge::verifyGuardianProcess(uint32_t guardian_pid,
                                                  uint32_t guardian_uid) const {
    // Validate guardian PID and UID are reasonable
    // Current: basic range checks
    // Future: verify against actual /proc for production
    
    if (guardian_pid == 0 || guardian_pid > 4194303)  // Max PID value
        return false;
    
    if (guardian_uid > 65535)  // Max UID value
        return false;
    
    return true;
}

bool RuntimeGuardianBridge::verifyWindowGrant(
    const WindowGrant &grant) const {
    // Verify grant properties match integrity state expectations
    
    // Check that grant's previous state matches current integrity state
    if (grant.previous_state_hash != integrity_state_.value())
        return false;
    
    // Verify grant has valid build and region IDs (non-zero)
    if (grant.build_id == DynamicHash{} || grant.region_id == DynamicHash{})
        return false;
    
    // Verify next state hash is not zero (must be different from previous)
    if (grant.next_state_hash == DynamicHash{} ||
        grant.next_state_hash == grant.previous_state_hash)
        return false;
    
    // Verify generation is reasonable
    if (grant.generation == 0)
        return false;
    
    return true;
}

bool RuntimeGuardianBridge::recordExecutionContext(
    uint64_t window_id, uint64_t continuation_id,
    const DynamicHash &execution_hash) const {
    // Record execution for audit trail
    // Current: validation only
    // Future: actual logging to audit buffer
    
    if (window_id == 0 || continuation_id == 0)
        return false;
    
    if (execution_hash == DynamicHash{})
        return false;
    
    return true;
}

bool RuntimeGuardianBridge::validateCompletion(
    uint32_t node_id, ContinuationNodeStatusV2 status,
    const DynamicHash &commitment) const {
    // Validate completion before returning to guardian

    // Node ID must be non-zero
    if (node_id == 0)
        return false;

    // Transition tail commitment must be valid
    if (commitment == DynamicHash{})
        return false;

    // Status must be valid
    if (status != ContinuationNodeStatusV2::Continue &&
        status != ContinuationNodeStatusV2::Return)
        return false;

    return true;
}

std::optional<WindowConsumer> WindowConsumer::create(
    const DynamicVmWindowSelectorV3 &selector) {
    // Validate selector before creating consumer
    if (selector.abi_id == 0 || selector.node_id == 0)
        return std::nullopt;
    
    if (selector.abi_hash == DynamicHash{} ||
        selector.graph_commitment == DynamicHash{})
        return std::nullopt;
    
    return WindowConsumer(selector);
}

bool WindowConsumer::advancePhase(WindowExecutionPhase::Type next_phase) {
    // Validate phase transition
    if (!validatePhaseTransition(current_phase_, next_phase))
        return false;
    
    current_phase_ = next_phase;
    return true;
}

bool WindowConsumer::validatePhaseTransition(
    WindowExecutionPhase::Type from, WindowExecutionPhase::Type to) const {
    // Define valid state transitions
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
