#ifndef XOVM_RUNTIME_GUARDIAN_INTEGRATION_H
#define XOVM_RUNTIME_GUARDIAN_INTEGRATION_H

#include <cstdint>
#include <optional>

#include "dynamic_vm_schema.h"
#include "integrity_state.h"

namespace xovm::material {

// Runtime integration with Guardian process verification
class RuntimeGuardianBridge {
public:
    // Initialize bridge with guardian state
    static std::optional<RuntimeGuardianBridge> create(
        const IntegrityState &integrity_state);

    // Verify guardian process before window execution
    bool verifyGuardianProcess(uint32_t guardian_pid,
                              uint32_t guardian_uid) const;

    // Verify window grant authenticity
    bool verifyWindowGrant(const WindowGrant &grant) const;

    // Record execution context for guardian audit
    bool recordExecutionContext(uint64_t window_id,
                               uint64_t continuation_id,
                               const DynamicHash &execution_hash) const;

    // Validate completion before returning to guardian
    bool validateCompletion(uint32_t node_id, ContinuationNodeStatusV2 status,
                           const DynamicHash &commitment) const;

private:
    explicit RuntimeGuardianBridge(IntegrityState integrity_state)
        : integrity_state_(std::move(integrity_state)) {}

    IntegrityState integrity_state_;
};

// Window execution lifecycle
struct WindowExecutionPhase {
    enum Type : uint8_t {
        PreExecution = 0,    // Before handler execution
        Executing = 1,       // During handler execution
        PostExecution = 2,   // After handler completion
        Returning = 3,       // Returning to guardian
    };
};

// Window consumption state machine
class WindowConsumer {
public:
    static std::optional<WindowConsumer> create(
        const DynamicVmWindowSelectorV3 &selector);

    // Advance execution phase
    bool advancePhase(WindowExecutionPhase::Type next_phase);

    // Verify current phase transition is valid
    bool validatePhaseTransition(WindowExecutionPhase::Type from,
                                 WindowExecutionPhase::Type to) const;

    // Check if window consumption is complete
    bool isComplete() const;

    // Get current execution phase
    WindowExecutionPhase::Type currentPhase() const;

private:
    explicit WindowConsumer(DynamicVmWindowSelectorV3 selector)
        : selector_(selector), current_phase_(WindowExecutionPhase::PreExecution) {}

    DynamicVmWindowSelectorV3 selector_;
    WindowExecutionPhase::Type current_phase_;
};

} // namespace xovm::material

#endif
