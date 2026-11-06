#ifndef XOVM_RUNTIME_GUARDIAN_INTEGRATION_H
#define XOVM_RUNTIME_GUARDIAN_INTEGRATION_H

#include <cstdint>
#include <memory>
#include <optional>

#include "dynamic_vm_schema.h"
#include "guardian_channel.h"
#include "integrity_state.h"

namespace xovm::material {

// Runtime integration with Guardian process verification (Worker side).
//
// The bridge wraps a GuardianChannel (Worker role) and a LeaseState so that
// the window-execution path can participate in the bilateral challenge and
// lease-renewal protocol without touching the channel directly.
class RuntimeGuardianBridge {
public:
    // Construct a Worker-side bridge bound to an established GuardianChannel.
    // `channel` must outlive the bridge.
    static std::optional<RuntimeGuardianBridge> create(
        GuardianChannel &channel,
        const IntegrityState &integrity_state);

    // Respond to the guardian's challenge (Worker side).
    // Delegates to channel.serveChallenge(). Returns false if channel is not
    // established or the challenge packet cannot be validated.
    bool serveChallenge();

    // Receive the GuardianGeneration sent by the guardian after its challenge
    // succeeds, and acquire a LeasePin for the returned generation.
    // `now_ns` should be CLOCK_MONOTONIC in nanoseconds.
    std::optional<LeasePin> receiveAndAcquireGeneration(uint64_t now_ns);

    // Attempt to renew the lease if due.
    bool renewLeaseIfDue(uint64_t now_ns);

    // Pin the current generation (for executing a window).
    std::optional<LeasePin> leasePin(uint64_t now_ns) const;

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

    // Whether the underlying channel is still established
    bool channelEstablished() const;

private:
    RuntimeGuardianBridge(GuardianChannel &channel,
                          IntegrityState integrity_state);

    GuardianChannel *channel_;                  // non-owning; outlives bridge
    std::shared_ptr<LeaseState> lease_state_;   // shared so bridge is movable
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
