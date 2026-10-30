#include <cassert>
#include <cstdint>
#include <optional>

#include "runtime/cloud_material/continuation_executor.h"
#include "runtime/cloud_material/dynamic_vm_schema.h"
#include "runtime/cloud_material/runtime_guardian_integration.h"

namespace xovm::material::test {

// End-to-end integration test
bool testWindowConsumptionLifecycle() {
    // Create window selector
    xovm::material::DynamicVmWindowSelectorV3 selector;
    selector.format_version = kDynamicVmSelectiveFormatVersionV3;
    selector.abi_id = 1;
    selector.node_id = 1;
    selector.semantic = xovm::material::ContinuationNodeSemanticV2::LoadI32;
    selector.abi_hash = xovm::material::DynamicHash{};
    selector.graph_commitment = xovm::material::DynamicHash{};
    
    // Initialize consumer
    auto consumer = xovm::material::WindowConsumer::create(selector);
    assert(consumer.has_value() && "Failed to create WindowConsumer");
    
    // Test phase transitions
    assert(!consumer->isComplete() && "Should not be complete initially");
    assert(consumer->currentPhase() == xovm::material::WindowExecutionPhase::PreExecution);
    
    // Advance through phases
    assert(consumer->advancePhase(xovm::material::WindowExecutionPhase::Executing));
    assert(consumer->currentPhase() == xovm::material::WindowExecutionPhase::Executing);
    
    assert(consumer->advancePhase(xovm::material::WindowExecutionPhase::PostExecution));
    assert(consumer->currentPhase() == xovm::material::WindowExecutionPhase::PostExecution);
    
    assert(consumer->advancePhase(xovm::material::WindowExecutionPhase::Returning));
    assert(consumer->currentPhase() == xovm::material::WindowExecutionPhase::Returning);
    
    // Should be complete now
    assert(consumer->isComplete() && "Should be complete after Returning phase");
    
    // Invalid transitions should fail
    assert(!consumer->advancePhase(xovm::material::WindowExecutionPhase::PreExecution));
    
    return true;
}

// Test Guardian verification
bool testGuardianProcessVerification() {
    // Create integrity state
    xovm::material::DynamicHash initial_state{};
    xovm::material::IntegrityState integrity(initial_state);
    
    // Create bridge
    auto bridge = xovm::material::RuntimeGuardianBridge::create(integrity);
    assert(bridge.has_value() && "Failed to create RuntimeGuardianBridge");
    
    // Valid process verification
    assert(bridge->verifyGuardianProcess(1000, 1000));
    
    // Invalid PID (0)
    assert(!bridge->verifyGuardianProcess(0, 1000));
    
    // Invalid PID (too large)
    assert(!bridge->verifyGuardianProcess(4194304, 1000));
    
    // Invalid UID (too large)
    assert(!bridge->verifyGuardianProcess(1000, 65536));
    
    return true;
}

// Test window grant verification
bool testWindowGrantVerification() {
    xovm::material::DynamicHash initial_state{};
    xovm::material::IntegrityState integrity(initial_state);
    
    auto bridge = xovm::material::RuntimeGuardianBridge::create(integrity);
    assert(bridge.has_value());
    
    // Create valid grant
    xovm::material::WindowGrant grant;
    grant.previous_state_hash = initial_state;
    grant.build_id = xovm::material::DynamicHash{1, 2, 3};
    grant.region_id = xovm::material::DynamicHash{4, 5, 6};
    grant.next_state_hash = xovm::material::DynamicHash{7, 8, 9};
    grant.generation = 1;
    
    assert(bridge->verifyWindowGrant(grant));
    
    // Invalid: empty build_id
    grant.build_id = xovm::material::DynamicHash{};
    assert(!bridge->verifyWindowGrant(grant));
    
    return true;
}

// Test execution context recording
bool testExecutionContextRecording() {
    xovm::material::DynamicHash initial_state{};
    xovm::material::IntegrityState integrity(initial_state);
    
    auto bridge = xovm::material::RuntimeGuardianBridge::create(integrity);
    assert(bridge.has_value());
    
    // Valid context recording
    xovm::material::DynamicHash exec_hash{1, 2, 3};
    assert(bridge->recordExecutionContext(1, 1, exec_hash));
    
    // Invalid: zero window_id
    assert(!bridge->recordExecutionContext(0, 1, exec_hash));
    
    // Invalid: zero continuation_id
    assert(!bridge->recordExecutionContext(1, 0, exec_hash));
    
    // Invalid: empty hash
    assert(!bridge->recordExecutionContext(1, 1, xovm::material::DynamicHash{}));
    
    return true;
}

// Test completion validation
bool testCompletionValidation() {
    xovm::material::DynamicHash initial_state{};
    xovm::material::IntegrityState integrity(initial_state);
    
    auto bridge = xovm::material::RuntimeGuardianBridge::create(integrity);
    assert(bridge.has_value());
    
    // Valid completion
    xovm::material::ContinuationCompletionV2 completion;
    completion.node_id = 1;
    completion.status = xovm::material::ContinuationNodeStatusV2::Continue;
    completion.transition_tail_commitment = xovm::material::DynamicHash{1, 2, 3};
    
    assert(bridge->validateCompletion(completion));
    
    // Invalid: zero node_id
    completion.node_id = 0;
    assert(!bridge->validateCompletion(completion));
    
    completion.node_id = 1;
    
    // Invalid: empty commitment
    completion.transition_tail_commitment = xovm::material::DynamicHash{};
    assert(!bridge->validateCompletion(completion));
    
    return true;
}

}  // namespace xovm::material::test

// Run all integration tests
extern "C" int runEndToEndIntegrationTests() {
    using namespace xovm::material::test;
    
    int tests_passed = 0;
    int tests_failed = 0;
    
    if (testWindowConsumptionLifecycle()) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (testGuardianProcessVerification()) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (testWindowGrantVerification()) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (testExecutionContextRecording()) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (testCompletionValidation()) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    return tests_failed == 0 ? 0 : 1;
}
