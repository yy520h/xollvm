#include "runtime/cloud_material/launcher.h"
#include "runtime/cloud_material/dynamic_vm_window_provider.h"

#include <cassert>
#include <iostream>

using namespace xovm::material;

void test_process_identity_capture() {
    std::cout << "[TEST] Process identity capture and verification" << std::endl;

    Launcher::StartOptions options;
    options.hello.session_id[0] = 1;
    options.hello.generation = 1;
    options.hello.challenge_counter = 1;
    options.hello.previous_state_digest[0] = 2;
    options.current_window_id = 1;

    options.worker = [](GuardianChannel &channel) {
        assert(channel.established());
        assert(channel.receiveShutdown());
        return 0;
    };

    auto child = Launcher::start(options);
    assert(child);

    // Test process identity capture
    auto identity = child->captureProcessIdentity();
    assert(identity);
    assert(identity->pid == child->pid());
    assert(identity->start_ticks > 0);

    std::cout << "  Captured PID: " << identity->pid << std::endl;
    std::cout << "  UID: " << identity->uid << ", GID: " << identity->gid << std::endl;
    std::cout << "  Start ticks: " << identity->start_ticks << std::endl;

    // Verify process identity
    bool verified = child->verifyProcessIdentity(*identity);
    assert(verified);
    std::cout << "  Process identity verified: OK" << std::endl;

    // Test FD integrity
    auto fd_status = child->checkFdIntegrity();
    assert(fd_status.descriptor_intact);
    assert(fd_status.socket_valid);
    std::cout << "  FD integrity: OK" << std::endl;

    child->channel().shutdown();
    assert(child->wait() == 0);
    std::cout << "[PASS] Process identity capture and verification" << std::endl;
}

void test_renewal_failure_state_machine() {
    std::cout << "[TEST] Renewal failure state machine" << std::endl;

    Launcher::StartOptions options;
    options.hello.session_id[0] = 2;
    options.hello.generation = 1;
    options.hello.challenge_counter = 1;
    options.hello.previous_state_digest[0] = 3;
    options.current_window_id = 1;

    options.worker = [](GuardianChannel &channel) {
        assert(channel.established());
        assert(channel.receiveShutdown());
        return 0;
    };

    auto child = Launcher::start(options);
    assert(child);

    // Initial state should be Active
    assert(child->renewalState() == RenewalFailureState::Active);
    std::cout << "  Initial state: Active" << std::endl;

    // Can enter protected entry in Active state
    assert(child->canEnterProtectedEntry());
    std::cout << "  Can enter protected entry: OK" << std::endl;

    // Transition to RenewalDue
    assert(child->transitionRenewalState(RenewalFailureState::RenewalDue));
    assert(child->renewalState() == RenewalFailureState::RenewalDue);
    std::cout << "  Transitioned to RenewalDue" << std::endl;

    // Transition to RenewalFailed
    assert(child->transitionRenewalState(RenewalFailureState::RenewalFailed));
    assert(child->renewalState() == RenewalFailureState::RenewalFailed);
    std::cout << "  Transitioned to RenewalFailed" << std::endl;

    // Transition to ProtectedEntryBlocked
    assert(child->transitionRenewalState(RenewalFailureState::ProtectedEntryBlocked));
    assert(child->renewalState() == RenewalFailureState::ProtectedEntryBlocked);
    std::cout << "  Transitioned to ProtectedEntryBlocked" << std::endl;

    // Cannot enter protected entry in ProtectedEntryBlocked state
    assert(!child->canEnterProtectedEntry());
    std::cout << "  Cannot enter protected entry: OK" << std::endl;

    // Terminal state - no more transitions
    assert(!child->transitionRenewalState(RenewalFailureState::RenewalDue));
    std::cout << "  Terminal state enforced: OK" << std::endl;

    child->channel().shutdown();
    assert(child->wait() == 0);
    std::cout << "[PASS] Renewal failure state machine" << std::endl;
}

void test_invalid_state_transitions() {
    std::cout << "[TEST] Invalid state transitions" << std::endl;

    Launcher::StartOptions options;
    options.hello.session_id[0] = 3;
    options.hello.generation = 1;
    options.hello.challenge_counter = 1;
    options.hello.previous_state_digest[0] = 4;
    options.current_window_id = 1;

    options.worker = [](GuardianChannel &channel) {
        assert(channel.established());
        assert(channel.receiveShutdown());
        return 0;
    };

    auto child = Launcher::start(options);
    assert(child);

    // Try invalid transition from Active directly to ProtectedEntryBlocked
    assert(!child->transitionRenewalState(RenewalFailureState::ProtectedEntryBlocked));
    std::cout << "  Rejected invalid transition Active->ProtectedEntryBlocked" << std::endl;

    // Valid transition to RenewalDue
    assert(child->transitionRenewalState(RenewalFailureState::RenewalDue));

    // Try invalid transition from RenewalDue directly to ProtectedEntryBlocked
    assert(!child->transitionRenewalState(RenewalFailureState::ProtectedEntryBlocked));
    std::cout << "  Rejected invalid transition RenewalDue->ProtectedEntryBlocked" << std::endl;

    // Can transition back to Active from RenewalDue
    assert(child->transitionRenewalState(RenewalFailureState::Active));
    std::cout << "  Allowed recovery transition RenewalDue->Active" << std::endl;

    child->channel().shutdown();
    assert(child->wait() == 0);
    std::cout << "[PASS] Invalid state transitions" << std::endl;
}

int main() {
    std::cout << "=== Guardian/Worker生产编排接入测试 ===" << std::endl << std::endl;

    try {
        test_process_identity_capture();
        std::cout << std::endl;

        test_renewal_failure_state_machine();
        std::cout << std::endl;

        test_invalid_state_transitions();
        std::cout << std::endl;

        std::cout << "=== 所有测试通过 ===" << std::endl;
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "Test failed: " << e.what() << std::endl;
        return 1;
    }
}
