// End-to-end Guardian/Worker integration tests.
//
// These tests exercise the real forked Guardian process (Launcher::start) and
// the RuntimeGuardianBridge bound to the Worker-side channel, proving the
// bilateral challenge / generation / lease protocol works end to end. The
// bridge is the "Guardian process backend": it connects the runtime
// window-execution path to the GuardianChannel protocol.
//
// Compiled with -DXOVM_GUARDIAN_TESTING so Launcher accepts an in-process
// worker lambda that runs inside the forked child (Worker role). The parent
// (Guardian role) drives challenge + installGeneration + shutdown from
// outside.

#include "runtime/cloud_material/dynamic_vm_schema.h"
#include "runtime/cloud_material/dynamic_vm_window_provider.h"
#include "runtime/cloud_material/guardian_channel.h"
#include "runtime/cloud_material/integrity_state.h"
#include "runtime/cloud_material/launcher.h"
#include "runtime/cloud_material/runtime_guardian_integration.h"

#include <cassert>
#include <cstdint>
#include <iostream>

#include <openssl/crypto.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

using namespace xovm::material;

namespace {

// Build a canonical selector + ABI used by the dynamic-vm Guardian tests.
DynamicVmWindowSelectorV3 canonicalSelector() {
    DynamicVmExecutionAbiV2 abi{};
    abi.abi_id = 1;
    abi.i32_register_count = 1;
    abi.loadi32_opcode = 0xa1;
    abi.return_i32_opcode = 0xb2;
    DynamicVmExecutionDescriptorV2 descriptor{};
    descriptor.abi_id = abi.abi_id;
    descriptor.abi_hash = *hashDynamicVmExecutionAbiV2(abi);
    descriptor.bytecode_hash[0] = 1;
    descriptor.bytecode_size = 2;
    descriptor.handler_shards_size = 1;
    descriptor.entry_node_id = 1;
    descriptor.node_count = 1;
    descriptor.graph_commitment[0] = 2;
    ContinuationNodeV2 node{};
    node.node_id = 1;
    node.shard_id = 1;
    node.bytecode_size = 2;
    node.shard_size = 1;
    node.semantic = ContinuationNodeSemanticV2::ReturnI32;
    node.status = ContinuationNodeStatusV2::Return;
    node.variant_id = 1;
    node.bytecode_block_commitment[0] = 3;
    node.handler_shard_commitment[0] = 4;
    node.transition_tail_commitment = *hashDynamicVmTransitionTailV2(node);
    auto selector = dynamicVmWindowSelectorV3(abi, descriptor, node);
    assert(selector);
    return *selector;
}

uint64_t nowMonotonicNs() {
    struct timespec ts {};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL +
           static_cast<uint64_t>(ts.tv_nsec);
}

// WindowConsumer lifecycle is independent of the GuardianChannel and can be
// exercised in a single process.
bool testWindowConsumptionLifecycle() {
    std::cout << "[TEST] WindowConsumer lifecycle" << std::endl;

    DynamicVmWindowSelectorV3 selector{};
    selector.format_version = kDynamicVmSelectiveFormatVersionV3;
    selector.abi_id = 1;
    selector.node_id = 1;
    selector.semantic = ContinuationNodeSemanticV2::LoadI32;
    selector.abi_hash[0] = 1;       // must be non-zero
    selector.graph_commitment[0] = 2; // must be non-zero

    auto consumer = WindowConsumer::create(selector);
    assert(consumer.has_value() && "Failed to create WindowConsumer");

    assert(!consumer->isComplete());
    assert(consumer->currentPhase() == WindowExecutionPhase::PreExecution);

    assert(consumer->advancePhase(WindowExecutionPhase::Executing));
    assert(consumer->advancePhase(WindowExecutionPhase::PostExecution));
    assert(consumer->advancePhase(WindowExecutionPhase::Returning));
    assert(consumer->isComplete());

    // Terminal: no further transitions.
    assert(!consumer->advancePhase(WindowExecutionPhase::PreExecution));

    std::cout << "  [PASS] phase machine OK" << std::endl;
    return true;
}

// Full Guardian/Worker bilateral protocol through Launcher::start, with the
// RuntimeGuardianBridge running inside the forked Worker process. The parent
// (Guardian) issues a challenge and a window generation; the Worker (bridge)
// serves the challenge and acquires a lease pin, then validates the grant.
//
// Worker success/failure is communicated via exit codes: 0 = all steps passed,
// 40-43 = first failing step. The parent validates Guardian-side operations
// directly and checks that the Worker exited 0.

bool testGuardianBridgeProtocol() {
    std::cout << "[TEST] Guardian bridge bilateral protocol (forked)" << std::endl;

    // Use real monotonic-clock timestamps so the lease deadline is in the future.
    uint64_t now_ns = nowMonotonicNs();
    uint64_t now_ms = now_ns / 1'000'000ULL;

    Launcher::StartOptions options;
    options.hello.session_id[0] = 8;
    options.hello.generation = 1;
    options.hello.challenge_counter = 7;
    options.hello.previous_state_digest[0] = 9;
    options.current_window_id = 11;

    options.worker = [now_ms](GuardianChannel &channel) -> int {
        if (!channel.established() ||
            channel.role() != GuardianChannel::Role::Worker) _exit(40);

        DynamicHash initial{};
        initial[0] = 9;  // matches hello.previous_state_digest
        IntegrityState integrity(initial);

        auto bridge = RuntimeGuardianBridge::create(channel, integrity);
        if (!bridge) _exit(40);

        // Answer the Guardian's challenge.
        if (!bridge->serveChallenge()) _exit(41);

        // Receive the generation the Guardian installs and acquire a lease.
        auto pin = bridge->receiveAndAcquireGeneration(nowMonotonicNs());
        if (!pin) _exit(42);
        if (pin->generation() != 2) _exit(42);

        // Verify the guardian process identity.
        if (!bridge->verifyGuardianProcess(
                static_cast<uint32_t>(channel.peerPid()), 1000))
            _exit(43);

        // Build a WindowGrant and verify it.
        WindowGrant grant{};
        grant.format_version = kDynamicVmSelectiveFormatVersionV3;
        grant.build_id[0] = 1;
        grant.region_id[0] = 2;
        grant.generation = 2;
        grant.window_id = 1;
        grant.previous_state_hash = initial;
        grant.next_state_hash[0] = 4;
        grant.issued_at_ms = now_ms;
        grant.expires_at_ms = now_ms + 60000;
        grant.key_version = 1;
        if (!bridge->verifyWindowGrant(grant)) _exit(44);

        if (!channel.receiveShutdown()) _exit(45);
        return 0;
    };

    auto child = Launcher::start(options);
    assert(child && "Launcher::start failed");
    assert(child->pid() > 0);
    assert(child->channel().established());
    assert(child->channel().role() == GuardianChannel::Role::Guardian);

    // Guardian issues a challenge; replay with same counter must be rejected.
    assert(child->challenge(8, 1));
    assert(!child->challenge(8, 1));  // replay rejected — no packet sent, Worker unaffected

    // Guardian installs a window generation for the Worker to acquire.
    GuardianGeneration next;
    next.request_id[0] = 12;
    next.sent_at_ns = now_ns;
    next.artifact_hash[0] = 3;
    next.grant.build_id[0] = 1;
    next.grant.region_id[0] = 2;
    next.grant.session_id = options.hello.session_id;
    next.grant.generation = 2;
    next.grant.window_id = 1;
    next.grant.previous_state_hash = options.hello.previous_state_digest;
    next.grant.next_state_hash[0] = 4;
    next.grant.issued_at_ms = now_ms;
    next.grant.expires_at_ms = now_ms + 60000;
    next.grant.key_version = 1;
    WindowIssueInput issue;
    issue.build_id = next.grant.build_id;
    issue.region_id = next.grant.region_id;
    issue.artifact_hash = next.artifact_hash;
    issue.selector = canonicalSelector();
    issue.session_id = next.grant.session_id;
    issue.generation = next.grant.generation;
    issue.window_id = 1;
    issue.previous_state_hash = next.grant.previous_state_hash;
    issue.next_state_hash = next.grant.next_state_hash;
    issue.now_ms = now_ms;
    issue.expires_at_ms = now_ms + 60000;
    issue.key_version = next.grant.key_version;
    issue.session_secret[0] = 6;
    issue.material.assign(kWindowMaterialSize, 5);
    auto issued = issueWindowGrant(issue);
    assert(issued);
    next.grant = std::move(*issued);
    next.grant_key = issue.session_secret;

    assert(child->channel().installGeneration(std::move(next)));
    assert(child->channel().shutdown());
    int status = child->wait();
    assert(status == 0 && "worker exited with error");

    std::cout << "  [PASS] bridge created, challenge served, generation 2 "
                 "acquired, grant verified" << std::endl;
    return true;
}

} // namespace

extern "C" int runEndToEndIntegrationTests() {
    int passed = 0, failed = 0;
    if (testWindowConsumptionLifecycle()) ++passed; else ++failed;
    if (testGuardianBridgeProtocol()) ++passed; else ++failed;
    std::cout << "End-to-end integration: " << passed << " passed, "
              << failed << " failed" << std::endl;
    return failed == 0 ? 0 : 1;
}

int main() {
    return runEndToEndIntegrationTests();
}
