#ifndef XOVM_DYNAMIC_VM_RUNTIME_H
#define XOVM_DYNAMIC_VM_RUNTIME_H

#include "dynamic_vm_artifact.h"
#include "dynamic_vm_window_provider.h"
#include "integrity_state.h"
#include "jit_handler_buffer.h"

#include <array>
#include <atomic>
#include <memory>
#include <optional>
#include <vector>

namespace xovm::material {

struct DynamicVmExecutionResult {
    uint32_t status = 0;
    uint32_t ip = 0;
    uint32_t return_value = 0;
    bool complete = false;
};

struct DynamicVmPendingControl {
    std::atomic<uint64_t> token{0};
    std::atomic<bool> abandoned{false};
};

class ConsumedDynamicVmWindow {
public:
    ConsumedDynamicVmWindow(const ConsumedDynamicVmWindow &) = delete;
    ConsumedDynamicVmWindow &operator=(const ConsumedDynamicVmWindow &) = delete;
    ConsumedDynamicVmWindow(ConsumedDynamicVmWindow &&other) noexcept;
    ConsumedDynamicVmWindow &operator=(ConsumedDynamicVmWindow &&other) noexcept;
    ~ConsumedDynamicVmWindow();

    const DynamicHash &buildId() const { return build_id_; }
    const DynamicHash &regionId() const { return region_id_; }
    const DynamicHash &artifactHash() const { return artifact_hash_; }
    const DynamicVmWindowSelectorV3 &selector() const { return grant_.selector; }
    uint64_t generation() const { return grant_.generation; }
    uint64_t windowId() const { return grant_.window_id; }
    uint64_t expiresAtMs() const { return grant_.expires_at_ms; }
    bool live() const { return live_; }
    bool matchesDecodeSalt(uint8_t salt) const { return material_.decode[0] == salt; }

private:
    friend class DynamicVmWindowConsumer;
#if defined(XOVM_DYNAMIC_VM_TESTING)
    friend class DynamicVmExecutionStateForTesting;
    friend std::optional<DynamicVmExecutionResult> executeDynamicVmWindowForTesting(
        const EncryptedVmArtifact &, class DynamicVmWindowConsumer &,
        ConsumedDynamicVmWindow &&, class DynamicVmExecutionStateForTesting &,
        uint64_t);
#endif
    ConsumedDynamicVmWindow(DynamicHash build_id, DynamicHash region_id,
                            DynamicHash artifact_hash, WindowGrant grant,
                            WindowMaterial material, DynamicHash commitment,
                            uint64_t continuation, uint64_t pending_token,
                            std::shared_ptr<DynamicVmPendingControl> pending_control)
        : build_id_(build_id), region_id_(region_id), artifact_hash_(artifact_hash),
          grant_(std::move(grant)), material_(material),
          integrity_commitment_(commitment), continuation_(continuation),
          pending_token_(pending_token), pending_control_(std::move(pending_control)) {}
    void clear(bool abandon = true);

    DynamicHash build_id_{};
    DynamicHash region_id_{};
    DynamicHash artifact_hash_{};
    WindowGrant grant_{};
    WindowMaterial material_{};
    DynamicHash integrity_commitment_{};
    uint64_t continuation_ = 0;
    uint64_t pending_token_ = 0;
    std::shared_ptr<DynamicVmPendingControl> pending_control_;
    bool live_ = true;
};

class DynamicVmWindowConsumer {
public:
    DynamicVmWindowConsumer(const DynamicVmWindowConsumer &) = delete;
    DynamicVmWindowConsumer &operator=(const DynamicVmWindowConsumer &) = delete;
    DynamicVmWindowConsumer(DynamicVmWindowConsumer &&other) noexcept;
    DynamicVmWindowConsumer &operator=(DynamicVmWindowConsumer &&other) noexcept;

    static std::optional<DynamicVmWindowConsumer> create(
        const EncryptedVmArtifact &artifact,
        const DynamicHash &build_id,
        const DynamicHash &region_id,
        const DynamicHash &expected_artifact_hash,
        const std::array<uint8_t, 16> &session_id,
        const DynamicHash &initial_state,
        uint64_t generation);

    std::optional<ConsumedDynamicVmWindow> consume(
        const WindowGrant &grant,
        std::span<const uint8_t, 32> session_secret,
        uint64_t now_ms, uint64_t continuation = 0);
    std::optional<ConsumedDynamicVmWindow> installReplacement(
        const WindowGrant &grant,
        std::span<const uint8_t, 32> session_secret,
        uint64_t now_ms, uint64_t continuation = 0);

    const DynamicHash &stateHash() const { return state_hash_; }
    uint64_t generation() const { return generation_; }
    uint64_t windowId() const { return window_id_; }
    const DynamicHash &integrityCommitment() const { return integrity_commitment_; }
    const DynamicVmWindowSelectorV3 &expectedSelector() const {
        return expected_selector_;
    }
    bool pending() const {
        return pending_ && pending_control_ &&
               !pending_control_->abandoned.load(std::memory_order_acquire);
    }

private:
#if defined(XOVM_DYNAMIC_VM_TESTING)
    friend std::optional<DynamicVmExecutionResult> executeDynamicVmWindowForTesting(
        const EncryptedVmArtifact &, DynamicVmWindowConsumer &,
        ConsumedDynamicVmWindow &&, class DynamicVmExecutionStateForTesting &,
        uint64_t);
#endif
    std::optional<ConsumedDynamicVmWindow> consumeValidated(
        const WindowGrant &grant,
        std::span<const uint8_t, 32> session_secret,
        uint64_t now_ms, uint64_t continuation,
        bool replacement);
    bool commitPending(const ConsumedDynamicVmWindow &window);
    void rejectPending(uint64_t token);
    std::optional<DynamicVmWindowSelectorV3> successor(
        const DynamicVmWindowSelectorV3 &selector) const;
    void invalidate();
    DynamicVmWindowConsumer(DynamicHash build_id, DynamicHash region_id,
                            DynamicHash artifact_hash,
                            std::array<uint8_t, 16> session_id,
                            DynamicHash state_hash, uint64_t generation,
                            DynamicVmExecutionAbiV2 abi,
                            ContinuationGraphV2 graph,
                            DynamicVmWindowSelectorV3 expected_selector)
        : build_id_(build_id), region_id_(region_id), artifact_hash_(artifact_hash),
          session_id_(session_id), state_hash_(state_hash), generation_(generation),
          abi_(std::move(abi)), graph_(std::move(graph)),
          expected_selector_(expected_selector) {}

    DynamicHash build_id_{};
    DynamicHash region_id_{};
    DynamicHash artifact_hash_{};
    std::array<uint8_t, 16> session_id_{};
    DynamicHash state_hash_{};
    uint64_t generation_ = 0;
    uint64_t window_id_ = 0;
    DynamicHash integrity_commitment_{};
    std::unique_ptr<IntegrityState> integrity_;
    DynamicVmExecutionAbiV2 abi_{};
    ContinuationGraphV2 graph_{};
    DynamicVmWindowSelectorV3 expected_selector_{};
    uint64_t pending_token_ = 0;
    std::shared_ptr<DynamicVmPendingControl> pending_control_;
    bool pending_ = false;
    bool poisoned_ = false;
};

#if defined(XOVM_DYNAMIC_VM_TESTING)
class DynamicVmExecutionStateForTesting {
public:
    DynamicVmExecutionStateForTesting() = default;
    DynamicVmExecutionStateForTesting(const DynamicVmExecutionStateForTesting &) = delete;
    DynamicVmExecutionStateForTesting &operator=(
        const DynamicVmExecutionStateForTesting &) = delete;
    DynamicVmExecutionStateForTesting(DynamicVmExecutionStateForTesting &&other) noexcept;
    DynamicVmExecutionStateForTesting &operator=(
        DynamicVmExecutionStateForTesting &&other) noexcept;
    ~DynamicVmExecutionStateForTesting();

    uint32_t instructionPointer() const { return instruction_pointer_; }
    uint32_t returnValue() const { return return_value_; }
    bool complete() const { return complete_; }

private:
    friend std::optional<DynamicVmExecutionResult> executeDynamicVmWindowForTesting(
        const EncryptedVmArtifact &, DynamicVmWindowConsumer &,
        ConsumedDynamicVmWindow &&, DynamicVmExecutionStateForTesting &,
        uint64_t);
    void clear();

    DynamicHash artifact_hash_{};
    DynamicHash abi_hash_{};
    uint32_t expected_node_id_ = 0;
    uint32_t instruction_pointer_ = 0;
    uint32_t return_value_ = 0;
    std::vector<uint32_t> registers_;
    bool started_ = false;
    bool complete_ = false;
};

// Test-only native seam. Each call consumes one authenticated node capability.
// No raw capability or whole-artifact execution entry is exported in production.
std::optional<DynamicVmExecutionResult> executeDynamicVmWindowForTesting(
    const EncryptedVmArtifact &artifact,
    DynamicVmWindowConsumer &consumer,
    ConsumedDynamicVmWindow &&window,
    DynamicVmExecutionStateForTesting &state,
    uint64_t now_ms);
#endif

} // namespace xovm::material

#endif
