#ifndef XOVM_DYNAMIC_VM_RUNTIME_H
#define XOVM_DYNAMIC_VM_RUNTIME_H

#include "dynamic_vm_artifact.h"
#include "dynamic_vm_window_provider.h"
#include "integrity_state.h"
#include "jit_handler_buffer.h"

#include <array>
#include <memory>
#include <optional>

namespace xovm::material {

class DynamicVmWindowConsumer {
public:
    static std::optional<DynamicVmWindowConsumer> create(
        const EncryptedVmArtifact &artifact,
        const DynamicHash &build_id,
        const DynamicHash &region_id,
        const std::array<uint8_t, 16> &session_id,
        const DynamicHash &initial_state);

    std::optional<WindowMaterial> consume(
        const WindowGrant &grant,
        std::span<const uint8_t, 32> session_secret,
        uint64_t now_ms, uint64_t continuation = 0);

    const DynamicHash &stateHash() const { return state_hash_; }
    uint64_t generation() const { return generation_; }
    uint64_t windowId() const { return window_id_; }
    const DynamicHash &integrityCommitment() const { return integrity_commitment_; }

private:
    DynamicVmWindowConsumer(DynamicHash build_id, DynamicHash region_id,
                            std::array<uint8_t, 16> session_id,
                            DynamicHash state_hash)
        : build_id_(build_id), region_id_(region_id), session_id_(session_id),
          state_hash_(state_hash) {}

    DynamicHash build_id_{};
    DynamicHash region_id_{};
    std::array<uint8_t, 16> session_id_{};
    DynamicHash state_hash_{};
    uint64_t generation_ = 0;
    uint64_t window_id_ = 0;
    DynamicHash integrity_commitment_{};
    std::unique_ptr<IntegrityState> integrity_;
};

struct DynamicVmExecutionResult {
    uint32_t status = 0;
    uint32_t ip = 0;
    uint32_t return_value = 0;
};

std::optional<DynamicVmExecutionResult> executeDynamicVmArtifact(
    const EncryptedVmArtifact &artifact,
    std::span<const uint8_t, 32> artifact_key,
    const DynamicHash &build_id, const DynamicHash &region_id,
    uint32_t initial_ip = 0);

} // namespace xovm::material

#endif
