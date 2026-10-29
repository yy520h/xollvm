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

struct DynamicVmExecutionResult {
    uint32_t status = 0;
    uint32_t ip = 0;
    uint32_t return_value = 0;
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
    uint64_t generation() const { return generation_; }
    uint64_t windowId() const { return window_id_; }
    uint64_t expiresAtMs() const { return expires_at_ms_; }
    bool live() const { return live_; }
    bool matchesDecodeSalt(uint8_t salt) const { return material_.decode[0] == salt; }

private:
    friend class DynamicVmWindowConsumer;
#if defined(XOVM_DYNAMIC_VM_TESTING)
    friend std::optional<DynamicVmExecutionResult> executeDynamicVmArtifactForTesting(
        const EncryptedVmArtifact &, ConsumedDynamicVmWindow &&, uint64_t,
        uint32_t);
#endif
    ConsumedDynamicVmWindow(DynamicHash build_id, DynamicHash region_id,
                            DynamicHash artifact_hash, uint64_t generation,
                            uint64_t window_id, uint64_t expires_at_ms,
                            WindowMaterial material)
        : build_id_(build_id), region_id_(region_id), artifact_hash_(artifact_hash),
          generation_(generation), window_id_(window_id),
          expires_at_ms_(expires_at_ms), material_(material) {}
    void clear();

    DynamicHash build_id_{};
    DynamicHash region_id_{};
    DynamicHash artifact_hash_{};
    uint64_t generation_ = 0;
    uint64_t window_id_ = 0;
    uint64_t expires_at_ms_ = 0;
    WindowMaterial material_{};
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

private:
    std::optional<ConsumedDynamicVmWindow> consumeValidated(
        const WindowGrant &grant,
        std::span<const uint8_t, 32> session_secret,
        uint64_t now_ms, uint64_t continuation,
        bool replacement);
    void invalidate();
    DynamicVmWindowConsumer(DynamicHash build_id, DynamicHash region_id,
                            DynamicHash artifact_hash,
                            std::array<uint8_t, 16> session_id,
                            DynamicHash state_hash, uint64_t generation)
        : build_id_(build_id), region_id_(region_id), artifact_hash_(artifact_hash),
          session_id_(session_id), state_hash_(state_hash), generation_(generation) {}

    DynamicHash build_id_{};
    DynamicHash region_id_{};
    DynamicHash artifact_hash_{};
    std::array<uint8_t, 16> session_id_{};
    DynamicHash state_hash_{};
    uint64_t generation_ = 0;
    uint64_t window_id_ = 0;
    DynamicHash integrity_commitment_{};
    std::unique_ptr<IntegrityState> integrity_;
};

#if defined(XOVM_DYNAMIC_VM_TESTING)
// Test-only native seam. The move consumes the authenticated window authority;
// no raw artifact-key execution entry is exposed.
std::optional<DynamicVmExecutionResult> executeDynamicVmArtifactForTesting(
    const EncryptedVmArtifact &artifact,
    ConsumedDynamicVmWindow &&window,
    uint64_t now_ms,
    uint32_t initial_ip = 0);
#endif

} // namespace xovm::material

#endif
