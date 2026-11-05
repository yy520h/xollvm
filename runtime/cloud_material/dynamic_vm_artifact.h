#ifndef XOVM_DYNAMIC_VM_ARTIFACT_H
#define XOVM_DYNAMIC_VM_ARTIFACT_H

#include "dynamic_vm_schema.h"

#include <optional>

namespace xovm::material {

struct DynamicVmNodeCapabilityV3 {
    uint32_t node_id = 0;
    std::array<uint8_t, 32> capability{};
};

struct ArtifactSourceV3 {
    DynamicHash build_id{};
    DynamicHash region_id{};
    std::vector<DynamicVmNodeCapabilityV3> node_capabilities;
    std::vector<uint8_t> bytecode;
    std::vector<uint8_t> handler_shards;
    std::vector<uint8_t> continuation_descriptors;
    std::vector<uint8_t> relocation_descriptors;
};

struct DynamicVmPrivateCapabilityV3 {
    DynamicVmWindowSelectorV3 selector;
    std::array<uint8_t, 32> capability{};
};

class DynamicVmPrivateRegistrationV3 {
public:
    DynamicVmPrivateRegistrationV3() = default;
    DynamicVmPrivateRegistrationV3(const DynamicVmPrivateRegistrationV3 &) = delete;
    DynamicVmPrivateRegistrationV3 &operator=(
        const DynamicVmPrivateRegistrationV3 &) = delete;
    DynamicVmPrivateRegistrationV3(DynamicVmPrivateRegistrationV3 &&) noexcept;
    DynamicVmPrivateRegistrationV3 &operator=(
        DynamicVmPrivateRegistrationV3 &&) noexcept;
    ~DynamicVmPrivateRegistrationV3();

    const DynamicHash &buildId() const { return build_id_; }
    const DynamicHash &regionId() const { return region_id_; }
    const DynamicHash &artifactHash() const { return artifact_hash_; }
    const std::vector<DynamicVmPrivateCapabilityV3> &capabilities() const {
        return capabilities_;
    }
    std::optional<std::array<uint8_t, 32>> capabilityFor(
        const DynamicVmWindowSelectorV3 &selector) const;
    void clear();

private:
    friend struct BuiltDynamicVmArtifactV3;
    friend std::optional<struct BuiltDynamicVmArtifactV3>
    buildSelectiveEncryptedVmArtifactV3(const ArtifactSourceV3 &);
    DynamicHash build_id_{};
    DynamicHash region_id_{};
    DynamicHash artifact_hash_{};
    std::vector<DynamicVmPrivateCapabilityV3> capabilities_;
};

struct BuiltDynamicVmArtifactV3 {
    EncryptedVmArtifact artifact;
    DynamicVmPrivateRegistrationV3 registration;
};

class DecryptedDynamicVmNodeV3 {
public:
    DecryptedDynamicVmNodeV3() = default;
    DecryptedDynamicVmNodeV3(const DecryptedDynamicVmNodeV3 &) = delete;
    DecryptedDynamicVmNodeV3 &operator=(const DecryptedDynamicVmNodeV3 &) = delete;
    DecryptedDynamicVmNodeV3(DecryptedDynamicVmNodeV3 &&) noexcept;
    DecryptedDynamicVmNodeV3 &operator=(DecryptedDynamicVmNodeV3 &&) noexcept;
    ~DecryptedDynamicVmNodeV3();

    const DynamicVmExecutionAbiV2 &abi() const { return abi_; }
    const DynamicVmExecutionDescriptorV2 &descriptor() const {
        return descriptor_;
    }
    const ContinuationNodeV2 &node() const { return node_; }
    const std::vector<uint8_t> &bytecodeBlock() const { return bytecode_block_; }
    const std::vector<uint8_t> &handlerShard() const { return handler_shard_; }
    void clear();

private:
    friend std::optional<DecryptedDynamicVmNodeV3>
    decryptSelectiveDynamicVmNodeV3(
        const EncryptedVmArtifact &, const DynamicVmWindowSelectorV3 &,
        std::span<const uint8_t, 32>, const DynamicHash &, const DynamicHash &,
        const DynamicHash &);
    DynamicVmExecutionAbiV2 abi_{};
    DynamicVmExecutionDescriptorV2 descriptor_{};
    ContinuationNodeV2 node_{};
    std::vector<uint8_t> bytecode_block_;
    std::vector<uint8_t> handler_shard_;
};

std::optional<BuiltDynamicVmArtifactV3> buildSelectiveEncryptedVmArtifactV3(
    const ArtifactSourceV3 &source);
DynamicHash computeEncryptedVmArtifactHash(const EncryptedVmArtifact &artifact);
bool validateEncryptedVmArtifactMetadata(const EncryptedVmArtifact &artifact,
                                         const DynamicHash &build_id,
                                         const DynamicHash &region_id,
                                         const DynamicHash &expected_artifact_hash);
std::optional<DecryptedDynamicVmNodeV3> decryptSelectiveDynamicVmNodeV3(
    const EncryptedVmArtifact &artifact,
    const DynamicVmWindowSelectorV3 &selector,
    std::span<const uint8_t, 32> node_capability,
    const DynamicHash &build_id,
    const DynamicHash &region_id,
    const DynamicHash &expected_artifact_hash);

} // namespace xovm::material

#endif
