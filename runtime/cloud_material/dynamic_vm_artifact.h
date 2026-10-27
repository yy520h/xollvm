#ifndef XOVM_DYNAMIC_VM_ARTIFACT_H
#define XOVM_DYNAMIC_VM_ARTIFACT_H

#include "dynamic_vm_schema.h"

#include <optional>

namespace xovm::material {

struct ArtifactSource {
    DynamicHash build_id{};
    DynamicHash region_id{};
    std::array<uint8_t, 32> artifact_key{};
    std::vector<uint8_t> bytecode;
    std::vector<uint8_t> handler_shards;
    std::vector<uint8_t> continuation_descriptors;
    std::vector<uint8_t> relocation_descriptors;
};

struct DecryptedVmArtifact {
    DynamicHash build_id{};
    DynamicHash region_id{};
    std::vector<uint8_t> bytecode;
    std::vector<uint8_t> handler_shards;
    std::vector<uint8_t> continuation_descriptors;
    std::vector<uint8_t> relocation_descriptors;
};

std::optional<EncryptedVmArtifact> buildEncryptedVmArtifact(const ArtifactSource &source);
DynamicHash computeEncryptedVmArtifactHash(const EncryptedVmArtifact &artifact);
bool validateEncryptedVmArtifactMetadata(const EncryptedVmArtifact &artifact,
                                         const DynamicHash &build_id,
                                         const DynamicHash &region_id,
                                         const DynamicHash &expected_artifact_hash);
std::optional<DecryptedVmArtifact> decryptEncryptedVmArtifact(
    const EncryptedVmArtifact &artifact,
    std::span<const uint8_t, 32> artifact_key,
    const DynamicHash &build_id,
    const DynamicHash &region_id,
    const DynamicHash &expected_artifact_hash);
void secureClear(DecryptedVmArtifact &artifact);

} // namespace xovm::material

#endif
