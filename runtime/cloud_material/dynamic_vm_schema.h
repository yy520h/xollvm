#ifndef XOVM_DYNAMIC_VM_SCHEMA_H
#define XOVM_DYNAMIC_VM_SCHEMA_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace xovm::material {

// The execution ABI remains frozen at v2. Selective artifacts and their wire
// requests use a separate format version so v2 bytes are never reinterpreted.
inline constexpr uint16_t kDynamicVmFormatVersion = 2;
inline constexpr uint16_t kDynamicVmSelectiveFormatVersionV3 = 3;
inline constexpr size_t kDynamicVmHashSize = 32;
inline constexpr size_t kDynamicVmWindowSelectorV3EncodedSize = 212;
inline constexpr size_t kWindowAcquireRequestEncodedSize = 374;
inline constexpr size_t kWindowMaterialSize = 192;
inline constexpr size_t kEncryptedWindowMaterialSize = 220;
inline constexpr size_t kDynamicVmMaxWindowMaterial = 256 * 1024;
inline constexpr size_t kDynamicVmMaxDescriptor = 64 * 1024;

// Version 2's first executable profile is deliberately small and closed.  These
// bounds are part of the canonical wire contract, not implementation hints.
inline constexpr uint16_t kDynamicVmExecutionSchemaVersionV2 = 1;
inline constexpr size_t kDynamicVmExecutionAbiV2EncodedSize = 66;
inline constexpr size_t kDynamicVmExecutionDescriptorV2EncodedSize = 120;
inline constexpr size_t kDynamicVmContinuationNodeV2EncodedSize = 140;
inline constexpr size_t kDynamicVmMaxContinuationNodesV2 = 2;
inline constexpr size_t kDynamicVmMaxHandlerShardsV2 = 2;
inline constexpr uint16_t kDynamicVmMaxI32RegistersV2 = 250;
inline constexpr uint32_t kDynamicVmLoadI32InstructionSizeV2 = 6;
inline constexpr uint32_t kDynamicVmReturnI32InstructionSizeV2 = 2;
inline constexpr std::string_view kDynamicVmExecutionAbiHashDomainV2 =
    "xovm.dynamic-vm.execution-abi.v2";
inline constexpr std::string_view kDynamicVmBytecodeBlockHashDomainV2 =
    "xovm.dynamic-vm.bytecode-block.v2";
inline constexpr std::string_view kDynamicVmHandlerShardHashDomainV2 =
    "xovm.dynamic-vm.handler-shard.v2";
inline constexpr std::string_view kDynamicVmTransitionTailHashDomainV2 =
    "xovm.dynamic-vm.transition-tail.v2";
inline constexpr std::string_view kDynamicVmContinuationGraphHashDomainV2 =
    "xovm.dynamic-vm.continuation-graph.v2";

using DynamicHash = std::array<uint8_t, kDynamicVmHashSize>;

enum class DynamicVmExecutionProfileV2 : uint16_t {
    LoadI32ReturnI32 = 1,
};

enum class ContinuationNodeSemanticV2 : uint8_t {
    LoadI32 = 1,
    ReturnI32 = 2,
};

enum class ContinuationNodeStatusV2 : uint8_t {
    Continue = 0,
    Return = 1,
};

enum class DynamicVmSchemaStatusV2 : uint8_t {
    Valid = 0,
    UnsupportedVersion,
    UnsupportedProfile,
    InvalidIdentity,
    InvalidRegisterCounts,
    InvalidRelocation,
    InvalidHashBinding,
    InvalidCount,
    InvalidIdOrder,
    InvalidEntry,
    InvalidSemantic,
    InvalidStatus,
    InvalidTopology,
    InvalidRange,
    InvalidInstructionBoundary,
    UnreachableNode,
    NonCanonicalEncoding,
};

// Canonical execution contract for the bounded v2 LOADI/RET_INT profile.
// abi_id is an issuer-assigned, nonzero identity; its canonical hash is bound
// by every execution descriptor.
struct DynamicVmExecutionAbiV2 {
    uint16_t format_version = kDynamicVmFormatVersion;
    uint16_t schema_version = kDynamicVmExecutionSchemaVersionV2;
    DynamicVmExecutionProfileV2 profile =
        DynamicVmExecutionProfileV2::LoadI32ReturnI32;
    uint16_t flags = 0;
    uint32_t abi_id = 0;
    uint16_t i32_register_count = 0;
    uint16_t i64_register_count = 0;
    uint16_t pointer_register_count = 0;
    uint16_t f64_register_count = 0;
    uint16_t relocation_count = 0;
    uint16_t loadi32_instruction_size = kDynamicVmLoadI32InstructionSizeV2;
    uint16_t return_i32_instruction_size = kDynamicVmReturnI32InstructionSizeV2;
    uint8_t loadi32_opcode = 0;
    uint8_t return_i32_opcode = 0;
    uint8_t loadi32_destination_offset = 1;
    uint8_t loadi32_immediate_offset = 2;
    uint8_t return_i32_source_offset = 1;
    uint8_t reserved8 = 0;
    uint8_t decode_salt = 0;
    std::array<uint8_t, 31> reserved_decode_salt{};
    uint16_t reserved = 0;

    bool operator==(const DynamicVmExecutionAbiV2 &) const = default;
};

struct DynamicVmExecutionDescriptorV2 {
    uint16_t format_version = kDynamicVmFormatVersion;
    uint16_t schema_version = kDynamicVmExecutionSchemaVersionV2;
    uint32_t abi_id = 0;
    DynamicHash abi_hash{};
    DynamicHash bytecode_hash{};
    uint32_t bytecode_size = 0;
    uint32_t handler_shards_size = 0;
    uint32_t entry_node_id = 0;
    uint16_t node_count = 0;
    uint16_t relocation_count = 0;
    DynamicHash graph_commitment{};

    bool operator==(const DynamicVmExecutionDescriptorV2 &) const = default;
};

struct ContinuationNodeV2 {
    uint32_t node_id = 0;
    uint32_t shard_id = 0;
    uint32_t bytecode_offset = 0;
    uint32_t bytecode_size = 0;
    uint32_t shard_offset = 0;
    uint32_t shard_size = 0;
    uint32_t next_node_id = 0;
    uint16_t register_index = 0;
    ContinuationNodeSemanticV2 semantic = ContinuationNodeSemanticV2::LoadI32;
    ContinuationNodeStatusV2 status = ContinuationNodeStatusV2::Continue;
    uint32_t variant_id = 0;
    DynamicHash bytecode_block_commitment{};
    DynamicHash handler_shard_commitment{};
    DynamicHash transition_tail_commitment{};
    uint32_t relocation_offset = 0;
    uint16_t relocation_count = 0;
    uint16_t reserved = 0;

    bool operator==(const ContinuationNodeV2 &) const = default;
};

struct ContinuationGraphV2 {
    DynamicVmExecutionDescriptorV2 descriptor;
    std::vector<ContinuationNodeV2> nodes;

    bool operator==(const ContinuationGraphV2 &) const = default;
};

struct DynamicVmWindowSelectorV3 {
    uint16_t format_version = kDynamicVmSelectiveFormatVersionV3;
    uint16_t execution_schema_version = kDynamicVmExecutionSchemaVersionV2;
    DynamicVmExecutionProfileV2 profile =
        DynamicVmExecutionProfileV2::LoadI32ReturnI32;
    uint16_t flags = 0;
    uint32_t abi_id = 0;
    DynamicHash abi_hash{};
    DynamicHash graph_commitment{};
    uint32_t node_id = 0;
    uint32_t shard_id = 0;
    uint32_t variant_id = 0;
    ContinuationNodeSemanticV2 semantic = ContinuationNodeSemanticV2::LoadI32;
    ContinuationNodeStatusV2 status = ContinuationNodeStatusV2::Continue;
    uint16_t reserved16 = 0;
    uint32_t bytecode_offset = 0;
    uint32_t bytecode_size = 0;
    DynamicHash bytecode_block_commitment{};
    uint32_t shard_offset = 0;
    uint32_t shard_size = 0;
    DynamicHash handler_shard_commitment{};
    uint32_t next_node_id = 0;
    DynamicHash transition_tail_commitment{};
    uint16_t relocation_count = 0;
    uint16_t reserved = 0;

    bool operator==(const DynamicVmWindowSelectorV3 &) const = default;
};

struct EncryptedVmArtifact {
    uint16_t format_version = kDynamicVmSelectiveFormatVersionV3;
    DynamicHash build_id{};
    DynamicHash region_id{};
    DynamicHash artifact_hash{};
    std::vector<uint8_t> encrypted_bytecode_blocks;
    std::vector<uint8_t> encrypted_handler_shards;
    std::vector<uint8_t> continuation_descriptors;
    std::vector<uint8_t> relocation_descriptors;
};

// Canonical wire claim sent by a client when acquiring its next material window.
struct WindowAcquireRequest {
    uint16_t format_version = kDynamicVmSelectiveFormatVersionV3;
    std::array<uint8_t, 16> request_id{};
    DynamicHash build_id{};
    DynamicHash region_id{};
    DynamicHash artifact_hash{};
    uint64_t generation = 0;
    uint64_t window_id = 0;
    DynamicHash previous_state_hash{};
    DynamicVmWindowSelectorV3 selector{};

    bool operator==(const WindowAcquireRequest &) const = default;
};

struct WindowGrant {
    uint16_t format_version = kDynamicVmSelectiveFormatVersionV3;
    DynamicHash build_id{};
    DynamicHash region_id{};
    DynamicHash artifact_hash{};
    DynamicVmWindowSelectorV3 selector{};
    std::array<uint8_t, 16> session_id{};
    uint64_t generation = 0;
    uint64_t window_id = 0;
    DynamicHash previous_state_hash{};
    DynamicHash next_state_hash{};
    uint64_t issued_at_ms = 0;
    uint64_t expires_at_ms = 0;
    uint32_t key_version = 0;
    std::vector<uint8_t> encrypted_window_material;
};

struct ContinuationWindow {
    DynamicHash state_hash{};
    uint64_t window_id = 0;
    std::vector<uint8_t> authenticated_bytes;
};

struct HandlerShardDescriptor {
    uint32_t shard_id = 0;
    uint32_t code_size = 0;
    uint32_t relocation_count = 0;
    DynamicHash commitment{};

    bool operator==(const HandlerShardDescriptor &) const = default;
};

struct HandlerShardPayload {
    HandlerShardDescriptor descriptor;
    std::vector<uint8_t> code;
};

struct GuardianChannelHello {
    uint16_t format_version = kDynamicVmFormatVersion;
    std::array<uint8_t, 32> boot_nonce{};
    std::array<uint8_t, 16> session_id{};
    uint64_t generation = 0;
    uint64_t challenge_counter = 0;
    DynamicHash previous_state_digest{};
};

struct WindowBinding {
    DynamicHash build_id{};
    DynamicHash region_id{};
    DynamicHash artifact_hash{};
    DynamicVmWindowSelectorV3 selector{};
    std::array<uint8_t, 16> session_id{};
    uint64_t generation = 0;
    uint64_t window_id = 0;
    DynamicHash previous_state_hash{};
    uint64_t now_ms = 0;
};

struct WindowMaterial {
    std::array<uint8_t, 32> window{};
    std::array<uint8_t, 32> permutation{};
    std::array<uint8_t, 32> decode{};
    std::array<uint8_t, 32> chaff{};
    std::array<uint8_t, 32> integrity{};
    std::array<uint8_t, 32> jit{};
};

static_assert(sizeof(WindowMaterial) == kWindowMaterialSize);

DynamicVmSchemaStatusV2 validateDynamicVmExecutionAbiV2(
    const DynamicVmExecutionAbiV2 &abi);
std::vector<uint8_t> encodeDynamicVmExecutionAbiV2(
    const DynamicVmExecutionAbiV2 &abi);
std::optional<DynamicVmExecutionAbiV2> decodeDynamicVmExecutionAbiV2(
    std::span<const uint8_t> encoded);
std::optional<DynamicHash> hashDynamicVmExecutionAbiV2(
    const DynamicVmExecutionAbiV2 &abi);
DynamicHash hashDynamicVmBytecodeBlockV2(std::span<const uint8_t> bytes);
DynamicHash hashDynamicVmHandlerShardV2(std::span<const uint8_t> bytes);
std::optional<DynamicHash> hashDynamicVmTransitionTailV2(
    const ContinuationNodeV2 &node);
std::optional<DynamicHash> hashDynamicVmContinuationGraphV2(
    const ContinuationGraphV2 &graph);

std::vector<uint8_t> encodeDynamicVmExecutionDescriptorV2(
    const DynamicVmExecutionDescriptorV2 &descriptor);
std::optional<DynamicVmExecutionDescriptorV2>
decodeDynamicVmExecutionDescriptorV2(std::span<const uint8_t> encoded);
std::vector<uint8_t> encodeContinuationNodeV2(const ContinuationNodeV2 &node);
std::optional<ContinuationNodeV2> decodeContinuationNodeV2(
    std::span<const uint8_t> encoded);
std::vector<uint8_t> encodeContinuationGraphV2(const ContinuationGraphV2 &graph);
std::optional<ContinuationGraphV2> decodeContinuationGraphV2(
    std::span<const uint8_t> encoded);
DynamicVmSchemaStatusV2 validateContinuationGraphV2(
    const DynamicVmExecutionAbiV2 &abi,
    const ContinuationGraphV2 &graph);
DynamicVmSchemaStatusV2 validateContinuationGraphV2(
    const DynamicVmExecutionAbiV2 &abi,
    const ContinuationGraphV2 &graph,
    std::span<const uint8_t> bytecode,
    std::span<const uint8_t> handler_shards);

bool validateDynamicVmWindowSelectorV3(
    const DynamicVmWindowSelectorV3 &selector);
std::optional<DynamicVmWindowSelectorV3> dynamicVmWindowSelectorV3(
    const DynamicVmExecutionAbiV2 &abi,
    const DynamicVmExecutionDescriptorV2 &descriptor,
    const ContinuationNodeV2 &node);
std::vector<uint8_t> encodeDynamicVmWindowSelectorV3(
    const DynamicVmWindowSelectorV3 &selector);
std::optional<DynamicVmWindowSelectorV3> decodeDynamicVmWindowSelectorV3(
    std::span<const uint8_t> encoded);

std::vector<uint8_t> encodeEncryptedVmArtifact(const EncryptedVmArtifact &artifact);
std::optional<EncryptedVmArtifact> decodeEncryptedVmArtifact(std::span<const uint8_t> encoded);
std::vector<uint8_t> encodeWindowAcquireRequest(const WindowAcquireRequest &request);
std::optional<WindowAcquireRequest> decodeWindowAcquireRequest(
    std::span<const uint8_t> encoded);
std::vector<uint8_t> encodeHandlerShardDescriptor(const HandlerShardDescriptor &descriptor);
std::optional<HandlerShardDescriptor> decodeHandlerShardDescriptor(
    std::span<const uint8_t> encoded);
std::vector<uint8_t> encodeHandlerShardPayload(const HandlerShardDescriptor &descriptor,
                                               std::span<const uint8_t> code);
std::optional<HandlerShardPayload> decodeHandlerShardPayload(
    std::span<const uint8_t> encoded);
std::vector<uint8_t> encodeWindowGrant(const WindowGrant &grant);
std::optional<WindowGrant> decodeWindowGrant(std::span<const uint8_t> encoded);
bool validateWindowBinding(const WindowGrant &grant, const WindowBinding &binding);
bool advanceContinuation(const DynamicHash &current_state,
                         const WindowGrant &grant,
                         DynamicHash &next_state);

WindowMaterial deriveWindowMaterial(std::span<const uint8_t, 32> session_secret,
                                    const WindowGrant &grant);

void secureClear(std::vector<uint8_t> &bytes);
void secureClear(WindowMaterial &material);

} // namespace xovm::material

#endif
