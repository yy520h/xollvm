#include "dynamic_vm_schema.h"

#include <algorithm>
#include <cstring>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace xovm::material {
namespace {

void put16(std::vector<uint8_t> &out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

void put32(std::vector<uint8_t> &out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value >> 24));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

void put64(std::vector<uint8_t> &out, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<uint8_t>(value >> shift));
}

void putBytes(std::vector<uint8_t> &out, std::span<const uint8_t> bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void putSized(std::vector<uint8_t> &out, std::span<const uint8_t> bytes) {
    put32(out, static_cast<uint32_t>(bytes.size()));
    putBytes(out, bytes);
}

void putHash(std::vector<uint8_t> &out, const DynamicHash &hash) {
    putBytes(out, hash);
}

DynamicHash domainHash(std::string_view domain,
                       std::span<const uint8_t> bytes) {
    std::vector<uint8_t> preimage;
    preimage.reserve(domain.size() + 1 + bytes.size());
    putBytes(preimage, std::span<const uint8_t>(
                           reinterpret_cast<const uint8_t *>(domain.data()),
                           domain.size()));
    preimage.push_back(0);
    putBytes(preimage, bytes);
    DynamicHash hash{};
    unsigned int length = 0;
    if (EVP_Digest(preimage.data(), preimage.size(), hash.data(), &length,
                   EVP_sha256(), nullptr) != 1 || length != hash.size())
        hash.fill(0);
    return hash;
}

bool same(std::span<const uint8_t> left, std::span<const uint8_t> right) {
    return left.size() == right.size() &&
           std::equal(left.begin(), left.end(), right.begin());
}

bool zeroHash(const DynamicHash &hash) {
    return std::all_of(hash.begin(), hash.end(),
                       [](uint8_t byte) { return byte == 0; });
}

uint16_t get16(std::span<const uint8_t> bytes, size_t offset) {
    return static_cast<uint16_t>(static_cast<uint16_t>(bytes[offset]) << 8 |
                                 bytes[offset + 1]);
}

uint32_t get32(std::span<const uint8_t> bytes, size_t offset) {
    return static_cast<uint32_t>(bytes[offset]) << 24 |
           static_cast<uint32_t>(bytes[offset + 1]) << 16 |
           static_cast<uint32_t>(bytes[offset + 2]) << 8 |
           static_cast<uint32_t>(bytes[offset + 3]);
}

bool boundedSlice(uint32_t offset, uint32_t size, uint32_t bound) {
    return size != 0 && offset <= bound && size <= bound - offset;
}

bool validDescriptorV2(const DynamicVmExecutionDescriptorV2 &descriptor) {
    return descriptor.format_version == kDynamicVmFormatVersion &&
           descriptor.schema_version == kDynamicVmExecutionSchemaVersionV2 &&
           descriptor.abi_id != 0 && !zeroHash(descriptor.abi_hash) &&
           !zeroHash(descriptor.bytecode_hash) &&
           descriptor.bytecode_size != 0 &&
           descriptor.bytecode_size <= kDynamicVmMaxWindowMaterial &&
           descriptor.handler_shards_size != 0 &&
           descriptor.handler_shards_size <= kDynamicVmMaxWindowMaterial &&
           descriptor.entry_node_id != 0 && descriptor.node_count != 0 &&
           descriptor.node_count <= kDynamicVmMaxContinuationNodesV2 &&
           descriptor.relocation_count == 0 &&
           !zeroHash(descriptor.graph_commitment);
}

bool validNodeV2(const ContinuationNodeV2 &node) {
    const bool known_semantic =
        node.semantic == ContinuationNodeSemanticV2::LoadI32 ||
        node.semantic == ContinuationNodeSemanticV2::ReturnI32;
    const bool known_status = node.status == ContinuationNodeStatusV2::Continue ||
                              node.status == ContinuationNodeStatusV2::Return;
    return node.node_id != 0 && node.shard_id != 0 && node.variant_id != 0 &&
           node.bytecode_size != 0 && node.shard_size != 0 && known_semantic &&
           known_status && !zeroHash(node.bytecode_block_commitment) &&
           !zeroHash(node.handler_shard_commitment) &&
           !zeroHash(node.transition_tail_commitment) &&
           node.relocation_offset == 0 && node.relocation_count == 0 &&
           node.reserved == 0;
}

bool canonicalGraphShapeV2(const ContinuationGraphV2 &graph) {
    const auto &descriptor = graph.descriptor;
    if (!validDescriptorV2(descriptor) ||
        graph.nodes.size() != descriptor.node_count || graph.nodes.empty() ||
        graph.nodes.size() > kDynamicVmMaxContinuationNodesV2 ||
        descriptor.entry_node_id != graph.nodes.front().node_id)
        return false;
    uint32_t bytecode_end = 0;
    uint32_t shard_end = 0;
    for (size_t index = 0; index < graph.nodes.size(); ++index) {
        const auto &node = graph.nodes[index];
        if (!validNodeV2(node) ||
            !boundedSlice(node.bytecode_offset, node.bytecode_size,
                          descriptor.bytecode_size) ||
            !boundedSlice(node.shard_offset, node.shard_size,
                          descriptor.handler_shards_size) ||
            node.bytecode_offset != bytecode_end ||
            node.shard_offset != shard_end)
            return false;
        if (index != 0 &&
            (graph.nodes[index - 1].node_id >= node.node_id ||
             graph.nodes[index - 1].shard_id >= node.shard_id))
            return false;
        bytecode_end = node.bytecode_offset + node.bytecode_size;
        shard_end = node.shard_offset + node.shard_size;
    }
    if (bytecode_end != descriptor.bytecode_size ||
        shard_end != descriptor.handler_shards_size)
        return false;
    for (const auto &node : graph.nodes) {
        const auto tail = hashDynamicVmTransitionTailV2(node);
        if (!tail || *tail != node.transition_tail_commitment) return false;
    }
    const auto graph_hash = hashDynamicVmContinuationGraphV2(graph);
    if (!graph_hash || *graph_hash != descriptor.graph_commitment) return false;
    if (graph.nodes.size() == 1) {
        const auto &node = graph.nodes.front();
        return node.semantic == ContinuationNodeSemanticV2::ReturnI32 &&
               node.status == ContinuationNodeStatusV2::Return &&
               node.next_node_id == 0;
    }
    const auto &load = graph.nodes[0];
    const auto &ret = graph.nodes[1];
    return load.semantic == ContinuationNodeSemanticV2::LoadI32 &&
           load.status == ContinuationNodeStatusV2::Continue &&
           load.next_node_id == ret.node_id &&
           ret.semantic == ContinuationNodeSemanticV2::ReturnI32 &&
           ret.status == ContinuationNodeStatusV2::Return &&
           ret.next_node_id == 0 &&
           load.register_index == ret.register_index;
}

DynamicVmSchemaStatusV2 validateContinuationGraphStructureV2(
    const DynamicVmExecutionAbiV2 &abi, const ContinuationGraphV2 &graph) {
    const auto abi_status = validateDynamicVmExecutionAbiV2(abi);
    if (abi_status != DynamicVmSchemaStatusV2::Valid) return abi_status;
    const auto &descriptor = graph.descriptor;
    if (descriptor.format_version != kDynamicVmFormatVersion ||
        descriptor.schema_version != kDynamicVmExecutionSchemaVersionV2)
        return DynamicVmSchemaStatusV2::UnsupportedVersion;
    if (descriptor.abi_id != abi.abi_id || zeroHash(descriptor.abi_hash))
        return DynamicVmSchemaStatusV2::InvalidIdentity;
    const auto expected_hash = hashDynamicVmExecutionAbiV2(abi);
    if (!expected_hash || descriptor.abi_hash != *expected_hash)
        return DynamicVmSchemaStatusV2::InvalidHashBinding;
    if (descriptor.relocation_count != 0)
        return DynamicVmSchemaStatusV2::InvalidRelocation;
    if (!validDescriptorV2(descriptor))
        return DynamicVmSchemaStatusV2::InvalidRange;
    if (graph.nodes.size() != descriptor.node_count || graph.nodes.empty() ||
        graph.nodes.size() > kDynamicVmMaxContinuationNodesV2)
        return DynamicVmSchemaStatusV2::InvalidCount;
    if (descriptor.entry_node_id != graph.nodes.front().node_id)
        return DynamicVmSchemaStatusV2::InvalidEntry;

    uint32_t bytecode_end = 0;
    uint32_t shard_end = 0;
    for (size_t index = 0; index < graph.nodes.size(); ++index) {
        const auto &node = graph.nodes[index];
        if (node.node_id == 0 || node.shard_id == 0)
            return DynamicVmSchemaStatusV2::InvalidIdOrder;
        if (node.variant_id == 0)
            return DynamicVmSchemaStatusV2::InvalidIdentity;
        if (node.semantic != ContinuationNodeSemanticV2::LoadI32 &&
            node.semantic != ContinuationNodeSemanticV2::ReturnI32)
            return DynamicVmSchemaStatusV2::InvalidSemantic;
        if (node.status != ContinuationNodeStatusV2::Continue &&
            node.status != ContinuationNodeStatusV2::Return)
            return DynamicVmSchemaStatusV2::InvalidStatus;
        if (node.relocation_offset != 0 || node.relocation_count != 0)
            return DynamicVmSchemaStatusV2::InvalidRelocation;
        if (zeroHash(node.bytecode_block_commitment) ||
            zeroHash(node.handler_shard_commitment) ||
            zeroHash(node.transition_tail_commitment))
            return DynamicVmSchemaStatusV2::InvalidHashBinding;
        if (node.reserved != 0 || node.bytecode_size == 0 ||
            node.shard_size == 0)
            return DynamicVmSchemaStatusV2::InvalidRange;
        if (index != 0 &&
            (graph.nodes[index - 1].node_id >= node.node_id ||
             graph.nodes[index - 1].shard_id >= node.shard_id))
            return DynamicVmSchemaStatusV2::InvalidIdOrder;
        if (!boundedSlice(node.bytecode_offset, node.bytecode_size,
                          descriptor.bytecode_size) ||
            !boundedSlice(node.shard_offset, node.shard_size,
                          descriptor.handler_shards_size))
            return DynamicVmSchemaStatusV2::InvalidRange;
        // Exact coverage makes instruction and shard partitioning unambiguous.
        if (node.bytecode_offset != bytecode_end || node.shard_offset != shard_end)
            return DynamicVmSchemaStatusV2::InvalidInstructionBoundary;
        bytecode_end = node.bytecode_offset + node.bytecode_size;
        shard_end = node.shard_offset + node.shard_size;
        if (node.register_index >= abi.i32_register_count)
            return DynamicVmSchemaStatusV2::InvalidRegisterCounts;
    }
    if (bytecode_end != descriptor.bytecode_size ||
        shard_end != descriptor.handler_shards_size)
        return DynamicVmSchemaStatusV2::InvalidRange;
    if (graph.nodes.size() == 1) {
        const auto &node = graph.nodes.front();
        if (node.semantic != ContinuationNodeSemanticV2::ReturnI32)
            return DynamicVmSchemaStatusV2::InvalidSemantic;
        if (node.status != ContinuationNodeStatusV2::Return)
            return DynamicVmSchemaStatusV2::InvalidStatus;
        if (node.next_node_id != 0)
            return DynamicVmSchemaStatusV2::InvalidTopology;
    } else {
        const auto &load = graph.nodes[0];
        const auto &ret = graph.nodes[1];
        if (load.semantic != ContinuationNodeSemanticV2::LoadI32 ||
            ret.semantic != ContinuationNodeSemanticV2::ReturnI32)
            return DynamicVmSchemaStatusV2::InvalidSemantic;
        if (load.status != ContinuationNodeStatusV2::Continue ||
            ret.status != ContinuationNodeStatusV2::Return)
            return DynamicVmSchemaStatusV2::InvalidStatus;
        if (load.next_node_id != ret.node_id || ret.next_node_id != 0)
            return DynamicVmSchemaStatusV2::InvalidTopology;
        if (load.register_index != ret.register_index)
            return DynamicVmSchemaStatusV2::InvalidRegisterCounts;
    }
    for (const auto &node : graph.nodes) {
        const auto tail = hashDynamicVmTransitionTailV2(node);
        if (!tail || *tail != node.transition_tail_commitment)
            return DynamicVmSchemaStatusV2::InvalidHashBinding;
    }
    const auto graph_hash = hashDynamicVmContinuationGraphV2(graph);
    if (!graph_hash || *graph_hash != descriptor.graph_commitment)
        return DynamicVmSchemaStatusV2::InvalidHashBinding;
    return DynamicVmSchemaStatusV2::Valid;
}

std::array<uint8_t, 32> derive(std::span<const uint8_t, 32> secret,
                               std::span<const uint8_t> salt,
                               std::string_view label) {
    std::array<uint8_t, 32> result{};
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    size_t size = result.size();
    const auto *labelBytes = reinterpret_cast<const uint8_t *>(label.data());
    const bool ok = context && EVP_PKEY_derive_init(context) == 1 &&
                    EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) == 1 &&
                    EVP_PKEY_CTX_set1_hkdf_salt(context, salt.data(), static_cast<int>(salt.size())) == 1 &&
                    EVP_PKEY_CTX_set1_hkdf_key(context, secret.data(), static_cast<int>(secret.size())) == 1 &&
                    EVP_PKEY_CTX_add1_hkdf_info(context, labelBytes, static_cast<int>(label.size())) == 1 &&
                    EVP_PKEY_derive(context, result.data(), &size) == 1 && size == result.size();
    EVP_PKEY_CTX_free(context);
    if (!ok) result.fill(0);
    return result;
}

} // namespace

DynamicVmSchemaStatusV2 validateDynamicVmExecutionAbiV2(
    const DynamicVmExecutionAbiV2 &abi) {
    if (abi.format_version != kDynamicVmFormatVersion ||
        abi.schema_version != kDynamicVmExecutionSchemaVersionV2)
        return DynamicVmSchemaStatusV2::UnsupportedVersion;
    if (abi.profile != DynamicVmExecutionProfileV2::LoadI32ReturnI32)
        return DynamicVmSchemaStatusV2::UnsupportedProfile;
    if (abi.abi_id == 0 || abi.flags != 0 || abi.reserved8 != 0 ||
        abi.reserved != 0 ||
        std::any_of(abi.reserved_decode_salt.begin(),
                    abi.reserved_decode_salt.end(),
                    [](uint8_t value) { return value != 0; }))
        return DynamicVmSchemaStatusV2::InvalidIdentity;
    if (abi.i32_register_count == 0 ||
        abi.i32_register_count > kDynamicVmMaxI32RegistersV2 ||
        abi.i64_register_count != 0 || abi.pointer_register_count != 0 ||
        abi.f64_register_count != 0)
        return DynamicVmSchemaStatusV2::InvalidRegisterCounts;
    if (abi.relocation_count != 0)
        return DynamicVmSchemaStatusV2::InvalidRelocation;
    if (abi.loadi32_instruction_size != kDynamicVmLoadI32InstructionSizeV2 ||
        abi.return_i32_instruction_size !=
            kDynamicVmReturnI32InstructionSizeV2 ||
        abi.loadi32_opcode == abi.return_i32_opcode ||
        abi.loadi32_destination_offset != 1 ||
        abi.loadi32_immediate_offset != 2 ||
        abi.return_i32_source_offset != 1)
        return DynamicVmSchemaStatusV2::InvalidInstructionBoundary;
    return DynamicVmSchemaStatusV2::Valid;
}

std::vector<uint8_t> encodeDynamicVmExecutionAbiV2(
    const DynamicVmExecutionAbiV2 &abi) {
    if (validateDynamicVmExecutionAbiV2(abi) !=
        DynamicVmSchemaStatusV2::Valid)
        return {};
    std::vector<uint8_t> out;
    out.reserve(kDynamicVmExecutionAbiV2EncodedSize);
    put16(out, abi.format_version);
    put16(out, abi.schema_version);
    put16(out, static_cast<uint16_t>(abi.profile));
    put16(out, abi.flags);
    put32(out, abi.abi_id);
    put16(out, abi.i32_register_count);
    put16(out, abi.i64_register_count);
    put16(out, abi.pointer_register_count);
    put16(out, abi.f64_register_count);
    put16(out, abi.relocation_count);
    put16(out, abi.loadi32_instruction_size);
    put16(out, abi.return_i32_instruction_size);
    out.push_back(abi.loadi32_opcode);
    out.push_back(abi.return_i32_opcode);
    out.push_back(abi.loadi32_destination_offset);
    out.push_back(abi.loadi32_immediate_offset);
    out.push_back(abi.return_i32_source_offset);
    out.push_back(abi.reserved8);
    out.push_back(abi.decode_salt);
    out.insert(out.end(), abi.reserved_decode_salt.begin(),
               abi.reserved_decode_salt.end());
    put16(out, abi.reserved);
    return out;
}

std::optional<DynamicVmExecutionAbiV2> decodeDynamicVmExecutionAbiV2(
    std::span<const uint8_t> encoded) {
    if (encoded.size() != kDynamicVmExecutionAbiV2EncodedSize)
        return std::nullopt;
    DynamicVmExecutionAbiV2 abi;
    abi.format_version = get16(encoded, 0);
    abi.schema_version = get16(encoded, 2);
    abi.profile = static_cast<DynamicVmExecutionProfileV2>(get16(encoded, 4));
    abi.flags = get16(encoded, 6);
    abi.abi_id = get32(encoded, 8);
    abi.i32_register_count = get16(encoded, 12);
    abi.i64_register_count = get16(encoded, 14);
    abi.pointer_register_count = get16(encoded, 16);
    abi.f64_register_count = get16(encoded, 18);
    abi.relocation_count = get16(encoded, 20);
    abi.loadi32_instruction_size = get16(encoded, 22);
    abi.return_i32_instruction_size = get16(encoded, 24);
    abi.loadi32_opcode = encoded[26];
    abi.return_i32_opcode = encoded[27];
    abi.loadi32_destination_offset = encoded[28];
    abi.loadi32_immediate_offset = encoded[29];
    abi.return_i32_source_offset = encoded[30];
    abi.reserved8 = encoded[31];
    abi.decode_salt = encoded[32];
    std::copy_n(encoded.begin() + 33, abi.reserved_decode_salt.size(),
                abi.reserved_decode_salt.begin());
    abi.reserved = get16(encoded, 64);
    if (encodeDynamicVmExecutionAbiV2(abi) !=
        std::vector<uint8_t>(encoded.begin(), encoded.end()))
        return std::nullopt;
    return abi;
}

std::optional<DynamicHash> hashDynamicVmExecutionAbiV2(
    const DynamicVmExecutionAbiV2 &abi) {
    const auto encoded = encodeDynamicVmExecutionAbiV2(abi);
    if (encoded.empty()) return std::nullopt;
    const auto hash = domainHash(kDynamicVmExecutionAbiHashDomainV2, encoded);
    if (zeroHash(hash)) return std::nullopt;
    return hash;
}

DynamicHash hashDynamicVmBytecodeBlockV2(std::span<const uint8_t> bytes) {
    return domainHash(kDynamicVmBytecodeBlockHashDomainV2, bytes);
}

DynamicHash hashDynamicVmHandlerShardV2(std::span<const uint8_t> bytes) {
    return domainHash(kDynamicVmHandlerShardHashDomainV2, bytes);
}

std::vector<uint8_t> encodeDynamicVmExecutionDescriptorV2(
    const DynamicVmExecutionDescriptorV2 &descriptor) {
    if (!validDescriptorV2(descriptor)) return {};
    std::vector<uint8_t> out;
    out.reserve(kDynamicVmExecutionDescriptorV2EncodedSize);
    put16(out, descriptor.format_version);
    put16(out, descriptor.schema_version);
    put32(out, descriptor.abi_id);
    putHash(out, descriptor.abi_hash);
    putHash(out, descriptor.bytecode_hash);
    put32(out, descriptor.bytecode_size);
    put32(out, descriptor.handler_shards_size);
    put32(out, descriptor.entry_node_id);
    put16(out, descriptor.node_count);
    put16(out, descriptor.relocation_count);
    putHash(out, descriptor.graph_commitment);
    return out;
}

std::optional<DynamicVmExecutionDescriptorV2>
decodeDynamicVmExecutionDescriptorV2(std::span<const uint8_t> encoded) {
    if (encoded.size() != kDynamicVmExecutionDescriptorV2EncodedSize)
        return std::nullopt;
    DynamicVmExecutionDescriptorV2 descriptor;
    descriptor.format_version = get16(encoded, 0);
    descriptor.schema_version = get16(encoded, 2);
    descriptor.abi_id = get32(encoded, 4);
    std::copy_n(encoded.begin() + 8, descriptor.abi_hash.size(),
                descriptor.abi_hash.begin());
    std::copy_n(encoded.begin() + 40, descriptor.bytecode_hash.size(),
                descriptor.bytecode_hash.begin());
    descriptor.bytecode_size = get32(encoded, 72);
    descriptor.handler_shards_size = get32(encoded, 76);
    descriptor.entry_node_id = get32(encoded, 80);
    descriptor.node_count = get16(encoded, 84);
    descriptor.relocation_count = get16(encoded, 86);
    std::copy_n(encoded.begin() + 88, descriptor.graph_commitment.size(),
                descriptor.graph_commitment.begin());
    if (encodeDynamicVmExecutionDescriptorV2(descriptor) !=
        std::vector<uint8_t>(encoded.begin(), encoded.end()))
        return std::nullopt;
    return descriptor;
}

std::vector<uint8_t> encodeContinuationNodeV2(const ContinuationNodeV2 &node) {
    if (!validNodeV2(node)) return {};
    std::vector<uint8_t> out;
    out.reserve(kDynamicVmContinuationNodeV2EncodedSize);
    put32(out, node.node_id);
    put32(out, node.shard_id);
    put32(out, node.bytecode_offset);
    put32(out, node.bytecode_size);
    put32(out, node.shard_offset);
    put32(out, node.shard_size);
    put32(out, node.next_node_id);
    put16(out, node.register_index);
    out.push_back(static_cast<uint8_t>(node.semantic));
    out.push_back(static_cast<uint8_t>(node.status));
    put32(out, node.variant_id);
    putHash(out, node.bytecode_block_commitment);
    putHash(out, node.handler_shard_commitment);
    putHash(out, node.transition_tail_commitment);
    put32(out, node.relocation_offset);
    put16(out, node.relocation_count);
    put16(out, node.reserved);
    return out;
}

std::optional<ContinuationNodeV2> decodeContinuationNodeV2(
    std::span<const uint8_t> encoded) {
    if (encoded.size() != kDynamicVmContinuationNodeV2EncodedSize)
        return std::nullopt;
    ContinuationNodeV2 node;
    node.node_id = get32(encoded, 0);
    node.shard_id = get32(encoded, 4);
    node.bytecode_offset = get32(encoded, 8);
    node.bytecode_size = get32(encoded, 12);
    node.shard_offset = get32(encoded, 16);
    node.shard_size = get32(encoded, 20);
    node.next_node_id = get32(encoded, 24);
    node.register_index = get16(encoded, 28);
    node.semantic = static_cast<ContinuationNodeSemanticV2>(encoded[30]);
    node.status = static_cast<ContinuationNodeStatusV2>(encoded[31]);
    node.variant_id = get32(encoded, 32);
    std::copy_n(encoded.begin() + 36, node.bytecode_block_commitment.size(),
                node.bytecode_block_commitment.begin());
    std::copy_n(encoded.begin() + 68, node.handler_shard_commitment.size(),
                node.handler_shard_commitment.begin());
    std::copy_n(encoded.begin() + 100, node.transition_tail_commitment.size(),
                node.transition_tail_commitment.begin());
    node.relocation_offset = get32(encoded, 132);
    node.relocation_count = get16(encoded, 136);
    node.reserved = get16(encoded, 138);
    if (encodeContinuationNodeV2(node) !=
        std::vector<uint8_t>(encoded.begin(), encoded.end()))
        return std::nullopt;
    return node;
}

std::optional<DynamicHash> hashDynamicVmTransitionTailV2(
    const ContinuationNodeV2 &node) {
    if (node.node_id == 0 || node.shard_id == 0 || node.variant_id == 0 ||
        zeroHash(node.bytecode_block_commitment) ||
        zeroHash(node.handler_shard_commitment))
        return std::nullopt;
    std::vector<uint8_t> preimage;
    preimage.reserve(72);
    put32(preimage, node.node_id);
    put32(preimage, node.shard_id);
    put32(preimage, node.bytecode_offset);
    put32(preimage, node.bytecode_size);
    put32(preimage, node.shard_offset);
    put32(preimage, node.shard_size);
    put32(preimage, node.next_node_id);
    put32(preimage, node.variant_id);
    put16(preimage, node.register_index);
    preimage.push_back(static_cast<uint8_t>(node.semantic));
    preimage.push_back(static_cast<uint8_t>(node.status));
    putHash(preimage, node.bytecode_block_commitment);
    putHash(preimage, node.handler_shard_commitment);
    const auto hash = domainHash(kDynamicVmTransitionTailHashDomainV2, preimage);
    if (zeroHash(hash)) return std::nullopt;
    return hash;
}

std::optional<DynamicHash> hashDynamicVmContinuationGraphV2(
    const ContinuationGraphV2 &graph) {
    const auto &descriptor = graph.descriptor;
    if (descriptor.format_version != kDynamicVmFormatVersion ||
        descriptor.schema_version != kDynamicVmExecutionSchemaVersionV2 ||
        descriptor.abi_id == 0 || zeroHash(descriptor.abi_hash) ||
        zeroHash(descriptor.bytecode_hash) || descriptor.node_count == 0 ||
        descriptor.node_count > kDynamicVmMaxContinuationNodesV2 ||
        graph.nodes.size() != descriptor.node_count)
        return std::nullopt;
    std::vector<uint8_t> preimage;
    put16(preimage, descriptor.format_version);
    put16(preimage, descriptor.schema_version);
    put32(preimage, descriptor.abi_id);
    putHash(preimage, descriptor.abi_hash);
    putHash(preimage, descriptor.bytecode_hash);
    put32(preimage, descriptor.bytecode_size);
    put32(preimage, descriptor.handler_shards_size);
    put32(preimage, descriptor.entry_node_id);
    put16(preimage, descriptor.node_count);
    put16(preimage, descriptor.relocation_count);
    for (const auto &node : graph.nodes) {
        const auto encoded = encodeContinuationNodeV2(node);
        if (encoded.empty()) return std::nullopt;
        putBytes(preimage, encoded);
    }
    const auto hash = domainHash(kDynamicVmContinuationGraphHashDomainV2,
                                 preimage);
    if (zeroHash(hash)) return std::nullopt;
    return hash;
}

DynamicVmSchemaStatusV2 validateContinuationGraphV2(
    const DynamicVmExecutionAbiV2 &abi, const ContinuationGraphV2 &graph) {
    return validateContinuationGraphStructureV2(abi, graph);
}

DynamicVmSchemaStatusV2 validateContinuationGraphV2(
    const DynamicVmExecutionAbiV2 &abi, const ContinuationGraphV2 &graph,
    std::span<const uint8_t> bytecode,
    std::span<const uint8_t> handler_shards) {
    const auto status = validateContinuationGraphStructureV2(abi, graph);
    if (status != DynamicVmSchemaStatusV2::Valid) return status;
    if (bytecode.size() != graph.descriptor.bytecode_size ||
        handler_shards.size() != graph.descriptor.handler_shards_size)
        return DynamicVmSchemaStatusV2::InvalidRange;
    DynamicHash hash{};
    unsigned int length = 0;
    if (EVP_Digest(bytecode.data(), bytecode.size(), hash.data(), &length,
                   EVP_sha256(), nullptr) != 1 ||
        length != hash.size() || hash != graph.descriptor.bytecode_hash)
        return DynamicVmSchemaStatusV2::InvalidHashBinding;
    for (const auto &node : graph.nodes) {
        if (node.semantic == ContinuationNodeSemanticV2::LoadI32 &&
            node.bytecode_size != abi.loadi32_instruction_size)
            return DynamicVmSchemaStatusV2::InvalidInstructionBoundary;
        if (node.semantic == ContinuationNodeSemanticV2::ReturnI32 &&
            node.bytecode_size != abi.return_i32_instruction_size)
            return DynamicVmSchemaStatusV2::InvalidInstructionBoundary;
        const auto block = bytecode.subspan(node.bytecode_offset,
                                            node.bytecode_size);
        const auto shard = handler_shards.subspan(node.shard_offset,
                                                  node.shard_size);
        if (hashDynamicVmBytecodeBlockV2(block) !=
                node.bytecode_block_commitment ||
            hashDynamicVmHandlerShardV2(shard) !=
                node.handler_shard_commitment)
            return DynamicVmSchemaStatusV2::InvalidHashBinding;
        const uint8_t expected_opcode =
            node.semantic == ContinuationNodeSemanticV2::LoadI32
                ? abi.loadi32_opcode
                : abi.return_i32_opcode;
        const uint8_t register_offset =
            node.semantic == ContinuationNodeSemanticV2::LoadI32
                ? abi.loadi32_destination_offset
                : abi.return_i32_source_offset;
        if (block[0] != expected_opcode)
            return DynamicVmSchemaStatusV2::InvalidSemantic;
        if (static_cast<uint8_t>(block[register_offset] ^ abi.decode_salt) !=
            node.register_index)
            return DynamicVmSchemaStatusV2::InvalidRegisterCounts;
    }
    return DynamicVmSchemaStatusV2::Valid;
}

std::vector<uint8_t> encodeContinuationGraphV2(
    const ContinuationGraphV2 &graph) {
    // Encoding validates graph-local invariants. ABI identity/hash validation is
    // intentionally performed by validateContinuationGraphV2 at the trust edge.
    if (!canonicalGraphShapeV2(graph)) return {};
    std::vector<uint8_t> out =
        encodeDynamicVmExecutionDescriptorV2(graph.descriptor);
    if (out.empty()) return {};
    out.reserve(kDynamicVmExecutionDescriptorV2EncodedSize +
                graph.nodes.size() * kDynamicVmContinuationNodeV2EncodedSize);
    for (const auto &node : graph.nodes) {
        auto encoded = encodeContinuationNodeV2(node);
        if (encoded.empty()) return {};
        out.insert(out.end(), encoded.begin(), encoded.end());
    }
    return out;
}

std::optional<ContinuationGraphV2> decodeContinuationGraphV2(
    std::span<const uint8_t> encoded) {
    if (encoded.size() < kDynamicVmExecutionDescriptorV2EncodedSize)
        return std::nullopt;
    auto descriptor = decodeDynamicVmExecutionDescriptorV2(
        encoded.first(kDynamicVmExecutionDescriptorV2EncodedSize));
    if (!descriptor) return std::nullopt;
    const size_t expected = kDynamicVmExecutionDescriptorV2EncodedSize +
        static_cast<size_t>(descriptor->node_count) *
            kDynamicVmContinuationNodeV2EncodedSize;
    if (descriptor->node_count == 0 ||
        descriptor->node_count > kDynamicVmMaxContinuationNodesV2 ||
        encoded.size() != expected)
        return std::nullopt;
    ContinuationGraphV2 graph;
    graph.descriptor = *descriptor;
    for (size_t index = 0; index < descriptor->node_count; ++index) {
        const size_t offset = kDynamicVmExecutionDescriptorV2EncodedSize +
            index * kDynamicVmContinuationNodeV2EncodedSize;
        auto node = decodeContinuationNodeV2(
            encoded.subspan(offset, kDynamicVmContinuationNodeV2EncodedSize));
        if (!node) return std::nullopt;
        graph.nodes.push_back(*node);
    }
    if (encodeContinuationGraphV2(graph) !=
        std::vector<uint8_t>(encoded.begin(), encoded.end()))
        return std::nullopt;
    return graph;
}

std::vector<uint8_t> encodeEncryptedVmArtifact(const EncryptedVmArtifact &artifact) {
    if (artifact.format_version != kDynamicVmFormatVersion ||
        artifact.encrypted_bytecode_blocks.size() > kDynamicVmMaxWindowMaterial * 64 ||
        artifact.encrypted_handler_shards.size() > kDynamicVmMaxWindowMaterial * 64 ||
        artifact.continuation_descriptors.size() > kDynamicVmMaxDescriptor ||
        !artifact.relocation_descriptors.empty())
        return {};
    std::vector<uint8_t> out;
    put16(out, artifact.format_version);
    putHash(out, artifact.build_id);
    putHash(out, artifact.region_id);
    putHash(out, artifact.artifact_hash);
    putSized(out, artifact.encrypted_bytecode_blocks);
    putSized(out, artifact.encrypted_handler_shards);
    putSized(out, artifact.continuation_descriptors);
    putSized(out, artifact.relocation_descriptors);
    return out;
}

std::optional<EncryptedVmArtifact> decodeEncryptedVmArtifact(std::span<const uint8_t> encoded) {
    size_t offset = 0;
    auto take = [&](size_t size) -> std::optional<std::span<const uint8_t>> {
        if (offset > encoded.size() || size > encoded.size() - offset) return std::nullopt;
        auto result = encoded.subspan(offset, size);
        offset += size;
        return result;
    };
    auto version_bytes = take(2);
    if (!version_bytes) return std::nullopt;
    const uint16_t version = static_cast<uint16_t>((*version_bytes)[0] << 8 | (*version_bytes)[1]);
    if (version != kDynamicVmFormatVersion) return std::nullopt;
    EncryptedVmArtifact artifact;
    artifact.format_version = version;
    for (DynamicHash *hash : {&artifact.build_id, &artifact.region_id, &artifact.artifact_hash}) {
        auto bytes = take(hash->size());
        if (!bytes) return std::nullopt;
        std::copy(bytes->begin(), bytes->end(), hash->begin());
    }
    auto read_sized = [&](std::vector<uint8_t> &destination, size_t maximum) -> bool {
        auto length_bytes = take(4);
        if (!length_bytes) return false;
        const uint32_t length = static_cast<uint32_t>((*length_bytes)[0]) << 24 |
            static_cast<uint32_t>((*length_bytes)[1]) << 16 |
            static_cast<uint32_t>((*length_bytes)[2]) << 8 |
            static_cast<uint32_t>((*length_bytes)[3]);
        if (length > maximum) return false;
        auto bytes = take(length);
        if (!bytes) return false;
        destination.assign(bytes->begin(), bytes->end());
        return true;
    };
    if (!read_sized(artifact.encrypted_bytecode_blocks, kDynamicVmMaxWindowMaterial * 64) ||
        !read_sized(artifact.encrypted_handler_shards, kDynamicVmMaxWindowMaterial * 64) ||
        !read_sized(artifact.continuation_descriptors, kDynamicVmMaxDescriptor) ||
        !read_sized(artifact.relocation_descriptors, 0) ||
        offset != encoded.size())
        return std::nullopt;
    return artifact;
}

std::vector<uint8_t> encodeWindowAcquireRequest(const WindowAcquireRequest &request) {
    if (request.format_version != kDynamicVmFormatVersion ||
        request.request_id == std::array<uint8_t, 16>{} ||
        request.build_id == DynamicHash{} || request.region_id == DynamicHash{} ||
        request.generation == 0 || request.window_id == 0 ||
        request.previous_state_hash == DynamicHash{})
        return {};

    std::vector<uint8_t> out;
    out.reserve(kWindowAcquireRequestEncodedSize);
    put16(out, request.format_version);
    putBytes(out, request.request_id);
    putHash(out, request.build_id);
    putHash(out, request.region_id);
    put64(out, request.generation);
    put64(out, request.window_id);
    putHash(out, request.previous_state_hash);
    return out;
}

std::optional<WindowAcquireRequest> decodeWindowAcquireRequest(
    std::span<const uint8_t> encoded) {
    if (encoded.size() != kWindowAcquireRequestEncodedSize) return std::nullopt;

    WindowAcquireRequest request;
    size_t offset = 0;
    auto take = [&](size_t size) {
        const auto result = encoded.subspan(offset, size);
        offset += size;
        return result;
    };
    const auto version = take(2);
    request.format_version = static_cast<uint16_t>(version[0]) << 8 | version[1];
    const auto request_id = take(request.request_id.size());
    std::copy(request_id.begin(), request_id.end(), request.request_id.begin());
    for (DynamicHash *hash : {&request.build_id, &request.region_id}) {
        const auto bytes = take(hash->size());
        std::copy(bytes.begin(), bytes.end(), hash->begin());
    }
    auto read64 = [&](uint64_t &value) {
        value = 0;
        for (uint8_t byte : take(sizeof(value))) value = (value << 8) | byte;
    };
    read64(request.generation);
    read64(request.window_id);
    const auto previous_state = take(request.previous_state_hash.size());
    std::copy(previous_state.begin(), previous_state.end(),
              request.previous_state_hash.begin());

    const auto canonical = encodeWindowAcquireRequest(request);
    if (canonical.size() != encoded.size() ||
        !std::equal(canonical.begin(), canonical.end(), encoded.begin()))
        return std::nullopt;
    return request;
}

std::vector<uint8_t> encodeHandlerShardDescriptor(const HandlerShardDescriptor &descriptor) {
    if (!descriptor.shard_id || !descriptor.code_size ||
        descriptor.relocation_count != 0)
        return {};
    std::vector<uint8_t> out;
    put32(out, descriptor.shard_id);
    put32(out, descriptor.code_size);
    put32(out, descriptor.relocation_count);
    putHash(out, descriptor.commitment);
    return out;
}

std::optional<HandlerShardDescriptor> decodeHandlerShardDescriptor(
    std::span<const uint8_t> encoded) {
    if (encoded.size() != 12 + kDynamicVmHashSize) return std::nullopt;
    HandlerShardDescriptor descriptor;
    descriptor.shard_id = static_cast<uint32_t>(encoded[0]) << 24 |
        static_cast<uint32_t>(encoded[1]) << 16 |
        static_cast<uint32_t>(encoded[2]) << 8 | encoded[3];
    descriptor.code_size = static_cast<uint32_t>(encoded[4]) << 24 |
        static_cast<uint32_t>(encoded[5]) << 16 |
        static_cast<uint32_t>(encoded[6]) << 8 | encoded[7];
    descriptor.relocation_count = static_cast<uint32_t>(encoded[8]) << 24 |
        static_cast<uint32_t>(encoded[9]) << 16 |
        static_cast<uint32_t>(encoded[10]) << 8 | encoded[11];
    std::copy(encoded.begin() + 12, encoded.end(), descriptor.commitment.begin());
    if (encodeHandlerShardDescriptor(descriptor) != std::vector<uint8_t>(encoded.begin(), encoded.end()))
        return std::nullopt;
    return descriptor;
}

std::vector<uint8_t> encodeHandlerShardPayload(const HandlerShardDescriptor &descriptor,
                                               std::span<const uint8_t> code) {
    if (descriptor.code_size != code.size() || code.empty()) return {};
    auto Descriptor = encodeHandlerShardDescriptor(descriptor);
    if (Descriptor.empty()) return {};
    Descriptor.insert(Descriptor.end(), code.begin(), code.end());
    return Descriptor;
}

std::optional<HandlerShardPayload> decodeHandlerShardPayload(
    std::span<const uint8_t> encoded) {
    if (encoded.size() <= 12 + kDynamicVmHashSize) return std::nullopt;
    auto Descriptor = decodeHandlerShardDescriptor(
        encoded.first(12 + kDynamicVmHashSize));
    if (!Descriptor || Descriptor->code_size != encoded.size() -
        (12 + kDynamicVmHashSize))
        return std::nullopt;
    HandlerShardPayload Result{*Descriptor,
        std::vector<uint8_t>(encoded.begin() + 12 + kDynamicVmHashSize, encoded.end())};
    return Result;
}

std::vector<uint8_t> encodeWindowGrant(const WindowGrant &grant) {
    if (grant.format_version != kDynamicVmFormatVersion ||
        grant.generation == 0 || grant.window_id == 0 ||
        std::all_of(grant.build_id.begin(), grant.build_id.end(),
                    [](uint8_t value) { return value == 0; }) ||
        std::all_of(grant.region_id.begin(), grant.region_id.end(),
                    [](uint8_t value) { return value == 0; }) ||
        std::all_of(grant.session_id.begin(), grant.session_id.end(),
                    [](uint8_t value) { return value == 0; }) ||
        std::all_of(grant.previous_state_hash.begin(), grant.previous_state_hash.end(),
                    [](uint8_t value) { return value == 0; }) ||
        std::all_of(grant.next_state_hash.begin(), grant.next_state_hash.end(),
                    [](uint8_t value) { return value == 0; }) ||
        grant.encrypted_window_material.size() != kEncryptedWindowMaterialSize ||
        grant.issued_at_ms >= grant.expires_at_ms)
        return {};
    std::vector<uint8_t> out;
    put16(out, grant.format_version);
    putHash(out, grant.build_id);
    putHash(out, grant.region_id);
    putBytes(out, grant.session_id);
    put64(out, grant.generation);
    put64(out, grant.window_id);
    putHash(out, grant.previous_state_hash);
    putHash(out, grant.next_state_hash);
    put64(out, grant.issued_at_ms);
    put64(out, grant.expires_at_ms);
    put32(out, grant.key_version);
    putSized(out, grant.encrypted_window_material);
    return out;
}

std::optional<WindowGrant> decodeWindowGrant(std::span<const uint8_t> encoded) {
    size_t offset = 0;
    auto take = [&](size_t size) -> std::optional<std::span<const uint8_t>> {
        if (size > encoded.size() - offset) return std::nullopt;
        auto result = encoded.subspan(offset, size);
        offset += size;
        return result;
    };
    auto read16 = [&](uint16_t &value) -> bool {
        auto bytes = take(2);
        if (!bytes) return false;
        value = static_cast<uint16_t>((*bytes)[0] << 8 | (*bytes)[1]);
        return true;
    };
    auto read32 = [&](uint32_t &value) -> bool {
        auto bytes = take(4);
        if (!bytes) return false;
        value = static_cast<uint32_t>((*bytes)[0]) << 24 |
            static_cast<uint32_t>((*bytes)[1]) << 16 |
            static_cast<uint32_t>((*bytes)[2]) << 8 | (*bytes)[3];
        return true;
    };
    auto read64 = [&](uint64_t &value) -> bool {
        auto bytes = take(8);
        if (!bytes) return false;
        value = 0;
        for (uint8_t byte : *bytes) value = (value << 8) | byte;
        return true;
    };
    WindowGrant grant;
    if (!read16(grant.format_version) || grant.format_version != kDynamicVmFormatVersion)
        return std::nullopt;
    for (DynamicHash *hash : {&grant.build_id, &grant.region_id}) {
        auto bytes = take(hash->size());
        if (!bytes) return std::nullopt;
        std::copy(bytes->begin(), bytes->end(), hash->begin());
    }
    auto session = take(grant.session_id.size());
    if (!session || !read64(grant.generation) || !read64(grant.window_id))
        return std::nullopt;
    std::copy(session->begin(), session->end(), grant.session_id.begin());
    for (DynamicHash *hash : {&grant.previous_state_hash, &grant.next_state_hash}) {
        auto bytes = take(hash->size());
        if (!bytes) return std::nullopt;
        std::copy(bytes->begin(), bytes->end(), hash->begin());
    }
    if (!read64(grant.issued_at_ms) || !read64(grant.expires_at_ms) ||
        !read32(grant.key_version))
        return std::nullopt;
    uint32_t material_size = 0;
    if (!read32(material_size) || material_size != kEncryptedWindowMaterialSize)
        return std::nullopt;
    auto material = take(material_size);
    if (!material || offset != encoded.size()) return std::nullopt;
    grant.encrypted_window_material.assign(material->begin(), material->end());
    if (grant.generation == 0 || grant.window_id == 0 ||
        std::all_of(grant.build_id.begin(), grant.build_id.end(),
                    [](uint8_t value) { return value == 0; }) ||
        std::all_of(grant.region_id.begin(), grant.region_id.end(),
                    [](uint8_t value) { return value == 0; }) ||
        std::all_of(grant.session_id.begin(), grant.session_id.end(),
                    [](uint8_t value) { return value == 0; }) ||
        std::all_of(grant.previous_state_hash.begin(), grant.previous_state_hash.end(),
                    [](uint8_t value) { return value == 0; }) ||
        std::all_of(grant.next_state_hash.begin(), grant.next_state_hash.end(),
                    [](uint8_t value) { return value == 0; }) ||
        encodeWindowGrant(grant) != std::vector<uint8_t>(encoded.begin(), encoded.end()))
        return std::nullopt;
    return grant;
}

bool validateWindowBinding(const WindowGrant &grant, const WindowBinding &binding) {
    return grant.format_version == kDynamicVmFormatVersion &&
           same(grant.build_id, binding.build_id) &&
           same(grant.region_id, binding.region_id) &&
           same(grant.session_id, binding.session_id) &&
           grant.generation == binding.generation && grant.window_id == binding.window_id &&
           same(grant.previous_state_hash, binding.previous_state_hash) &&
           grant.issued_at_ms <= binding.now_ms && binding.now_ms < grant.expires_at_ms &&
           !std::all_of(grant.next_state_hash.begin(), grant.next_state_hash.end(),
                        [](uint8_t value) { return value == 0; });
}

bool advanceContinuation(const DynamicHash &current_state,
                         const WindowGrant &grant,
                         DynamicHash &next_state) {
    if (!same(current_state, grant.previous_state_hash)) return false;
    next_state = grant.next_state_hash;
    return !std::all_of(next_state.begin(), next_state.end(),
                        [](uint8_t value) { return value == 0; });
}

WindowMaterial deriveWindowMaterial(std::span<const uint8_t, 32> session_secret,
                                    const WindowGrant &grant) {
    const auto encoded = encodeWindowGrant(grant);
    const std::array<std::string_view, 6> labels = {
        "xovm/dynamic/window", "xovm/dynamic/perm", "xovm/dynamic/decode",
        "xovm/dynamic/chaff", "xovm/dynamic/integrity", "xovm/dynamic/jit"};
    WindowMaterial result;
    std::array<std::array<uint8_t, 32> *, 6> output = {
        &result.window, &result.permutation, &result.decode,
        &result.chaff, &result.integrity, &result.jit};
    for (size_t index = 0; index < labels.size(); ++index) {
        std::array<uint8_t, 32> salt{};
        const auto *bytes = encoded.data();
        const size_t size = encoded.size();
        EVP_Digest(bytes, size, salt.data(), nullptr, EVP_sha256(), nullptr);
        *output[index] = derive(session_secret, salt, labels[index]);
    }
    return result;
}

void secureClear(std::vector<uint8_t> &bytes) {
    if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size());
    bytes.clear();
    bytes.shrink_to_fit();
}

void secureClear(WindowMaterial &material) {
    OPENSSL_cleanse(&material, sizeof(material));
}

} // namespace xovm::material
