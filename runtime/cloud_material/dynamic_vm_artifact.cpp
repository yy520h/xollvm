#include "dynamic_vm_artifact.h"
#include "dynamic_vm_shard.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <limits>
#include <string_view>

namespace xovm::material {
namespace {

constexpr size_t kAeadNonceSize = 12;
constexpr size_t kAeadTagSize = 16;
constexpr size_t kAeadOverhead = kAeadNonceSize + kAeadTagSize;
constexpr size_t kRecordContainerHeaderSize = 12;
constexpr size_t kRecordMetadataSize = 128;
constexpr size_t kLegacyHandlerDescriptorSize = 44;
constexpr std::array<uint8_t, 8> kRecordContainerMagic = {
    'X', 'O', 'V', 'M', 'R', 'E', 'C', '2'};

enum class RecordRole : uint8_t {
    BytecodeBlock = 1,
    HandlerShard = 2,
};

struct ParsedDescriptors {
    DynamicVmExecutionAbiV2 abi;
    ContinuationGraphV2 graph;
};

struct EncryptedRecordView {
    std::span<const uint8_t> encoded;
};

class VectorScrubber {
public:
    explicit VectorScrubber(std::vector<uint8_t> &bytes) : bytes_(&bytes) {}
    VectorScrubber(const VectorScrubber &) = delete;
    VectorScrubber &operator=(const VectorScrubber &) = delete;
    ~VectorScrubber() {
        if (bytes_) secureClear(*bytes_);
    }
    void release() { bytes_ = nullptr; }

private:
    std::vector<uint8_t> *bytes_;
};

void append16(std::vector<uint8_t> &bytes, uint16_t value) {
    bytes.push_back(static_cast<uint8_t>(value >> 8));
    bytes.push_back(static_cast<uint8_t>(value));
}

void append32(std::vector<uint8_t> &bytes, uint32_t value) {
    bytes.push_back(static_cast<uint8_t>(value >> 24));
    bytes.push_back(static_cast<uint8_t>(value >> 16));
    bytes.push_back(static_cast<uint8_t>(value >> 8));
    bytes.push_back(static_cast<uint8_t>(value));
}

void appendFramed(std::vector<uint8_t> &bytes, std::span<const uint8_t> part) {
    append32(bytes, static_cast<uint32_t>(part.size()));
    bytes.insert(bytes.end(), part.begin(), part.end());
}

uint16_t read16(std::span<const uint8_t> bytes, size_t offset) {
    return static_cast<uint16_t>(static_cast<uint16_t>(bytes[offset]) << 8 |
                                 bytes[offset + 1]);
}

uint32_t read32(std::span<const uint8_t> bytes, size_t offset) {
    return static_cast<uint32_t>(bytes[offset]) << 24 |
           static_cast<uint32_t>(bytes[offset + 1]) << 16 |
           static_cast<uint32_t>(bytes[offset + 2]) << 8 |
           static_cast<uint32_t>(bytes[offset + 3]);
}

std::vector<uint8_t> encrypt(std::span<const uint8_t> plaintext,
                             std::span<const uint8_t, 32> key,
                             std::span<const uint8_t> aad) {
    if (plaintext.empty() || plaintext.size() > std::numeric_limits<int>::max() ||
        aad.size() > std::numeric_limits<int>::max())
        return {};
    std::array<uint8_t, kAeadNonceSize> nonce{};
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) return {};
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (!context ||
        EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(context, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(context);
        return {};
    }
    int count = 0;
    if (EVP_EncryptUpdate(context, nullptr, &count, aad.data(),
                          static_cast<int>(aad.size())) != 1) {
        EVP_CIPHER_CTX_free(context);
        return {};
    }
    std::vector<uint8_t> ciphertext(plaintext.size() + kAeadTagSize);
    VectorScrubber ciphertext_scrubber(ciphertext);
    if (EVP_EncryptUpdate(context, ciphertext.data(), &count, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(context);
        return {};
    }
    int final = 0;
    if (EVP_EncryptFinal_ex(context, ciphertext.data() + count, &final) != 1) {
        EVP_CIPHER_CTX_free(context);
        return {};
    }
    std::array<uint8_t, kAeadTagSize> tag{};
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(tag.size()), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(context);
        return {};
    }
    EVP_CIPHER_CTX_free(context);
    ciphertext.resize(static_cast<size_t>(count + final));
    std::vector<uint8_t> result;
    result.reserve(nonce.size() + ciphertext.size() + tag.size());
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());
    return result;
}

std::vector<uint8_t> decrypt(std::span<const uint8_t> encoded,
                             std::span<const uint8_t, 32> key,
                             std::span<const uint8_t> aad) {
    if (encoded.size() < kAeadOverhead ||
        encoded.size() - kAeadOverhead >
            static_cast<size_t>(std::numeric_limits<int>::max()) ||
        aad.size() > std::numeric_limits<int>::max())
        return {};
    const auto nonce = encoded.first<kAeadNonceSize>();
    const auto tag = encoded.last<kAeadTagSize>();
    const auto ciphertext = encoded.subspan(
        kAeadNonceSize, encoded.size() - kAeadOverhead);
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (!context ||
        EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(context, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(context);
        return {};
    }
    int count = 0;
    const bool aad_ok = EVP_DecryptUpdate(
        context, nullptr, &count, aad.data(), static_cast<int>(aad.size())) == 1;
    std::vector<uint8_t> plaintext(ciphertext.size() + kAeadTagSize);
    VectorScrubber plaintext_scrubber(plaintext);
    const bool data_ok = aad_ok && EVP_DecryptUpdate(
        context, plaintext.data(), &count, ciphertext.data(),
        static_cast<int>(ciphertext.size())) == 1;
    const bool tag_ok = data_ok && EVP_CIPHER_CTX_ctrl(
        context, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
        const_cast<uint8_t *>(tag.data())) == 1;
    int final = 0;
    const bool final_ok = tag_ok &&
        EVP_DecryptFinal_ex(context, plaintext.data() + count, &final) == 1;
    EVP_CIPHER_CTX_free(context);
    if (!final_ok) return {};
    plaintext.resize(static_cast<size_t>(count + final));
    plaintext_scrubber.release();
    return plaintext;
}

DynamicHash hash(std::span<const uint8_t> bytes) {
    DynamicHash result{};
    unsigned int size = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), result.data(), &size,
                   EVP_sha256(), nullptr) != 1 || size != result.size())
        result.fill(0);
    return result;
}

bool nonzero(std::span<const uint8_t> bytes) {
    return std::any_of(bytes.begin(), bytes.end(),
                       [](uint8_t value) { return value != 0; });
}

std::optional<ParsedDescriptors> parseDescriptors(
    std::span<const uint8_t> encoded) {
    if (encoded.size() <= kDynamicVmExecutionAbiV2EncodedSize ||
        encoded.size() > kDynamicVmMaxDescriptor)
        return std::nullopt;
    auto abi = decodeDynamicVmExecutionAbiV2(
        encoded.first(kDynamicVmExecutionAbiV2EncodedSize));
    auto graph = decodeContinuationGraphV2(
        encoded.subspan(kDynamicVmExecutionAbiV2EncodedSize));
    if (!abi || !graph ||
        validateContinuationGraphV2(*abi, *graph) !=
            DynamicVmSchemaStatusV2::Valid)
        return std::nullopt;
    return ParsedDescriptors{*abi, *graph};
}

std::string_view roleName(RecordRole role) {
    return role == RecordRole::BytecodeBlock ? "bytecode-block" :
                                                "handler-shard";
}

uint32_t recordPlaintextSize(RecordRole role,
                             const ContinuationNodeV2 &node) {
    return role == RecordRole::BytecodeBlock ? node.bytecode_size :
                                                node.shard_size;
}

uint32_t recordOffset(RecordRole role, const ContinuationNodeV2 &node) {
    return role == RecordRole::BytecodeBlock ? node.bytecode_offset :
                                                node.shard_offset;
}

const DynamicHash &recordCommitment(RecordRole role,
                                    const ContinuationNodeV2 &node) {
    return role == RecordRole::BytecodeBlock
        ? node.bytecode_block_commitment
        : node.handler_shard_commitment;
}

std::vector<uint8_t> recordAad(
    RecordRole role, const DynamicHash &build_id, const DynamicHash &region_id,
    std::span<const uint8_t> descriptors,
    const DynamicVmExecutionDescriptorV2 &graph_descriptor,
    const ContinuationNodeV2 &node, uint32_t plaintext_size) {
    static constexpr std::string_view domain =
        "XOVM2/artifact-record-aad/v2";
    std::vector<uint8_t> aad(domain.begin(), domain.end());
    aad.push_back(0);
    const auto role_name = roleName(role);
    appendFramed(aad, std::span<const uint8_t>(
        reinterpret_cast<const uint8_t *>(role_name.data()), role_name.size()));
    appendFramed(aad, build_id);
    appendFramed(aad, region_id);
    appendFramed(aad, descriptors);
    appendFramed(aad, graph_descriptor.graph_commitment);
    append32(aad, node.node_id);
    append32(aad, node.shard_id);
    append32(aad, node.bytecode_offset);
    append32(aad, node.bytecode_size);
    append32(aad, node.shard_offset);
    append32(aad, node.shard_size);
    appendFramed(aad, node.bytecode_block_commitment);
    appendFramed(aad, node.handler_shard_commitment);
    appendFramed(aad, node.transition_tail_commitment);
    append32(aad, plaintext_size);
    return aad;
}

void appendRecordMetadata(std::vector<uint8_t> &encoded,
                          const ContinuationNodeV2 &node,
                          uint32_t plaintext_size,
                          uint32_t encrypted_size) {
    append32(encoded, node.node_id);
    append32(encoded, node.shard_id);
    append32(encoded, node.bytecode_offset);
    append32(encoded, node.bytecode_size);
    append32(encoded, node.shard_offset);
    append32(encoded, node.shard_size);
    encoded.insert(encoded.end(), node.bytecode_block_commitment.begin(),
                   node.bytecode_block_commitment.end());
    encoded.insert(encoded.end(), node.handler_shard_commitment.begin(),
                   node.handler_shard_commitment.end());
    encoded.insert(encoded.end(), node.transition_tail_commitment.begin(),
                   node.transition_tail_commitment.end());
    append32(encoded, plaintext_size);
    append32(encoded, encrypted_size);
}

bool metadataMatches(std::span<const uint8_t> metadata,
                     const ContinuationNodeV2 &node,
                     uint32_t plaintext_size) {
    return metadata.size() == kRecordMetadataSize &&
        read32(metadata, 0) == node.node_id &&
        read32(metadata, 4) == node.shard_id &&
        read32(metadata, 8) == node.bytecode_offset &&
        read32(metadata, 12) == node.bytecode_size &&
        read32(metadata, 16) == node.shard_offset &&
        read32(metadata, 20) == node.shard_size &&
        std::equal(node.bytecode_block_commitment.begin(),
                   node.bytecode_block_commitment.end(), metadata.begin() + 24) &&
        std::equal(node.handler_shard_commitment.begin(),
                   node.handler_shard_commitment.end(), metadata.begin() + 56) &&
        std::equal(node.transition_tail_commitment.begin(),
                   node.transition_tail_commitment.end(), metadata.begin() + 88) &&
        read32(metadata, 120) == plaintext_size &&
        read32(metadata, 124) == plaintext_size + kAeadOverhead;
}

std::vector<uint8_t> encodeRecordContainer(
    RecordRole role, std::span<const uint8_t> plaintext,
    std::span<const uint8_t, 32> key, const DynamicHash &build_id,
    const DynamicHash &region_id, std::span<const uint8_t> descriptors,
    const ContinuationGraphV2 &graph) {
    if (graph.nodes.empty() ||
        graph.nodes.size() > kDynamicVmMaxContinuationNodesV2)
        return {};
    std::vector<uint8_t> encoded(kRecordContainerMagic.begin(),
                                 kRecordContainerMagic.end());
    append16(encoded, kDynamicVmFormatVersion);
    encoded.push_back(static_cast<uint8_t>(role));
    encoded.push_back(static_cast<uint8_t>(graph.nodes.size()));
    for (const auto &node : graph.nodes) {
        const uint32_t offset = recordOffset(role, node);
        const uint32_t size = recordPlaintextSize(role, node);
        if (size == 0 || offset > plaintext.size() ||
            size > plaintext.size() - offset)
            return {};
        const auto aad = recordAad(role, build_id, region_id, descriptors,
                                   graph.descriptor, node, size);
        auto encrypted = encrypt(plaintext.subspan(offset, size), key, aad);
        if (encrypted.empty() || encrypted.size() > UINT32_MAX) {
            secureClear(encrypted);
            return {};
        }
        appendRecordMetadata(encoded, node, size,
                             static_cast<uint32_t>(encrypted.size()));
        encoded.insert(encoded.end(), encrypted.begin(), encrypted.end());
    }
    return encoded;
}

std::optional<std::vector<EncryptedRecordView>> parseRecordContainer(
    std::span<const uint8_t> encoded, RecordRole role,
    const ContinuationGraphV2 &graph) {
    if (encoded.size() < kRecordContainerHeaderSize ||
        !std::equal(kRecordContainerMagic.begin(), kRecordContainerMagic.end(),
                    encoded.begin()) ||
        read16(encoded, 8) != kDynamicVmFormatVersion ||
        encoded[10] != static_cast<uint8_t>(role) ||
        encoded[11] != graph.nodes.size() || graph.nodes.empty() ||
        graph.nodes.size() > kDynamicVmMaxContinuationNodesV2)
        return std::nullopt;
    size_t offset = kRecordContainerHeaderSize;
    std::vector<EncryptedRecordView> records;
    records.reserve(graph.nodes.size());
    for (const auto &node : graph.nodes) {
        if (offset > encoded.size() ||
            kRecordMetadataSize > encoded.size() - offset)
            return std::nullopt;
        const auto metadata = encoded.subspan(offset, kRecordMetadataSize);
        const uint32_t plaintext_size = recordPlaintextSize(role, node);
        if (!metadataMatches(metadata, node, plaintext_size))
            return std::nullopt;
        const uint32_t encrypted_size = read32(metadata, 124);
        offset += kRecordMetadataSize;
        if (offset > encoded.size() || encrypted_size > encoded.size() - offset)
            return std::nullopt;
        records.push_back({encoded.subspan(offset, encrypted_size)});
        offset += encrypted_size;
    }
    if (offset != encoded.size()) return std::nullopt;
    return records;
}

uint32_t readLittleEndian32(std::span<const uint8_t> bytes) {
    return static_cast<uint32_t>(bytes[0]) |
        static_cast<uint32_t>(bytes[1]) << 8 |
        static_cast<uint32_t>(bytes[2]) << 16 |
        static_cast<uint32_t>(bytes[3]) << 24;
}

bool validateNativeShards(const DynamicVmExecutionAbiV2 &abi,
                          const ContinuationGraphV2 &graph,
                          std::span<const uint8_t> bytecode,
                          std::span<const uint8_t> raw_handlers) {
    return std::all_of(graph.nodes.begin(), graph.nodes.end(),
                       [&](const ContinuationNodeV2 &node) {
        if (node.bytecode_offset > bytecode.size() ||
            node.bytecode_size > bytecode.size() - node.bytecode_offset ||
            node.shard_offset > raw_handlers.size() ||
            node.shard_size > raw_handlers.size() - node.shard_offset)
            return false;
        const auto block = bytecode.subspan(node.bytecode_offset,
                                            node.bytecode_size);
        const auto shard = raw_handlers.subspan(node.shard_offset,
                                                node.shard_size);
        const uint32_t next_ip = node.bytecode_offset + node.bytecode_size;
        if (node.semantic == ContinuationNodeSemanticV2::LoadI32) {
            if (abi.loadi32_immediate_offset > block.size() ||
                sizeof(uint32_t) > block.size() - abi.loadi32_immediate_offset)
                return false;
            return validateAarch64LoadImmediateShard(
                shard, node.register_index,
                readLittleEndian32(block.subspan(abi.loadi32_immediate_offset,
                                                  sizeof(uint32_t))),
                next_ip);
        }
        if (node.semantic == ContinuationNodeSemanticV2::ReturnI32)
            return validateAarch64ReturnIntShard(shard, node.register_index,
                                                 next_ip);
        return false;
    });
}

std::optional<std::vector<uint8_t>> decryptRecordContainer(
    std::span<const uint8_t> encoded, RecordRole role,
    std::span<const uint8_t, 32> key, const DynamicHash &build_id,
    const DynamicHash &region_id, std::span<const uint8_t> descriptors,
    const ContinuationGraphV2 &graph) {
    auto records = parseRecordContainer(encoded, role, graph);
    if (!records) return std::nullopt;
    const uint32_t total_size = role == RecordRole::BytecodeBlock
        ? graph.descriptor.bytecode_size
        : graph.descriptor.handler_shards_size;
    if (total_size == 0 || total_size > kDynamicVmMaxWindowMaterial)
        return std::nullopt;
    std::vector<uint8_t> plaintext(total_size);
    VectorScrubber plaintext_scrubber(plaintext);
    for (size_t index = 0; index < graph.nodes.size(); ++index) {
        const auto &node = graph.nodes[index];
        const uint32_t expected_size = recordPlaintextSize(role, node);
        const auto aad = recordAad(role, build_id, region_id, descriptors,
                                   graph.descriptor, node, expected_size);
        auto record_plaintext = decrypt((*records)[index].encoded, key, aad);
        VectorScrubber record_scrubber(record_plaintext);
        if (record_plaintext.size() != expected_size ||
            (role == RecordRole::BytecodeBlock
                 ? hashDynamicVmBytecodeBlockV2(record_plaintext)
                 : hashDynamicVmHandlerShardV2(record_plaintext)) !=
                recordCommitment(role, node))
            return std::nullopt;
        const uint32_t offset = recordOffset(role, node);
        std::copy(record_plaintext.begin(), record_plaintext.end(),
                  plaintext.begin() + offset);
    }
    plaintext_scrubber.release();
    return plaintext;
}

} // namespace

DynamicHash computeEncryptedVmArtifactHash(const EncryptedVmArtifact &artifact) {
    static constexpr std::string_view domain = "XOVM2/encrypted-artifact/v2";
    if (artifact.format_version != kDynamicVmFormatVersion ||
        !artifact.relocation_descriptors.empty())
        return {};
    std::vector<uint8_t> commitment(domain.begin(), domain.end());
    commitment.push_back(0);
    append16(commitment, artifact.format_version);
    appendFramed(commitment, artifact.build_id);
    appendFramed(commitment, artifact.region_id);
    appendFramed(commitment, artifact.encrypted_bytecode_blocks);
    appendFramed(commitment, artifact.encrypted_handler_shards);
    appendFramed(commitment, artifact.continuation_descriptors);
    appendFramed(commitment, artifact.relocation_descriptors);
    return hash(commitment);
}

bool validateEncryptedVmArtifactMetadata(
    const EncryptedVmArtifact &artifact, const DynamicHash &build_id,
    const DynamicHash &region_id, const DynamicHash &expected_artifact_hash) {
    if (expected_artifact_hash == DynamicHash{} || !nonzero(build_id) ||
        !nonzero(region_id) || artifact.format_version != kDynamicVmFormatVersion ||
        artifact.build_id != build_id || artifact.region_id != region_id ||
        artifact.artifact_hash != expected_artifact_hash ||
        artifact.encrypted_bytecode_blocks.empty() ||
        artifact.encrypted_handler_shards.empty() ||
        artifact.relocation_descriptors.size() != 0 ||
        computeEncryptedVmArtifactHash(artifact) != expected_artifact_hash)
        return false;
    const auto descriptors = parseDescriptors(artifact.continuation_descriptors);
    return descriptors &&
        parseRecordContainer(artifact.encrypted_bytecode_blocks,
                             RecordRole::BytecodeBlock,
                             descriptors->graph).has_value() &&
        parseRecordContainer(artifact.encrypted_handler_shards,
                             RecordRole::HandlerShard,
                             descriptors->graph).has_value();
}

std::optional<EncryptedVmArtifact> buildEncryptedVmArtifact(
    const ArtifactSource &source) {
    if (source.bytecode.empty() ||
        source.bytecode.size() > kDynamicVmMaxWindowMaterial ||
        source.handler_shards.size() <= kLegacyHandlerDescriptorSize ||
        source.handler_shards.size() >
            kLegacyHandlerDescriptorSize + kDynamicVmMaxWindowMaterial ||
        source.continuation_descriptors.size() > kDynamicVmMaxDescriptor ||
        !source.relocation_descriptors.empty() || !nonzero(source.build_id) ||
        !nonzero(source.region_id) || !nonzero(source.artifact_key))
        return std::nullopt;
    auto descriptors = parseDescriptors(source.continuation_descriptors);
    if (!descriptors) return std::nullopt;
    auto handler_payload = decodeHandlerShardPayload(source.handler_shards);
    if (!handler_payload) return std::nullopt;
    VectorScrubber handler_code_scrubber(handler_payload->code);
    const auto &graph = descriptors->graph;
    if (handler_payload->descriptor.shard_id != graph.nodes.front().shard_id ||
        handler_payload->descriptor.code_size != handler_payload->code.size() ||
        handler_payload->descriptor.relocation_count != 0 ||
        handler_payload->descriptor.commitment !=
            hashAarch64ShardCode(handler_payload->code) ||
        validateContinuationGraphV2(descriptors->abi, graph, source.bytecode,
                                    handler_payload->code) !=
            DynamicVmSchemaStatusV2::Valid ||
        !validateAarch64Shard(handler_payload->code) ||
        !validateNativeShards(descriptors->abi, graph, source.bytecode,
                              handler_payload->code))
        return std::nullopt;

    EncryptedVmArtifact artifact;
    artifact.build_id = source.build_id;
    artifact.region_id = source.region_id;
    artifact.encrypted_bytecode_blocks = encodeRecordContainer(
        RecordRole::BytecodeBlock, source.bytecode, source.artifact_key,
        source.build_id, source.region_id, source.continuation_descriptors,
        graph);
    artifact.encrypted_handler_shards = encodeRecordContainer(
        RecordRole::HandlerShard, handler_payload->code, source.artifact_key,
        source.build_id, source.region_id, source.continuation_descriptors,
        graph);
    if (artifact.encrypted_bytecode_blocks.empty() ||
        artifact.encrypted_handler_shards.empty())
        return std::nullopt;
    artifact.continuation_descriptors = source.continuation_descriptors;
    artifact.artifact_hash = computeEncryptedVmArtifactHash(artifact);
    if (artifact.artifact_hash == DynamicHash{}) return std::nullopt;
    return artifact;
}

std::optional<DecryptedVmArtifact> decryptEncryptedVmArtifact(
    const EncryptedVmArtifact &artifact,
    std::span<const uint8_t, 32> artifact_key,
    const DynamicHash &build_id, const DynamicHash &region_id,
    const DynamicHash &expected_artifact_hash) {
    if (!validateEncryptedVmArtifactMetadata(
            artifact, build_id, region_id, expected_artifact_hash))
        return std::nullopt;
    const auto descriptors = parseDescriptors(artifact.continuation_descriptors);
    if (!descriptors) return std::nullopt;
    auto bytecode = decryptRecordContainer(
        artifact.encrypted_bytecode_blocks, RecordRole::BytecodeBlock,
        artifact_key, build_id, region_id, artifact.continuation_descriptors,
        descriptors->graph);
    if (!bytecode) return std::nullopt;
    VectorScrubber bytecode_scrubber(*bytecode);
    auto raw_handlers = decryptRecordContainer(
        artifact.encrypted_handler_shards, RecordRole::HandlerShard,
        artifact_key, build_id, region_id, artifact.continuation_descriptors,
        descriptors->graph);
    if (!raw_handlers) return std::nullopt;
    VectorScrubber raw_handler_scrubber(*raw_handlers);
    if (validateContinuationGraphV2(descriptors->abi, descriptors->graph,
                                    *bytecode, *raw_handlers) !=
            DynamicVmSchemaStatusV2::Valid ||
        !validateAarch64Shard(*raw_handlers) ||
        !validateNativeShards(descriptors->abi, descriptors->graph, *bytecode,
                              *raw_handlers))
        return std::nullopt;

    HandlerShardDescriptor legacy_descriptor;
    legacy_descriptor.shard_id = descriptors->graph.nodes.front().shard_id;
    legacy_descriptor.code_size = static_cast<uint32_t>(raw_handlers->size());
    legacy_descriptor.commitment = hashAarch64ShardCode(*raw_handlers);
    auto legacy_handlers = encodeHandlerShardPayload(legacy_descriptor,
                                                     *raw_handlers);
    VectorScrubber legacy_handler_scrubber(legacy_handlers);
    if (legacy_handlers.empty()) return std::nullopt;

    DecryptedVmArtifact result{
        artifact.build_id, artifact.region_id, std::move(*bytecode),
        std::move(legacy_handlers), artifact.continuation_descriptors, {}};
    bytecode_scrubber.release();
    legacy_handler_scrubber.release();
    return result;
}

void secureClear(DecryptedVmArtifact &artifact) {
    secureClear(artifact.bytecode);
    secureClear(artifact.handler_shards);
    secureClear(artifact.continuation_descriptors);
    secureClear(artifact.relocation_descriptors);
}

} // namespace xovm::material
