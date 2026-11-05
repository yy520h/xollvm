#include "dynamic_vm_artifact.h"
#include "dynamic_vm_shard.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
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
    'X', 'O', 'V', 'M', 'R', 'E', 'C', '3'};

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

std::array<uint8_t, 32> deriveRecordKeyV3(
    std::span<const uint8_t, 32> capability, RecordRole role,
    const DynamicHash &build_id, const DynamicHash &region_id,
    const DynamicVmWindowSelectorV3 &selector) {
    static constexpr std::string_view bytecode_domain =
        "xovm.dynamic-vm.record-key.bytecode.v3";
    static constexpr std::string_view handler_domain =
        "xovm.dynamic-vm.record-key.handler.v3";
    std::vector<uint8_t> salt_input;
    appendFramed(salt_input, build_id);
    appendFramed(salt_input, region_id);
    const auto encoded_selector = encodeDynamicVmWindowSelectorV3(selector);
    appendFramed(salt_input, encoded_selector);
    DynamicHash salt = hash(salt_input);
    std::array<uint8_t, 32> result{};
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    size_t size = result.size();
    const auto domain = role == RecordRole::BytecodeBlock
        ? bytecode_domain : handler_domain;
    const auto *info = reinterpret_cast<const uint8_t *>(domain.data());
    const bool ok = !encoded_selector.empty() && nonzero(salt) && context &&
        EVP_PKEY_derive_init(context) == 1 &&
        EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_salt(context, salt.data(), salt.size()) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_key(context, capability.data(),
                                  capability.size()) == 1 &&
        EVP_PKEY_CTX_add1_hkdf_info(context, info, domain.size()) == 1 &&
        EVP_PKEY_derive(context, result.data(), &size) == 1 &&
        size == result.size();
    EVP_PKEY_CTX_free(context);
    OPENSSL_cleanse(salt.data(), salt.size());
    if (!ok) result.fill(0);
    return result;
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

std::vector<uint8_t> recordAad(
    RecordRole role, const DynamicHash &build_id, const DynamicHash &region_id,
    std::span<const uint8_t> descriptors,
    const DynamicVmExecutionDescriptorV2 &graph_descriptor,
    const ContinuationNodeV2 &node, uint32_t plaintext_size) {
    static constexpr std::string_view domain =
        "XOVM2/artifact-record-aad/v3";
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
    const std::vector<DynamicVmNodeCapabilityV3> &capabilities,
    const DynamicHash &build_id, const DynamicHash &region_id,
    std::span<const uint8_t> descriptors,
    const DynamicVmExecutionAbiV2 &abi, const ContinuationGraphV2 &graph) {
    if (graph.nodes.empty() ||
        graph.nodes.size() > kDynamicVmMaxContinuationNodesV2)
        return {};
    std::vector<uint8_t> encoded(kRecordContainerMagic.begin(),
                                 kRecordContainerMagic.end());
    append16(encoded, kDynamicVmSelectiveFormatVersionV3);
    encoded.push_back(static_cast<uint8_t>(role));
    encoded.push_back(static_cast<uint8_t>(graph.nodes.size()));
    for (const auto &node : graph.nodes) {
        const uint32_t offset = recordOffset(role, node);
        const uint32_t size = recordPlaintextSize(role, node);
        if (size == 0 || offset > plaintext.size() ||
            size > plaintext.size() - offset)
            return {};
        const auto capability = std::find_if(
            capabilities.begin(), capabilities.end(), [&](const auto &value) {
                return value.node_id == node.node_id;
            });
        const auto selector = dynamicVmWindowSelectorV3(
            abi, graph.descriptor, node);
        if (capability == capabilities.end() || !selector ||
            !nonzero(capability->capability))
            return {};
        auto key = deriveRecordKeyV3(capability->capability, role, build_id,
                                     region_id, *selector);
        if (!nonzero(key)) {
            OPENSSL_cleanse(key.data(), key.size());
            return {};
        }
        const auto aad = recordAad(role, build_id, region_id, descriptors,
                                   graph.descriptor, node, size);
        auto encrypted = encrypt(plaintext.subspan(offset, size), key, aad);
        OPENSSL_cleanse(key.data(), key.size());
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
        read16(encoded, 8) != kDynamicVmSelectiveFormatVersionV3 ||
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


} // namespace

DynamicHash computeEncryptedVmArtifactHash(const EncryptedVmArtifact &artifact) {
    static constexpr std::string_view domain = "XOVM2/encrypted-artifact/v3";
    if (artifact.format_version != kDynamicVmSelectiveFormatVersionV3 ||
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
        !nonzero(region_id) || artifact.format_version != kDynamicVmSelectiveFormatVersionV3 ||
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

DynamicVmPrivateRegistrationV3::DynamicVmPrivateRegistrationV3(
    DynamicVmPrivateRegistrationV3 &&other) noexcept
    : build_id_(other.build_id_), region_id_(other.region_id_),
      artifact_hash_(other.artifact_hash_),
      capabilities_(std::move(other.capabilities_)) {
    other.clear();
}

DynamicVmPrivateRegistrationV3 &DynamicVmPrivateRegistrationV3::operator=(
    DynamicVmPrivateRegistrationV3 &&other) noexcept {
    if (this != &other) {
        clear();
        build_id_ = other.build_id_;
        region_id_ = other.region_id_;
        artifact_hash_ = other.artifact_hash_;
        capabilities_ = std::move(other.capabilities_);
        other.clear();
    }
    return *this;
}

DynamicVmPrivateRegistrationV3::~DynamicVmPrivateRegistrationV3() { clear(); }

void DynamicVmPrivateRegistrationV3::clear() {
    for (auto &entry : capabilities_)
        OPENSSL_cleanse(entry.capability.data(), entry.capability.size());
    capabilities_.clear();
    capabilities_.shrink_to_fit();
    build_id_.fill(0);
    region_id_.fill(0);
    artifact_hash_.fill(0);
}

std::optional<std::array<uint8_t, 32>>
DynamicVmPrivateRegistrationV3::capabilityFor(
    const DynamicVmWindowSelectorV3 &selector) const {
    const auto found = std::find_if(
        capabilities_.begin(), capabilities_.end(), [&](const auto &entry) {
            return entry.selector == selector;
        });
    if (found == capabilities_.end()) return std::nullopt;
    return found->capability;
}

DecryptedDynamicVmNodeV3::DecryptedDynamicVmNodeV3(
    DecryptedDynamicVmNodeV3 &&other) noexcept
    : abi_(other.abi_), descriptor_(other.descriptor_), node_(other.node_),
      bytecode_block_(std::move(other.bytecode_block_)),
      handler_shard_(std::move(other.handler_shard_)) {
    other.clear();
}

DecryptedDynamicVmNodeV3 &DecryptedDynamicVmNodeV3::operator=(
    DecryptedDynamicVmNodeV3 &&other) noexcept {
    if (this != &other) {
        clear();
        abi_ = other.abi_;
        descriptor_ = other.descriptor_;
        node_ = other.node_;
        bytecode_block_ = std::move(other.bytecode_block_);
        handler_shard_ = std::move(other.handler_shard_);
        other.clear();
    }
    return *this;
}

DecryptedDynamicVmNodeV3::~DecryptedDynamicVmNodeV3() { clear(); }

void DecryptedDynamicVmNodeV3::clear() {
    secureClear(bytecode_block_);
    secureClear(handler_shard_);
    OPENSSL_cleanse(&abi_, sizeof(abi_));
    OPENSSL_cleanse(&descriptor_, sizeof(descriptor_));
    OPENSSL_cleanse(&node_, sizeof(node_));
}

std::optional<BuiltDynamicVmArtifactV3> buildSelectiveEncryptedVmArtifactV3(
    const ArtifactSourceV3 &source) {
    if (source.bytecode.empty() ||
        source.bytecode.size() > kDynamicVmMaxWindowMaterial ||
        source.handler_shards.size() <= kLegacyHandlerDescriptorSize ||
        source.handler_shards.size() >
            kLegacyHandlerDescriptorSize + kDynamicVmMaxWindowMaterial ||
        source.continuation_descriptors.size() > kDynamicVmMaxDescriptor ||
        !source.relocation_descriptors.empty() || !nonzero(source.build_id) ||
        !nonzero(source.region_id))
        return std::nullopt;
    auto descriptors = parseDescriptors(source.continuation_descriptors);
    if (!descriptors ||
        source.node_capabilities.size() != descriptors->graph.nodes.size())
        return std::nullopt;
    auto handler_payload = decodeHandlerShardPayload(source.handler_shards);
    if (!handler_payload) return std::nullopt;
    VectorScrubber handler_code_scrubber(handler_payload->code);
    const auto &graph = descriptors->graph;
    for (size_t index = 0; index < graph.nodes.size(); ++index) {
        if (source.node_capabilities[index].node_id != graph.nodes[index].node_id ||
            !nonzero(source.node_capabilities[index].capability))
            return std::nullopt;
        for (size_t prior = 0; prior < index; ++prior)
            if (source.node_capabilities[prior].node_id ==
                    source.node_capabilities[index].node_id ||
                source.node_capabilities[prior].capability ==
                    source.node_capabilities[index].capability)
                return std::nullopt;
    }
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

    BuiltDynamicVmArtifactV3 built;
    built.artifact.build_id = source.build_id;
    built.artifact.region_id = source.region_id;
    built.artifact.encrypted_bytecode_blocks = encodeRecordContainer(
        RecordRole::BytecodeBlock, source.bytecode, source.node_capabilities,
        source.build_id, source.region_id, source.continuation_descriptors,
        descriptors->abi, graph);
    built.artifact.encrypted_handler_shards = encodeRecordContainer(
        RecordRole::HandlerShard, handler_payload->code,
        source.node_capabilities, source.build_id, source.region_id,
        source.continuation_descriptors, descriptors->abi, graph);
    if (built.artifact.encrypted_bytecode_blocks.empty() ||
        built.artifact.encrypted_handler_shards.empty())
        return std::nullopt;
    built.artifact.continuation_descriptors = source.continuation_descriptors;
    built.artifact.artifact_hash = computeEncryptedVmArtifactHash(built.artifact);
    if (!nonzero(built.artifact.artifact_hash)) return std::nullopt;

    built.registration.build_id_ = source.build_id;
    built.registration.region_id_ = source.region_id;
    built.registration.artifact_hash_ = built.artifact.artifact_hash;
    built.registration.capabilities_.reserve(graph.nodes.size());
    for (size_t index = 0; index < graph.nodes.size(); ++index) {
        auto selector = dynamicVmWindowSelectorV3(
            descriptors->abi, graph.descriptor, graph.nodes[index]);
        if (!selector) return std::nullopt;
        built.registration.capabilities_.push_back(
            {*selector, source.node_capabilities[index].capability});
    }
    return std::optional<BuiltDynamicVmArtifactV3>(std::move(built));
}

std::optional<DecryptedDynamicVmNodeV3> decryptSelectiveDynamicVmNodeV3(
    const EncryptedVmArtifact &artifact,
    const DynamicVmWindowSelectorV3 &selector,
    std::span<const uint8_t, 32> node_capability,
    const DynamicHash &build_id, const DynamicHash &region_id,
    const DynamicHash &expected_artifact_hash) {
    if (!nonzero(node_capability) ||
        !validateEncryptedVmArtifactMetadata(
            artifact, build_id, region_id, expected_artifact_hash))
        return std::nullopt;
    const auto descriptors = parseDescriptors(artifact.continuation_descriptors);
    if (!descriptors) return std::nullopt;
    const auto node_it = std::find_if(
        descriptors->graph.nodes.begin(), descriptors->graph.nodes.end(),
        [&](const auto &node) {
            auto expected = dynamicVmWindowSelectorV3(
                descriptors->abi, descriptors->graph.descriptor, node);
            return expected && *expected == selector;
        });
    if (node_it == descriptors->graph.nodes.end()) return std::nullopt;
    const size_t node_index = static_cast<size_t>(
        node_it - descriptors->graph.nodes.begin());
    auto blocks = parseRecordContainer(artifact.encrypted_bytecode_blocks,
                                       RecordRole::BytecodeBlock,
                                       descriptors->graph);
    auto shards = parseRecordContainer(artifact.encrypted_handler_shards,
                                       RecordRole::HandlerShard,
                                       descriptors->graph);
    if (!blocks || !shards || node_index >= blocks->size() ||
        node_index >= shards->size())
        return std::nullopt;

    auto block_key = deriveRecordKeyV3(node_capability,
        RecordRole::BytecodeBlock, build_id, region_id, selector);
    auto shard_key = deriveRecordKeyV3(node_capability,
        RecordRole::HandlerShard, build_id, region_id, selector);
    if (!nonzero(block_key) || !nonzero(shard_key)) {
        OPENSSL_cleanse(block_key.data(), block_key.size());
        OPENSSL_cleanse(shard_key.data(), shard_key.size());
        return std::nullopt;
    }
    const auto block_aad = recordAad(
        RecordRole::BytecodeBlock, build_id, region_id,
        artifact.continuation_descriptors, descriptors->graph.descriptor,
        *node_it, node_it->bytecode_size);
    const auto shard_aad = recordAad(
        RecordRole::HandlerShard, build_id, region_id,
        artifact.continuation_descriptors, descriptors->graph.descriptor,
        *node_it, node_it->shard_size);
    auto block = decrypt((*blocks)[node_index].encoded, block_key, block_aad);
    auto shard = decrypt((*shards)[node_index].encoded, shard_key, shard_aad);
    OPENSSL_cleanse(block_key.data(), block_key.size());
    OPENSSL_cleanse(shard_key.data(), shard_key.size());
    VectorScrubber block_scrubber(block);
    VectorScrubber shard_scrubber(shard);
    if (block.size() != node_it->bytecode_size ||
        shard.size() != node_it->shard_size ||
        hashDynamicVmBytecodeBlockV2(block) !=
            node_it->bytecode_block_commitment ||
        hashDynamicVmHandlerShardV2(shard) !=
            node_it->handler_shard_commitment)
        return std::nullopt;

    const uint32_t next_ip = node_it->bytecode_offset + node_it->bytecode_size;
    bool native_valid = false;
    if (node_it->semantic == ContinuationNodeSemanticV2::LoadI32 &&
        descriptors->abi.loadi32_immediate_offset <= block.size() &&
        sizeof(uint32_t) <= block.size() -
            descriptors->abi.loadi32_immediate_offset) {
        native_valid = validateAarch64LoadImmediateShard(
            shard, node_it->register_index,
            readLittleEndian32(std::span<const uint8_t>(block).subspan(
                descriptors->abi.loadi32_immediate_offset, sizeof(uint32_t))),
            next_ip);
    } else if (node_it->semantic == ContinuationNodeSemanticV2::ReturnI32) {
        native_valid = validateAarch64ReturnIntShard(
            shard, node_it->register_index, next_ip);
    }
    if (!native_valid) return std::nullopt;

    DecryptedDynamicVmNodeV3 result;
    result.abi_ = descriptors->abi;
    result.descriptor_ = descriptors->graph.descriptor;
    result.node_ = *node_it;
    result.bytecode_block_ = std::move(block);
    result.handler_shard_ = std::move(shard);
    block_scrubber.release();
    shard_scrubber.release();
    return std::optional<DecryptedDynamicVmNodeV3>(std::move(result));
}

} // namespace xovm::material
