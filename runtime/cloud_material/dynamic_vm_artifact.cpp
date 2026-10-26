#include "dynamic_vm_artifact.h"
#include "dynamic_vm_shard.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>

namespace xovm::material {
namespace {

std::vector<uint8_t> encrypt(std::span<const uint8_t> plaintext,
                             std::span<const uint8_t, 32> key,
                             std::span<const uint8_t> aad) {
    std::array<uint8_t, 12> nonce{};
    if (RAND_bytes(nonce.data(), nonce.size()) != 1) return {};
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (!context || EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1 ||
        EVP_EncryptInit_ex(context, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(context);
        return {};
    }
    int count = 0;
    if (EVP_EncryptUpdate(context, nullptr, &count, aad.data(), static_cast<int>(aad.size())) != 1) {
        EVP_CIPHER_CTX_free(context); return {};
    }
    std::vector<uint8_t> ciphertext(plaintext.size() + 16);
    if (EVP_EncryptUpdate(context, ciphertext.data(), &count, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(context); return {};
    }
    int final = 0;
    if (EVP_EncryptFinal_ex(context, ciphertext.data() + count, &final) != 1) {
        EVP_CIPHER_CTX_free(context); return {};
    }
    std::array<uint8_t, 16> tag{};
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(context); return {};
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
    if (encoded.size() < 12 + 16) return {};
    const auto nonce = encoded.first<12>();
    const auto tag = encoded.last<16>();
    const auto ciphertext = encoded.subspan(12, encoded.size() - 12 - 16);
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (!context || EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1 ||
        EVP_DecryptInit_ex(context, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(context);
        return {};
    }
    int count = 0;
    const bool aad_ok = EVP_DecryptUpdate(context, nullptr, &count, aad.data(),
                                          static_cast<int>(aad.size())) == 1;
    std::vector<uint8_t> plaintext(ciphertext.size() + 16);
    const bool data_ok = aad_ok && EVP_DecryptUpdate(context, plaintext.data(), &count,
                                                     ciphertext.data(),
                                                     static_cast<int>(ciphertext.size())) == 1;
    const bool tag_ok = data_ok && EVP_CIPHER_CTX_ctrl(
        context, EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<uint8_t *>(tag.data())) == 1;
    int final = 0;
    const bool final_ok = tag_ok && EVP_DecryptFinal_ex(context, plaintext.data() + count, &final) == 1;
    EVP_CIPHER_CTX_free(context);
    if (!final_ok) return {};
    plaintext.resize(static_cast<size_t>(count + final));
    return plaintext;
}

DynamicHash hash(std::span<const uint8_t> bytes) {
    DynamicHash result{};
    EVP_Digest(bytes.data(), bytes.size(), result.data(), nullptr, EVP_sha256(), nullptr);
    return result;
}

} // namespace

std::optional<EncryptedVmArtifact> buildEncryptedVmArtifact(const ArtifactSource &source) {
    auto handler_payload = decodeHandlerShardPayload(source.handler_shards);
    if (source.bytecode.empty() || source.bytecode.size() > kDynamicVmMaxWindowMaterial * 64 ||
        source.continuation_descriptors.size() > kDynamicVmMaxDescriptor ||
        source.relocation_descriptors.size() > kDynamicVmMaxDescriptor ||
        !handler_payload ||
        handler_payload->descriptor.code_size != handler_payload->code.size() ||
        handler_payload->descriptor.relocation_count != source.relocation_descriptors.size() / 8 ||
        source.relocation_descriptors.size() % 8 != 0 ||
        handler_payload->descriptor.commitment != hashAarch64ShardCode(handler_payload->code) ||
        !validateAarch64Shard(handler_payload->code))
        return std::nullopt;
    EncryptedVmArtifact artifact;
    artifact.build_id = source.build_id;
    artifact.region_id = source.region_id;
    std::vector<uint8_t> aad(source.build_id.begin(), source.build_id.end());
    aad.insert(aad.end(), source.region_id.begin(), source.region_id.end());
    artifact.encrypted_bytecode_blocks = encrypt(source.bytecode, source.artifact_key, aad);
    artifact.encrypted_handler_shards = encrypt(source.handler_shards, source.artifact_key, aad);
    if (artifact.encrypted_bytecode_blocks.empty() || artifact.encrypted_handler_shards.empty())
        return std::nullopt;
    artifact.continuation_descriptors = source.continuation_descriptors;
    artifact.relocation_descriptors = source.relocation_descriptors;
    std::vector<uint8_t> commitment = artifact.encrypted_bytecode_blocks;
    commitment.insert(commitment.end(), artifact.encrypted_handler_shards.begin(),
                      artifact.encrypted_handler_shards.end());
    commitment.insert(commitment.end(), artifact.continuation_descriptors.begin(),
                      artifact.continuation_descriptors.end());
    commitment.insert(commitment.end(), artifact.relocation_descriptors.begin(),
                      artifact.relocation_descriptors.end());
    artifact.artifact_hash = hash(commitment);
    return artifact;
}

std::optional<DecryptedVmArtifact> decryptEncryptedVmArtifact(
    const EncryptedVmArtifact &artifact,
    std::span<const uint8_t, 32> artifact_key,
    const DynamicHash &build_id,
    const DynamicHash &region_id) {
    if (artifact.format_version != kDynamicVmFormatVersion || artifact.build_id != build_id ||
        artifact.region_id != region_id || artifact.encrypted_bytecode_blocks.empty() ||
        artifact.encrypted_handler_shards.empty())
        return std::nullopt;
    std::vector<uint8_t> aad(build_id.begin(), build_id.end());
    aad.insert(aad.end(), region_id.begin(), region_id.end());
    std::vector<uint8_t> commitment = artifact.encrypted_bytecode_blocks;
    commitment.insert(commitment.end(), artifact.encrypted_handler_shards.begin(),
                      artifact.encrypted_handler_shards.end());
    commitment.insert(commitment.end(), artifact.continuation_descriptors.begin(),
                      artifact.continuation_descriptors.end());
    commitment.insert(commitment.end(), artifact.relocation_descriptors.begin(),
                      artifact.relocation_descriptors.end());
    if (hash(commitment) != artifact.artifact_hash) return std::nullopt;
    auto bytecode = decrypt(artifact.encrypted_bytecode_blocks, artifact_key, aad);
    auto handlers = decrypt(artifact.encrypted_handler_shards, artifact_key, aad);
    if (bytecode.empty() || handlers.empty()) return std::nullopt;
    auto Payload = decodeHandlerShardPayload(handlers);
    if (!Payload || !validateAarch64Shard(Payload->code) ||
        Payload->descriptor.relocation_count != artifact.relocation_descriptors.size() / 8 ||
        artifact.relocation_descriptors.size() % 8 != 0 ||
        Payload->descriptor.commitment != hashAarch64ShardCode(Payload->code))
        return std::nullopt;
    return DecryptedVmArtifact{artifact.build_id, artifact.region_id, std::move(bytecode),
                               std::move(handlers), artifact.continuation_descriptors,
                               artifact.relocation_descriptors};
}

void secureClear(DecryptedVmArtifact &artifact) {
    secureClear(artifact.bytecode);
    secureClear(artifact.handler_shards);
    secureClear(artifact.continuation_descriptors);
    secureClear(artifact.relocation_descriptors);
}

} // namespace xovm::material
