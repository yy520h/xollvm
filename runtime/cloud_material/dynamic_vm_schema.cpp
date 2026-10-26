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

bool same(std::span<const uint8_t> left, std::span<const uint8_t> right) {
    return left.size() == right.size() &&
           std::equal(left.begin(), left.end(), right.begin());
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

std::vector<uint8_t> encodeEncryptedVmArtifact(const EncryptedVmArtifact &artifact) {
    if (artifact.format_version != kDynamicVmFormatVersion ||
        artifact.encrypted_bytecode_blocks.size() > kDynamicVmMaxWindowMaterial * 64 ||
        artifact.encrypted_handler_shards.size() > kDynamicVmMaxWindowMaterial * 64 ||
        artifact.continuation_descriptors.size() > kDynamicVmMaxDescriptor ||
        artifact.relocation_descriptors.size() > kDynamicVmMaxDescriptor)
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
        !read_sized(artifact.relocation_descriptors, kDynamicVmMaxDescriptor) ||
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
        descriptor.relocation_count > descriptor.code_size / 4)
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
