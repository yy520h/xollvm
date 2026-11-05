#include "raw_protocol.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <algorithm>
#include <cstring>
#include <limits>

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

bool get16(std::span<const uint8_t> bytes, size_t &offset, uint16_t &value) {
    if (bytes.size() - offset < 2) return false;
    value = static_cast<uint16_t>(bytes[offset] << 8 | bytes[offset + 1]);
    offset += 2;
    return true;
}

bool get32(std::span<const uint8_t> bytes, size_t &offset, uint32_t &value) {
    if (bytes.size() - offset < 4) return false;
    value = (static_cast<uint32_t>(bytes[offset]) << 24) |
            (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
            (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
            static_cast<uint32_t>(bytes[offset + 3]);
    offset += 4;
    return true;
}

bool get64(std::span<const uint8_t> bytes, size_t &offset, uint64_t &value) {
    if (bytes.size() - offset < 8) return false;
    value = 0;
    for (size_t index = 0; index < 8; ++index) value = (value << 8) | bytes[offset++];
    return true;
}

bool getString(std::span<const uint8_t> bytes, size_t &offset, std::string &value) {
    uint16_t length = 0;
    if (!get16(bytes, offset, length) || length == 0 || length > 64 ||
        bytes.size() - offset < length)
        return false;
    value.assign(reinterpret_cast<const char *>(bytes.data() + offset), length);
    offset += length;
    return true;
}

bool validType(uint16_t type) {
    return type >= static_cast<uint16_t>(RawFrameType::Announcement) &&
           (type <= static_cast<uint16_t>(RawFrameType::LoginCard) ||
            type == static_cast<uint16_t>(RawFrameType::Error));
}

void putString(std::vector<uint8_t> &out, const std::string &value) {
    put16(out, static_cast<uint16_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

std::vector<uint8_t> hkdf(std::span<const uint8_t> secret,
                          std::span<const uint8_t> salt,
                          std::span<const uint8_t> info) {
    std::vector<uint8_t> result(32);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    size_t size = result.size();
    const bool ok = ctx && EVP_PKEY_derive_init(ctx) == 1 &&
                    EVP_PKEY_CTX_set_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) == 1 &&
                    EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1 &&
                    EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), static_cast<int>(salt.size())) == 1 &&
                    EVP_PKEY_CTX_set1_hkdf_key(ctx, secret.data(), static_cast<int>(secret.size())) == 1 &&
                    EVP_PKEY_CTX_add1_hkdf_info(ctx, info.data(), static_cast<int>(info.size())) == 1 &&
                    EVP_PKEY_derive(ctx, result.data(), &size) == 1 && size == result.size();
    EVP_PKEY_CTX_free(ctx);
    if (!ok) return {};
    return result;
}

} // namespace

std::vector<uint8_t> encodeRawFrameHeader(const RawFrameHeader &header) {
    if (header.version != kRawProtocolVersion || header.payload_length > kRawMaxFramePayload)
        return {};
    std::vector<uint8_t> out;
    out.reserve(kRawFrameHeaderSize);
    put32(out, kRawFrameMagic);
    put16(out, header.version);
    put16(out, static_cast<uint16_t>(header.type));
    put32(out, header.flags);
    putBytes(out, header.session_id);
    put64(out, header.sequence);
    put32(out, header.payload_length);
    put32(out, 0);
    return out;
}

std::variant<RawFrameHeader, RawProtocolError>
decodeRawFrameHeader(std::span<const uint8_t> bytes) {
    if (bytes.size() != kRawFrameHeaderSize) return RawProtocolError{"invalid_header_size"};
    size_t offset = 0;
    uint32_t magic = 0;
    uint16_t version = 0;
    uint16_t type = 0;
    RawFrameHeader header;
    uint32_t reserved = 0;
    if (!get32(bytes, offset, magic) || !get16(bytes, offset, version) ||
        !get16(bytes, offset, type) || !get32(bytes, offset, header.flags) ||
        bytes.size() - offset < header.session_id.size())
        return RawProtocolError{"invalid_header"};
    std::copy_n(bytes.begin() + offset, header.session_id.size(), header.session_id.begin());
    offset += header.session_id.size();
    if (!get64(bytes, offset, header.sequence) || !get32(bytes, offset, header.payload_length) ||
        !get32(bytes, offset, reserved) || magic != kRawFrameMagic ||
        version != kRawProtocolVersion || !validType(type) || reserved != 0 ||
        header.payload_length > kRawMaxFramePayload)
        return RawProtocolError{"invalid_header"};
    header.version = version;
    header.type = static_cast<RawFrameType>(type);
    return header;
}

std::vector<uint8_t> encodeRawHello(const RawHello &hello) {
    if (hello.version != kRawProtocolVersion || hello.software_id.empty() ||
        hello.software_id.size() > 64 || hello.build_id.empty() || hello.build_id.size() > 64)
        return {};
    std::vector<uint8_t> out;
    put16(out, hello.version);
    putString(out, hello.software_id);
    putString(out, hello.build_id);
    putBytes(out, hello.client_nonce);
    putBytes(out, hello.client_ephemeral_public);
    putBytes(out, hello.request_id);
    put16(out, hello.cipher_suite);
    return out;
}

std::variant<RawHello, RawProtocolError> decodeRawHello(std::span<const uint8_t> bytes) {
    if (bytes.size() > 256) return RawProtocolError{"hello_size_limit"};
    size_t offset = 0;
    RawHello hello;
    uint16_t suite = 0;
    if (!get16(bytes, offset, hello.version) || hello.version != kRawProtocolVersion ||
        !getString(bytes, offset, hello.software_id) ||
        !getString(bytes, offset, hello.build_id) ||
        bytes.size() - offset < hello.client_nonce.size() + hello.client_ephemeral_public.size() +
            hello.request_id.size() + sizeof(suite))
        return RawProtocolError{"invalid_hello"};
    std::copy_n(bytes.begin() + offset, hello.client_nonce.size(), hello.client_nonce.begin());
    offset += hello.client_nonce.size();
    std::copy_n(bytes.begin() + offset, hello.client_ephemeral_public.size(),
                hello.client_ephemeral_public.begin());
    offset += hello.client_ephemeral_public.size();
    std::copy_n(bytes.begin() + offset, hello.request_id.size(), hello.request_id.begin());
    offset += hello.request_id.size();
    if (!get16(bytes, offset, suite) || suite != 1 || offset != bytes.size())
        return RawProtocolError{"invalid_hello"};
    hello.cipher_suite = suite;
    return hello;
}

std::vector<uint8_t> encodeRawServerHello(const RawServerHello &hello) {
    if (hello.version != kRawProtocolVersion) return {};
    std::vector<uint8_t> out;
    put16(out, hello.version);
    putBytes(out, hello.session_id);
    putBytes(out, hello.server_nonce);
    putBytes(out, hello.server_ephemeral_public);
    put64(out, hello.counter);
    put32(out, hello.key_version);
    put64(out, hello.expires_at_ms);
    putBytes(out, hello.signature);
    return out;
}

std::variant<RawServerHello, RawProtocolError>
decodeRawServerHello(std::span<const uint8_t> bytes) {
    constexpr size_t kEncodedSize = 2 + 16 + 32 + 32 + 8 + 4 + 8 + 64;
    if (bytes.size() != kEncodedSize) return RawProtocolError{"invalid_server_hello"};
    size_t offset = 0;
    RawServerHello hello;
    if (!get16(bytes, offset, hello.version) || hello.version != kRawProtocolVersion ||
        bytes.size() - offset < hello.session_id.size())
        return RawProtocolError{"invalid_server_hello"};
    std::copy_n(bytes.begin() + offset, hello.session_id.size(), hello.session_id.begin());
    offset += hello.session_id.size();
    std::copy_n(bytes.begin() + offset, hello.server_nonce.size(), hello.server_nonce.begin());
    offset += hello.server_nonce.size();
    std::copy_n(bytes.begin() + offset, hello.server_ephemeral_public.size(),
                hello.server_ephemeral_public.begin());
    offset += hello.server_ephemeral_public.size();
    if (!get64(bytes, offset, hello.counter) || !get32(bytes, offset, hello.key_version) ||
        !get64(bytes, offset, hello.expires_at_ms) || bytes.size() - offset != hello.signature.size())
        return RawProtocolError{"invalid_server_hello"};
    std::copy_n(bytes.begin() + offset, hello.signature.size(), hello.signature.begin());
    return hello;
}

std::vector<uint8_t> encodeRawTranscript(const RawSessionTranscript &transcript) {
    const auto hello = encodeRawHello(transcript.hello);
    const auto server = encodeRawServerHello(transcript.server_hello);
    if (hello.empty() || server.empty()) return {};
    std::vector<uint8_t> out;
    out.reserve(hello.size() + server.size() + 8);
    put32(out, static_cast<uint32_t>(hello.size()));
    putBytes(out, hello);
    put32(out, static_cast<uint32_t>(server.size()));
    putBytes(out, server);
    return out;
}

std::array<uint8_t, 32> hashRawTranscript(const RawSessionTranscript &transcript) {
    const auto encoded = encodeRawTranscript(transcript);
    std::array<uint8_t, 32> digest{};
    if (!encoded.empty()) SHA256(encoded.data(), encoded.size(), digest.data());
    return digest;
}

std::vector<uint8_t> encodeRawFrameAad(const RawFrameHeader &header,
                                       std::span<const uint8_t, 32> transcript_hash,
                                       RawFrameDirection direction) {
    const auto encoded = encodeRawFrameHeader(header);
    if (encoded.empty()) return {};
    std::vector<uint8_t> aad;
    aad.reserve(encoded.size() + transcript_hash.size() + 1);
    putBytes(aad, encoded);
    putBytes(aad, transcript_hash);
    aad.push_back(static_cast<uint8_t>(direction));
    return aad;
}

std::variant<RawSessionKeys, RawProtocolError>
deriveRawSessionKeys(const RawSessionTranscript &transcript,
                     std::span<const uint8_t, 32> shared_secret) {
    const auto encoded = encodeRawTranscript(transcript);
    if (encoded.empty() || std::all_of(shared_secret.begin(), shared_secret.end(),
                                       [](uint8_t byte) { return byte == 0; }))
        return RawProtocolError{"invalid_transcript"};
    std::array<uint8_t, 32> salt{};
    SHA256(encoded.data(), encoded.size(), salt.data());
    RawSessionKeys keys;
    const std::array<std::string_view, 4> labels = {
        "xovm/raw-socket/c2s", "xovm/raw-socket/s2c",
        "xovm/raw-socket/material", "xovm/raw-socket/control"};
    std::array<std::array<uint8_t, 32> *, 4> outputs = {
        &keys.client_to_server, &keys.server_to_client, &keys.material, &keys.control};
    for (size_t index = 0; index < labels.size(); ++index) {
        const auto result = hkdf(shared_secret, salt,
                                 std::span<const uint8_t>(
                                     reinterpret_cast<const uint8_t *>(labels[index].data()),
                                     labels[index].size()));
        if (result.size() != 32) return RawProtocolError{"kdf_failure"};
        std::copy(result.begin(), result.end(), outputs[index]->begin());
    }
    return keys;
}

std::variant<std::array<uint8_t, 32>, RawProtocolError>
deriveRawSharedSecret(std::span<const uint8_t, 32> private_key,
                      std::span<const uint8_t, 32> peer_public_key) {
    EVP_PKEY *local = EVP_PKEY_new_raw_private_key_ex(nullptr, "X25519", nullptr,
                                                       private_key.data(), private_key.size());
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key_ex(nullptr, "X25519", nullptr,
                                                     peer_public_key.data(), peer_public_key.size());
    EVP_PKEY_CTX *context = local ? EVP_PKEY_CTX_new(local, nullptr) : nullptr;
    std::array<uint8_t, 32> shared{};
    size_t size = shared.size();
    const bool ok = local && peer && context && EVP_PKEY_derive_init(context) == 1 &&
                    EVP_PKEY_derive_set_peer(context, peer) == 1 &&
                    EVP_PKEY_derive(context, shared.data(), &size) == 1 && size == shared.size() &&
                    std::any_of(shared.begin(), shared.end(), [](uint8_t byte) { return byte != 0; });
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(local);
    if (!ok) return RawProtocolError{"invalid_key"};
    return shared;
}

bool verifyRawServerHello(const RawSessionTranscript &transcript,
                          std::span<const uint8_t, 32> server_signing_public_key) {
    auto unsignedHello = transcript.server_hello;
    unsignedHello.signature.fill(0);
    RawSessionTranscript unsignedTranscript{transcript.hello, unsignedHello};
    const auto bytes = encodeRawTranscript(unsignedTranscript);
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key_ex(nullptr, "ED25519", nullptr,
                                                    server_signing_public_key.data(),
                                                    server_signing_public_key.size());
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    const bool valid = key && context && EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1 &&
                       EVP_DigestVerify(context, transcript.server_hello.signature.data(),
                                        transcript.server_hello.signature.size(), bytes.data(),
                                        bytes.size()) == 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return valid;
}

} // namespace xovm::material
