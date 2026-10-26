#include "dynamic_vm_window_provider.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string_view>

namespace xovm::material {
namespace {

constexpr size_t kGcmNonceSize = 12;
constexpr size_t kGcmTagSize = 16;
constexpr std::string_view kWindowGrantAadDomain =
    "xovm/dynamic-vm/window-grant/aad/v1";

bool isZero(std::span<const uint8_t> bytes) {
    return std::all_of(bytes.begin(), bytes.end(),
                       [](uint8_t byte) { return byte == 0; });
}

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

bool validGrantMetadata(const WindowGrant &grant) {
    return grant.format_version == kDynamicVmFormatVersion &&
           !isZero(grant.build_id) && !isZero(grant.region_id) &&
           !isZero(grant.session_id) && grant.generation != 0 &&
           grant.window_id != 0 && !isZero(grant.previous_state_hash) &&
           !isZero(grant.next_state_hash) &&
           grant.issued_at_ms < grant.expires_at_ms;
}

// This encoding is deliberately independent of encodeWindowGrant: it has its
// own domain and contains every immutable grant field, but no ciphertext or
// placeholder/sentinel for ciphertext.
std::vector<uint8_t> windowGrantAad(const WindowGrant &grant) {
    if (!validGrantMetadata(grant)) return {};

    std::vector<uint8_t> aad;
    aad.reserve(kWindowGrantAadDomain.size() + 2 + 32 + 32 + 16 + 8 + 8 +
                32 + 32 + 8 + 8 + 4 + 4);
    aad.insert(aad.end(), kWindowGrantAadDomain.begin(),
               kWindowGrantAadDomain.end());
    put16(aad, grant.format_version);
    putBytes(aad, grant.build_id);
    putBytes(aad, grant.region_id);
    putBytes(aad, grant.session_id);
    put64(aad, grant.generation);
    put64(aad, grant.window_id);
    putBytes(aad, grant.previous_state_hash);
    putBytes(aad, grant.next_state_hash);
    put64(aad, grant.issued_at_ms);
    put64(aad, grant.expires_at_ms);
    put32(aad, grant.key_version);
    put32(aad, static_cast<uint32_t>(kEncryptedWindowMaterialSize));
    return aad;
}

} // namespace

std::optional<WindowGrant> issueWindowGrant(const WindowIssueInput &input) {
    if (input.generation == 0 || input.window_id == 0 ||
        isZero(input.build_id) || isZero(input.region_id) ||
        isZero(input.session_id) || isZero(input.previous_state_hash) ||
        isZero(input.next_state_hash) || input.expires_at_ms <= input.now_ms ||
        input.material.size() != kWindowMaterialSize ||
        isZero(input.session_secret))
        return std::nullopt;

    WindowGrant grant;
    grant.build_id = input.build_id;
    grant.region_id = input.region_id;
    grant.session_id = input.session_id;
    grant.generation = input.generation;
    grant.window_id = input.window_id;
    grant.previous_state_hash = input.previous_state_hash;
    grant.next_state_hash = input.next_state_hash;
    grant.issued_at_ms = input.now_ms;
    grant.expires_at_ms = input.expires_at_ms;
    grant.key_version = input.key_version;
    const auto aad = windowGrantAad(grant);
    if (aad.empty()) return std::nullopt;

    std::array<uint8_t, kGcmNonceSize> nonce{};
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1)
        return std::nullopt;

    WindowMaterial plaintext{};
    std::memcpy(&plaintext, input.material.data(), sizeof(plaintext));
    std::vector<uint8_t> ciphertext(kWindowMaterialSize);
    std::array<uint8_t, kGcmTagSize> tag{};
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    int aad_produced = 0;
    int produced = 0;
    int final = 0;
    const bool encrypted =
        context &&
        EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) == 1 &&
        EVP_EncryptInit_ex(context, nullptr, nullptr,
                           input.session_secret.data(), nonce.data()) == 1 &&
        EVP_EncryptUpdate(context, nullptr, &aad_produced, aad.data(),
                          static_cast<int>(aad.size())) == 1 &&
        EVP_EncryptUpdate(context, ciphertext.data(), &produced,
                          reinterpret_cast<const uint8_t *>(&plaintext),
                          static_cast<int>(sizeof(plaintext))) == 1 &&
        EVP_EncryptFinal_ex(context, ciphertext.data() + produced, &final) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(tag.size()), tag.data()) == 1;
    EVP_CIPHER_CTX_free(context);
    secureClear(plaintext);

    if (!encrypted || produced + final != static_cast<int>(kWindowMaterialSize)) {
        secureClear(ciphertext);
        OPENSSL_cleanse(tag.data(), tag.size());
        return std::nullopt;
    }

    grant.encrypted_window_material.reserve(kEncryptedWindowMaterialSize);
    grant.encrypted_window_material.insert(grant.encrypted_window_material.end(),
                                            nonce.begin(), nonce.end());
    grant.encrypted_window_material.insert(grant.encrypted_window_material.end(),
                                            ciphertext.begin(), ciphertext.end());
    grant.encrypted_window_material.insert(grant.encrypted_window_material.end(),
                                            tag.begin(), tag.end());
    secureClear(ciphertext);
    OPENSSL_cleanse(tag.data(), tag.size());
    if (grant.encrypted_window_material.size() != kEncryptedWindowMaterialSize)
        return std::nullopt;
    return grant;
}

std::optional<WindowMaterial> decryptWindowMaterial(
    const WindowGrant &grant, std::span<const uint8_t, 32> session_secret) {
    if (grant.encrypted_window_material.size() != kEncryptedWindowMaterialSize ||
        isZero(session_secret))
        return std::nullopt;
    const auto aad = windowGrantAad(grant);
    if (aad.empty()) return std::nullopt;

    const auto &blob = grant.encrypted_window_material;
    const auto nonce = std::span<const uint8_t, kGcmNonceSize>(
        blob.data(), kGcmNonceSize);
    const auto ciphertext = std::span<const uint8_t, kWindowMaterialSize>(
        blob.data() + kGcmNonceSize, kWindowMaterialSize);
    const auto tag = std::span<const uint8_t, kGcmTagSize>(
        blob.data() + kGcmNonceSize + kWindowMaterialSize, kGcmTagSize);

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (!context ||
        EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(context, nullptr, nullptr, session_secret.data(),
                           nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(context);
        return std::nullopt;
    }

    int aad_produced = 0;
    int produced = 0;
    WindowMaterial material{};
    const bool aad_ok = EVP_DecryptUpdate(
        context, nullptr, &aad_produced, aad.data(),
        static_cast<int>(aad.size())) == 1;
    const bool data_ok = aad_ok && EVP_DecryptUpdate(
        context, reinterpret_cast<uint8_t *>(&material), &produced,
        ciphertext.data(), static_cast<int>(ciphertext.size())) == 1;
    const bool tag_ok = data_ok && EVP_CIPHER_CTX_ctrl(
        context, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
        const_cast<uint8_t *>(tag.data())) == 1;
    int final = 0;
    const bool final_ok = tag_ok && EVP_DecryptFinal_ex(
        context, reinterpret_cast<uint8_t *>(&material) + produced, &final) == 1;
    EVP_CIPHER_CTX_free(context);

    if (!final_ok || produced + final != static_cast<int>(sizeof(material))) {
        secureClear(material);
        return std::nullopt;
    }
    return material;
}

} // namespace xovm::material
