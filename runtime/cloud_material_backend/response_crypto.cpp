#include "response_crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <algorithm>
#include <limits>

namespace xovm::cloud_material {
namespace {
using Json = nlohmann::json;

std::vector<std::uint8_t> frame(std::string_view label,
                                std::initializer_list<std::span<const std::uint8_t>> parts) {
    std::vector<std::uint8_t> result(label.begin(), label.end());
    result.push_back(0);
    for (const auto part : parts) {
        if (part.size() > UINT32_MAX) throw BackendError{"invalid_frame"};
        const auto size = static_cast<std::uint32_t>(part.size());
        result.push_back(static_cast<std::uint8_t>(size >> 24));
        result.push_back(static_cast<std::uint8_t>(size >> 16));
        result.push_back(static_cast<std::uint8_t>(size >> 8));
        result.push_back(static_cast<std::uint8_t>(size));
        result.insert(result.end(), part.begin(), part.end());
    }
    return result;
}

std::array<std::uint8_t, 32> digest(std::span<const std::uint8_t> data) {
    std::array<std::uint8_t, 32> result{};
    unsigned int size = 0;
    if (EVP_Digest(data.data(), data.size(), result.data(), &size, EVP_sha256(), nullptr) != 1 ||
        size != result.size()) throw BackendError{"key_unavailable"};
    return result;
}

std::vector<std::uint8_t> hkdf(std::span<const std::uint8_t> input,
                               std::span<const std::uint8_t> salt,
                               std::span<const std::uint8_t> info, size_t size) {
    EVP_PKEY_CTX *raw = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    std::vector<std::uint8_t> result(size);
    size_t actual = size;
    if (!raw || EVP_PKEY_derive_init(raw) != 1 ||
        EVP_PKEY_CTX_set_hkdf_mode(raw, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) != 1 ||
        EVP_PKEY_CTX_set_hkdf_md(raw, EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_key(raw, input.data(), static_cast<int>(input.size())) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_salt(raw, salt.data(), static_cast<int>(salt.size())) != 1 ||
        EVP_PKEY_CTX_add1_hkdf_info(raw, info.data(), static_cast<int>(info.size())) != 1 ||
        EVP_PKEY_derive(raw, result.data(), &actual) != 1 || actual != size) {
        EVP_PKEY_CTX_free(raw);
        throw BackendError{"key_unavailable"};
    }
    EVP_PKEY_CTX_free(raw);
    return result;
}

std::string b64(std::span<const std::uint8_t> bytes) {
    std::string output(4 * ((bytes.size() + 2) / 3), '\0');
    const int size = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output.data()),
                                     bytes.data(), static_cast<int>(bytes.size()));
    if (size < 0) throw BackendError{"key_unavailable"};
    output.resize(static_cast<size_t>(size));
    return output;
}

std::vector<std::uint8_t> x25519(std::span<const std::uint8_t, 32> privateKey,
                                 std::span<const std::uint8_t, 32> publicKey) {
    EVP_PKEY *local = EVP_PKEY_new_raw_private_key_ex(nullptr, "X25519", nullptr,
                                                       privateKey.data(), privateKey.size());
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key_ex(nullptr, "X25519", nullptr,
                                                     publicKey.data(), publicKey.size());
    EVP_PKEY_CTX *context = local ? EVP_PKEY_CTX_new(local, nullptr) : nullptr;
    std::vector<std::uint8_t> shared(32);
    size_t size = shared.size();
    const bool ok = local && peer && context && EVP_PKEY_derive_init(context) == 1 &&
        EVP_PKEY_derive_set_peer(context, peer) == 1 &&
        EVP_PKEY_derive(context, shared.data(), &size) == 1 && size == shared.size() &&
        std::any_of(shared.begin(), shared.end(), [](auto byte) { return byte != 0; });
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(local);
    if (!ok) throw BackendError{"invalid_key"};
    return shared;
}
}

std::vector<std::uint8_t> frameForTest(std::string_view label,
                                      std::span<const std::uint8_t> part) {
    return frame(label, {part});
}

std::variant<std::vector<std::byte>, BackendError> sealResponse(
    const Json &transcript, std::span<const std::byte> plaintext,
    std::span<const std::uint8_t, 32> clientPublic,
    std::span<const std::uint8_t, 32> serverPrivate, const SignEd25519 &sign) {
    std::vector<std::uint8_t> shared, key, iv;
    try {
        if (!sign || plaintext.size() > INT_MAX) throw BackendError{"key_unavailable"};
        const std::string transcriptText = transcript.dump();
        const auto transcriptBytes = std::span(
            reinterpret_cast<const std::uint8_t *>(transcriptText.data()), transcriptText.size());
        const auto transcriptFrame = frame("XOVM2/transcript", {transcriptBytes});
        const auto transcriptHash = digest(transcriptFrame);
        shared = x25519(serverPrivate, clientPublic);
        const auto keyInfo = frame("XOVM2/response-key", {transcriptHash});
        const auto ivInfo = frame("XOVM2/response-iv", {transcriptHash});
        key = hkdf(shared, transcriptHash, keyInfo, 32);
        iv = hkdf(shared, transcriptHash, ivInfo, 12);
        const auto aad = frame("XOVM2/aad", {transcriptBytes});
        EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
        std::vector<std::uint8_t> ciphertext(plaintext.size() + 16);
        std::array<std::uint8_t, 16> tag{};
        int produced = 0, final = 0;
        const bool encrypted = context && EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr,
            nullptr, nullptr) == 1 && EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
            static_cast<int>(iv.size()), nullptr) == 1 && EVP_EncryptInit_ex(context, nullptr,
            nullptr, key.data(), iv.data()) == 1 && EVP_EncryptUpdate(context, nullptr, &produced,
            aad.data(), static_cast<int>(aad.size())) == 1 && EVP_EncryptUpdate(context,
            ciphertext.data(), &produced, reinterpret_cast<const std::uint8_t *>(plaintext.data()),
            static_cast<int>(plaintext.size())) == 1 && EVP_EncryptFinal_ex(context,
            ciphertext.data() + produced, &final) == 1 && EVP_CIPHER_CTX_ctrl(context,
            EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) == 1;
        EVP_CIPHER_CTX_free(context);
        if (!encrypted) throw BackendError{"key_unavailable"};
        ciphertext.resize(static_cast<size_t>(produced + final));
        const auto signatureInput = frame("XOVM2/signature", {transcriptBytes, ciphertext, tag});
        auto signedResult = sign(signatureInput);
        if (auto *error = std::get_if<BackendError>(&signedResult)) throw *error;
        const auto signature = std::get<std::array<std::uint8_t, 64>>(signedResult);
        Json envelope{{"transcript", transcript}, {"ciphertext", b64(ciphertext)},
                      {"tag", b64(tag)}, {"signature", b64(signature)}};
        const std::string encoded = "{\"ciphertext\":" + Json(b64(ciphertext)).dump() +
            ",\"signature\":" + Json(b64(signature)).dump() + ",\"tag\":" +
            Json(b64(tag)).dump() + ",\"transcript\":" + transcriptText + "}";
        (void)envelope;
        if (encoded.size() > kMaxRawResponse) throw BackendError{"response_size_limit"};
        std::vector<std::byte> output;
        output.reserve(encoded.size());
        for (const unsigned char byte : encoded) output.push_back(static_cast<std::byte>(byte));
        OPENSSL_cleanse(shared.data(), shared.size());
        OPENSSL_cleanse(key.data(), key.size());
        OPENSSL_cleanse(iv.data(), iv.size());
        return output;
    } catch (const BackendError &error) {
        OPENSSL_cleanse(shared.data(), shared.size());
        OPENSSL_cleanse(key.data(), key.size());
        OPENSSL_cleanse(iv.data(), iv.size());
        return error;
    } catch (...) {
        OPENSSL_cleanse(shared.data(), shared.size());
        OPENSSL_cleanse(key.data(), key.size());
        OPENSSL_cleanse(iv.data(), iv.size());
        return BackendError{"key_unavailable"};
    }
}

} // namespace xovm::cloud_material
