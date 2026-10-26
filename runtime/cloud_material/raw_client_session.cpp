#include "raw_client_session.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <algorithm>
#include <limits>

namespace xovm::cloud_material {
namespace {

using xovm::material::RawFrameDirection;
using xovm::material::RawFrameHeader;

void clear(std::span<uint8_t> bytes) noexcept {
    if (!bytes.empty()) OPENSSL_cleanse(bytes.data(), bytes.size());
}

template <size_t Size>
void clear(std::array<uint8_t, Size> &bytes) noexcept {
    clear(std::span<uint8_t>(bytes));
}

void clear(std::vector<uint8_t> &bytes) noexcept {
    clear(std::span<uint8_t>(bytes));
    bytes.clear();
}

class SensitiveBytes final {
public:
    ~SensitiveBytes() { clear(value); }
    std::vector<uint8_t> value;
};

std::variant<std::array<uint8_t, 32>, RawClientSessionError> deriveKey(
    std::span<const uint8_t, 32> secret, std::span<const uint8_t, 32> salt,
    std::span<const uint8_t> info) {
    std::array<uint8_t, 32> result{};
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    size_t result_size = result.size();
    const bool ok = context && EVP_PKEY_derive_init(context) == 1 &&
                    EVP_PKEY_CTX_set_hkdf_mode(
                        context, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) == 1 &&
                    EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) == 1 &&
                    EVP_PKEY_CTX_set1_hkdf_salt(
                        context, salt.data(), static_cast<int>(salt.size())) == 1 &&
                    EVP_PKEY_CTX_set1_hkdf_key(
                        context, secret.data(), static_cast<int>(secret.size())) == 1 &&
                    EVP_PKEY_CTX_add1_hkdf_info(
                        context, info.data(), static_cast<int>(info.size())) == 1 &&
                    EVP_PKEY_derive(context, result.data(), &result_size) == 1 &&
                    result_size == result.size();
    EVP_PKEY_CTX_free(context);
    if (!ok) {
        clear(result);
        return RawClientSessionError{"kdf_failure"};
    }
    return result;
}

std::array<uint8_t, 12> nonce(uint64_t sequence, uint32_t key_version) {
    std::array<uint8_t, 12> result{};
    result[0] = static_cast<uint8_t>(key_version >> 24);
    result[1] = static_cast<uint8_t>(key_version >> 16);
    result[2] = static_cast<uint8_t>(key_version >> 8);
    result[3] = static_cast<uint8_t>(key_version);
    for (int shift = 56; shift >= 0; shift -= 8)
        result[11 - static_cast<size_t>(shift / 8)] = static_cast<uint8_t>(sequence >> shift);
    return result;
}

std::variant<std::vector<uint8_t>, RawClientSessionError> seal(
    std::span<const uint8_t, 32> key, const RawFrameHeader &header,
    std::span<const uint8_t> plaintext, std::span<const uint8_t, 32> transcript_hash,
    RawFrameDirection direction, std::array<uint8_t, 16> &tag) {
    const auto aad = xovm::material::encodeRawFrameAad(header, transcript_hash, direction);
    const auto iv = nonce(header.sequence, header.flags);
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> output(plaintext.size() + 16);
    int ignored = 0;
    int produced = 0;
    int final = 0;
    const bool ok = context && EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                    EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) == 1 &&
                    EVP_EncryptInit_ex(context, nullptr, nullptr, key.data(), iv.data()) == 1 &&
                    EVP_EncryptUpdate(context, nullptr, &ignored, aad.data(), static_cast<int>(aad.size())) == 1 &&
                    EVP_EncryptUpdate(context, output.data(), &produced, plaintext.data(),
                                      static_cast<int>(plaintext.size())) == 1 &&
                    EVP_EncryptFinal_ex(context, output.data() + produced, &final) == 1 &&
                    EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) == 1;
    EVP_CIPHER_CTX_free(context);
    if (!ok) {
        clear(output);
        clear(tag);
        return RawClientSessionError{"encrypt_failed"};
    }
    output.resize(static_cast<size_t>(produced + final));
    return output;
}

std::variant<std::vector<uint8_t>, RawClientSessionError> open(
    std::span<const uint8_t, 32> key, const RawFrameHeader &header,
    std::span<const uint8_t> ciphertext, std::span<const uint8_t, 16> tag,
    std::span<const uint8_t, 32> transcript_hash, RawFrameDirection direction) {
    const auto aad = xovm::material::encodeRawFrameAad(header, transcript_hash, direction);
    const auto iv = nonce(header.sequence, header.flags);
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> output(ciphertext.size() + 16);
    int ignored = 0;
    int produced = 0;
    int final = 0;
    const bool ok = context && EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                    EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) == 1 &&
                    EVP_DecryptInit_ex(context, nullptr, nullptr, key.data(), iv.data()) == 1 &&
                    EVP_DecryptUpdate(context, nullptr, &ignored, aad.data(), static_cast<int>(aad.size())) == 1 &&
                    EVP_DecryptUpdate(context, output.data(), &produced, ciphertext.data(),
                                      static_cast<int>(ciphertext.size())) == 1 &&
                    EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, tag.size(),
                                        const_cast<uint8_t *>(tag.data())) == 1 &&
                    EVP_DecryptFinal_ex(context, output.data() + produced, &final) == 1;
    EVP_CIPHER_CTX_free(context);
    if (!ok) {
        clear(output);
        return RawClientSessionError{"bad_tag"};
    }
    output.resize(static_cast<size_t>(produced + final));
    return output;
}

} // namespace

RawClientSession::~RawClientSession() { clearSecrets(); }

RawClientSession::RawClientSession(RawClientSession &&other) noexcept {
    *this = std::move(other);
}

RawClientSession &RawClientSession::operator=(RawClientSession &&other) noexcept {
    if (this == &other) return *this;
    clearSecrets();
    hello_ = std::move(other.hello_);
    private_key_ = other.private_key_;
    server_signing_public_key_ = other.server_signing_public_key_;
    server_hello_ = other.server_hello_;
    transcript_ = std::move(other.transcript_);
    keys_ = other.keys_;
    transcript_hash_ = other.transcript_hash_;
    initial_state_commitment_ = other.initial_state_commitment_;
    send_sequence_ = other.send_sequence_;
    receive_sequence_ = other.receive_sequence_;
    established_ = other.established_;
    other.clearSecrets();
    other.established_ = false;
    return *this;
}

void RawClientSession::clearSecrets() noexcept {
    clear(private_key_);
    clear(keys_.client_to_server);
    clear(keys_.server_to_client);
    clear(keys_.material);
    clear(keys_.control);
}

std::variant<RawClientSession, RawClientSessionError> RawClientSession::create(
    const RawClientSessionConfig &config) {
    if (!config.random_bytes || config.hello.version != xovm::material::kRawProtocolVersion ||
        config.hello.software_id.empty() || config.hello.build_id.empty())
        return RawClientSessionError{"invalid_client_config"};
    SensitiveBytes random;
    try {
        auto result = config.random_bytes(64);
        if (std::holds_alternative<RawClientSessionError>(result))
            return std::get<RawClientSessionError>(std::move(result));
        random.value = std::get<std::vector<uint8_t>>(std::move(result));
    } catch (...) {
        return RawClientSessionError{"random_unavailable"};
    }
    if (random.value.size() != 64)
        return RawClientSessionError{"random_unavailable"};
    RawClientSession result;
    result.hello_ = config.hello;
    std::copy_n(random.value.begin(), 32, result.private_key_.begin());
    std::copy_n(random.value.begin() + 32, 32,
                result.hello_.client_nonce.begin());
    result.server_signing_public_key_ = config.server_signing_public_key;
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(nullptr, "X25519", nullptr,
                                                     result.private_key_.data(), result.private_key_.size());
    size_t public_size = result.hello_.client_ephemeral_public.size();
    const bool ok = key && EVP_PKEY_get_raw_public_key(key, result.hello_.client_ephemeral_public.data(),
                                                       &public_size) == 1 &&
                    public_size == result.hello_.client_ephemeral_public.size();
    EVP_PKEY_free(key);
    if (!ok) return RawClientSessionError{"key_unavailable"};
    return result;
}

bool RawClientSession::acceptServerHello(const xovm::material::RawServerHello &server_hello) {
    if (established_ || server_hello.version != xovm::material::kRawProtocolVersion) return false;
    transcript_.hello = hello_;
    transcript_.server_hello = server_hello;
    if (!xovm::material::verifyRawServerHello(transcript_, server_signing_public_key_)) return false;
    auto shared = xovm::material::deriveRawSharedSecret(
        private_key_, server_hello.server_ephemeral_public);
    if (std::holds_alternative<xovm::material::RawProtocolError>(shared)) return false;
    auto &shared_secret = std::get<std::array<uint8_t, 32>>(shared);
    auto keys = xovm::material::deriveRawSessionKeys(transcript_, shared_secret);
    clear(shared_secret);
    clear(private_key_);
    if (std::holds_alternative<xovm::material::RawProtocolError>(keys)) return false;
    server_hello_ = server_hello;
    auto &derived_keys = std::get<xovm::material::RawSessionKeys>(keys);
    keys_ = derived_keys;
    clear(derived_keys.client_to_server);
    clear(derived_keys.server_to_client);
    clear(derived_keys.material);
    clear(derived_keys.control);
    transcript_hash_ = xovm::material::hashRawTranscript(transcript_);
    constexpr char initial_state_label[] = "xovm/raw-socket/initial-state/v1";
    auto initial_state = deriveKey(
        keys_.control, transcript_hash_,
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t *>(initial_state_label),
            sizeof(initial_state_label) - 1));
    if (const auto *error = std::get_if<RawClientSessionError>(&initial_state)) {
        (void)error;
        return false;
    }
    auto &initial_state_bytes =
        std::get<std::array<uint8_t, 32>>(initial_state);
    initial_state_commitment_ = initial_state_bytes;
    clear(initial_state_bytes);
    clear(keys_.control);
    established_ = true;
    return true;
}

std::variant<std::array<uint8_t, 32>, RawClientSessionError>
RawClientSession::deriveGrantKey(
    std::span<const uint8_t, 32> request_commitment) const {
    if (!established_) return RawClientSessionError{"session_not_established"};
    constexpr char label[] = "xovm/raw-socket/grant-key/v1";
    std::vector<uint8_t> info;
    info.reserve(sizeof(label) - 1 + server_hello_.session_id.size() +
                 sizeof(server_hello_.key_version) + request_commitment.size());
    info.insert(info.end(), label, label + sizeof(label) - 1);
    info.insert(info.end(), server_hello_.session_id.begin(),
                server_hello_.session_id.end());
    info.push_back(static_cast<uint8_t>(server_hello_.key_version >> 24));
    info.push_back(static_cast<uint8_t>(server_hello_.key_version >> 16));
    info.push_back(static_cast<uint8_t>(server_hello_.key_version >> 8));
    info.push_back(static_cast<uint8_t>(server_hello_.key_version));
    info.insert(info.end(), request_commitment.begin(), request_commitment.end());
    auto result = deriveKey(keys_.material, transcript_hash_, info);
    clear(info);
    return result;
}

std::variant<std::vector<uint8_t>, RawClientSessionError> RawClientSession::encrypt(
    RawFrameHeader header, std::span<const uint8_t> plaintext) {
    if (!established_ || header.session_id != server_hello_.session_id ||
        header.flags != server_hello_.key_version ||
        header.payload_length != plaintext.size() + 16 ||
        plaintext.size() > xovm::material::kRawMaxFramePayload ||
        header.sequence != send_sequence_ ||
        send_sequence_ == std::numeric_limits<uint64_t>::max())
        return RawClientSessionError{"invalid_frame"};
    header.flags = server_hello_.key_version;
    std::array<uint8_t, 16> tag{};
    auto ciphertext = seal(keys_.client_to_server, header, plaintext, transcript_hash_,
                           RawFrameDirection::ClientToServer, tag);
    if (std::holds_alternative<RawClientSessionError>(ciphertext))
        return std::get<RawClientSessionError>(std::move(ciphertext));
    auto result = std::get<std::vector<uint8_t>>(std::move(ciphertext));
    result.insert(result.end(), tag.begin(), tag.end());
    ++send_sequence_;
    return result;
}

std::variant<std::vector<uint8_t>, RawClientSessionError> RawClientSession::decrypt(
    const RawFrameHeader &header, std::span<const uint8_t> ciphertext,
    std::span<const uint8_t, 16> tag) {
    if (!established_ || header.payload_length != ciphertext.size() + tag.size() ||
        ciphertext.size() > xovm::material::kRawMaxFramePayload)
        return RawClientSessionError{"invalid_frame_length"};
    if (header.session_id != server_hello_.session_id ||
        header.flags != server_hello_.key_version ||
        header.sequence != receive_sequence_ ||
        receive_sequence_ == std::numeric_limits<uint64_t>::max())
        return RawClientSessionError{"replay_detected"};
    auto plaintext = open(keys_.server_to_client, header, ciphertext, tag, transcript_hash_,
                          RawFrameDirection::ServerToClient);
    if (std::holds_alternative<RawClientSessionError>(plaintext))
        return std::get<RawClientSessionError>(std::move(plaintext));
    ++receive_sequence_;
    return std::get<std::vector<uint8_t>>(std::move(plaintext));
}

} // namespace xovm::cloud_material
