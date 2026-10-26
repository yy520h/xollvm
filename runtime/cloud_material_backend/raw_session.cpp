#include "raw_session.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <algorithm>
#include <cstring>
#include <limits>

namespace xovm::cloud_material {
namespace {

using xovm::material::RawFrameHeader;
using xovm::material::RawProtocolError;

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

class SensitiveVectors final {
public:
    ~SensitiveVectors() {
        clear(private_key);
        clear(server_nonce);
        clear(session_id);
    }

    SensitiveVectors(const SensitiveVectors &) = delete;
    SensitiveVectors &operator=(const SensitiveVectors &) = delete;

    SensitiveVectors() = default;
    std::vector<uint8_t> private_key;
    std::vector<uint8_t> server_nonce;
    std::vector<uint8_t> session_id;
};

std::variant<std::array<uint8_t, 32>, RawSessionError> deriveKey(
    std::span<const uint8_t, 32> secret, std::span<const uint8_t, 32> salt,
    std::span<const uint8_t> info) {
    std::array<uint8_t, 32> result{};
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    size_t resultSize = result.size();
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
                    EVP_PKEY_derive(context, result.data(), &resultSize) == 1 &&
                    resultSize == result.size();
    EVP_PKEY_CTX_free(context);
    if (!ok) {
        clear(result);
        return RawSessionError{"kdf_failure"};
    }
    return result;
}

std::variant<std::vector<uint8_t>, RawSessionError> seal(
    std::span<const uint8_t, 32> key, const RawFrameHeader &header,
    std::span<const uint8_t> plaintext, std::span<const uint8_t, 32> transcript_hash,
    xovm::material::RawFrameDirection direction, std::array<uint8_t, 16> &tag) {
    const auto headerBytes = xovm::material::encodeRawFrameAad(header, transcript_hash, direction);
    const auto iv = nonce(header.sequence, header.flags);
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> output(plaintext.size() + 16);
    int produced = 0;
    int final = 0;
    const bool ok = context && EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                    EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) == 1 &&
                    EVP_EncryptInit_ex(context, nullptr, nullptr, key.data(), iv.data()) == 1 &&
                    EVP_EncryptUpdate(context, nullptr, &produced, headerBytes.data(),
                                      static_cast<int>(headerBytes.size())) == 1 &&
                    EVP_EncryptUpdate(context, output.data(), &produced, plaintext.data(),
                                      static_cast<int>(plaintext.size())) == 1 &&
                    EVP_EncryptFinal_ex(context, output.data() + produced, &final) == 1 &&
                    EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) == 1;
    EVP_CIPHER_CTX_free(context);
    if (!ok) {
        clear(output);
        return RawSessionError{"encrypt_failed"};
    }
    output.resize(static_cast<size_t>(produced + final));
    return output;
}

std::variant<std::vector<uint8_t>, RawSessionError> open(
    std::span<const uint8_t, 32> key, const RawFrameHeader &header,
    std::span<const uint8_t> ciphertext, std::span<const uint8_t, 16> tag,
    std::span<const uint8_t, 32> transcript_hash,
    xovm::material::RawFrameDirection direction) {
    const auto headerBytes = xovm::material::encodeRawFrameAad(header, transcript_hash, direction);
    const auto iv = nonce(header.sequence, header.flags);
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> output(ciphertext.size() + 16);
    int produced = 0;
    int final = 0;
    const bool ok = context && EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                    EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) == 1 &&
                    EVP_DecryptInit_ex(context, nullptr, nullptr, key.data(), iv.data()) == 1 &&
                    EVP_DecryptUpdate(context, nullptr, &produced, headerBytes.data(),
                                      static_cast<int>(headerBytes.size())) == 1 &&
                    EVP_DecryptUpdate(context, output.data(), &produced, ciphertext.data(),
                                      static_cast<int>(ciphertext.size())) == 1 &&
                    EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, tag.size(),
                                        const_cast<uint8_t *>(tag.data())) == 1 &&
                    EVP_DecryptFinal_ex(context, output.data() + produced, &final) == 1;
    EVP_CIPHER_CTX_free(context);
    if (!ok) {
        clear(output);
        return RawSessionError{"bad_tag"};
    }
    output.resize(static_cast<size_t>(produced + final));
    return output;
}

} // namespace

AuthenticatedRawContext::~AuthenticatedRawContext() { clearSecrets(); }

AuthenticatedRawContext::AuthenticatedRawContext(AuthenticatedRawContext &&other) noexcept {
    *this = std::move(other);
}

AuthenticatedRawContext &AuthenticatedRawContext::operator=(
    AuthenticatedRawContext &&other) noexcept {
    if (this == &other) return *this;
    clearSecrets();
    software_id_ = std::move(other.software_id_);
    build_id_ = std::move(other.build_id_);
    session_id_ = other.session_id_;
    key_version_ = other.key_version_;
    expires_at_ms_ = other.expires_at_ms_;
    transcript_hash_ = other.transcript_hash_;
    initial_state_commitment_ = other.initial_state_commitment_;
    grant_key_root_ = other.grant_key_root_;
    other.clearSecrets();
    return *this;
}

void AuthenticatedRawContext::clearSecrets() noexcept {
    clear(grant_key_root_);
}

std::variant<std::array<uint8_t, 32>, RawSessionError>
AuthenticatedRawContext::deriveGrantKey(
    std::span<const uint8_t, 32> request_commitment) const {
    constexpr char label[] = "xovm/raw-socket/grant-key/v1";
    std::vector<uint8_t> info;
    info.reserve(sizeof(label) - 1 + session_id_.size() + sizeof(key_version_) +
                 request_commitment.size());
    info.insert(info.end(), label, label + sizeof(label) - 1);
    info.insert(info.end(), session_id_.begin(), session_id_.end());
    info.push_back(static_cast<uint8_t>(key_version_ >> 24));
    info.push_back(static_cast<uint8_t>(key_version_ >> 16));
    info.push_back(static_cast<uint8_t>(key_version_ >> 8));
    info.push_back(static_cast<uint8_t>(key_version_));
    info.insert(info.end(), request_commitment.begin(), request_commitment.end());
    auto result = deriveKey(grant_key_root_, transcript_hash_, info);
    clear(info);
    return result;
}

RawSession::~RawSession() { clearSecrets(); }

RawSession::RawSession(RawSession &&other) noexcept { *this = std::move(other); }

RawSession &RawSession::operator=(RawSession &&other) noexcept {
    if (this == &other) return *this;
    clearSecrets();
    server_hello_ = std::move(other.server_hello_);
    transcript_ = std::move(other.transcript_);
    keys_ = other.keys_;
    transcript_hash_ = other.transcript_hash_;
    authenticated_context_ = std::move(other.authenticated_context_);
    trusted_now_ = std::move(other.trusted_now_);
    send_sequence_ = other.send_sequence_;
    receive_sequence_ = other.receive_sequence_;
    other.clearSecrets();
    return *this;
}

void RawSession::clearSecrets() noexcept {
    clear(keys_.client_to_server);
    clear(keys_.server_to_client);
    clear(keys_.material);
    clear(keys_.control);
}

std::variant<RawSession, RawSessionError> RawSession::accept(
    const xovm::material::RawHello &hello, const RawSessionConfig &config) {
    if (hello.version != xovm::material::kRawProtocolVersion || !config.random_bytes ||
        !config.sign || !config.trusted_now || config.expires_at_ms == 0)
        return RawSessionError{"invalid_session_config"};
    std::variant<uint64_t, RawSessionError> now = RawSessionError{"trusted_time_unavailable"};
    try { now = config.trusted_now(); }
    catch (...) { return RawSessionError{"trusted_time_unavailable"}; }
    if (const auto *error = std::get_if<RawSessionError>(&now)) return *error;
    if (config.expires_at_ms <= std::get<uint64_t>(now))
        return RawSessionError{"session_expired"};
    auto random = [&config](size_t size) -> std::variant<std::vector<uint8_t>, RawSessionError> {
        try { return config.random_bytes(size); }
        catch (...) { return RawSessionError{"random_unavailable"}; }
    };
    auto privateResult = random(32);
    auto nonceResult = random(32);
    auto sessionResult = random(16);
    if (std::holds_alternative<RawSessionError>(privateResult) ||
        std::holds_alternative<RawSessionError>(nonceResult) ||
        std::holds_alternative<RawSessionError>(sessionResult)) {
        if (auto *value = std::get_if<std::vector<uint8_t>>(&privateResult)) clear(*value);
        if (auto *value = std::get_if<std::vector<uint8_t>>(&nonceResult)) clear(*value);
        if (auto *value = std::get_if<std::vector<uint8_t>>(&sessionResult)) clear(*value);
        return RawSessionError{"random_unavailable"};
    }
    SensitiveVectors sensitive;
    sensitive.private_key = std::get<std::vector<uint8_t>>(std::move(privateResult));
    sensitive.server_nonce = std::get<std::vector<uint8_t>>(std::move(nonceResult));
    sensitive.session_id = std::get<std::vector<uint8_t>>(std::move(sessionResult));
    if (sensitive.private_key.size() != 32 || sensitive.server_nonce.size() != 32 ||
        sensitive.session_id.size() != 16)
        return RawSessionError{"random_unavailable"};
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(nullptr, "X25519", nullptr,
        sensitive.private_key.data(), sensitive.private_key.size());
    std::array<uint8_t, 32> serverPublic{};
    size_t publicSize = serverPublic.size();
    if (!key || EVP_PKEY_get_raw_public_key(key, serverPublic.data(), &publicSize) != 1 ||
        publicSize != serverPublic.size()) {
        EVP_PKEY_free(key); return RawSessionError{"key_unavailable"};
    }
    EVP_PKEY_free(key);
    RawSession result;
    result.trusted_now_ = config.trusted_now;
    std::copy(sensitive.session_id.begin(), sensitive.session_id.end(),
              result.server_hello_.session_id.begin());
    std::copy(sensitive.server_nonce.begin(), sensitive.server_nonce.end(),
              result.server_hello_.server_nonce.begin());
    result.server_hello_.server_ephemeral_public = serverPublic;
    result.server_hello_.counter = config.counter;
    result.server_hello_.key_version = config.key_version;
    result.server_hello_.expires_at_ms = config.expires_at_ms;
    result.transcript_.hello = hello;
    result.transcript_.server_hello = result.server_hello_;
    const auto transcript = xovm::material::encodeRawTranscript(result.transcript_);
    std::variant<std::array<uint8_t, 64>, RawSessionError> signature =
        RawSessionError{"sign_failed"};
    try { signature = config.sign(transcript); }
    catch (...) { return RawSessionError{"sign_failed"}; }
    if (const auto *error = std::get_if<RawSessionError>(&signature)) return *error;
    result.server_hello_.signature = std::get<std::array<uint8_t, 64>>(signature);
    result.transcript_.server_hello = result.server_hello_;
    result.transcript_hash_ = xovm::material::hashRawTranscript(result.transcript_);
    auto shared = xovm::material::deriveRawSharedSecret(
        std::span<const uint8_t, 32>(sensitive.private_key.data(), sensitive.private_key.size()),
        hello.client_ephemeral_public);
    if (const auto *error = std::get_if<RawProtocolError>(&shared))
        return RawSessionError{error->code};
    auto &sharedSecret = std::get<std::array<uint8_t, 32>>(shared);
    auto keys = xovm::material::deriveRawSessionKeys(result.transcript_, sharedSecret);
    clear(sharedSecret);
    if (const auto *error = std::get_if<RawProtocolError>(&keys))
        return RawSessionError{error->code};
    auto &derivedKeys = std::get<xovm::material::RawSessionKeys>(keys);
    result.keys_ = derivedKeys;
    clear(derivedKeys.client_to_server);
    clear(derivedKeys.server_to_client);
    clear(derivedKeys.material);
    clear(derivedKeys.control);
    result.authenticated_context_.software_id_ = hello.software_id;
    result.authenticated_context_.build_id_ = hello.build_id;
    result.authenticated_context_.session_id_ = result.server_hello_.session_id;
    result.authenticated_context_.key_version_ = result.server_hello_.key_version;
    result.authenticated_context_.expires_at_ms_ = result.server_hello_.expires_at_ms;
    result.authenticated_context_.transcript_hash_ = result.transcript_hash_;
    constexpr char initialStateLabel[] = "xovm/raw-socket/initial-state/v1";
    auto initialState = deriveKey(result.keys_.control, result.transcript_hash_,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(initialStateLabel),
                                 sizeof(initialStateLabel) - 1));
    if (const auto *error = std::get_if<RawSessionError>(&initialState)) return *error;
    auto &initialStateBytes = std::get<std::array<uint8_t, 32>>(initialState);
    result.authenticated_context_.initial_state_commitment_ = initialStateBytes;
    clear(initialStateBytes);
    result.authenticated_context_.grant_key_root_ = result.keys_.material;
    clear(result.keys_.material);
    clear(result.keys_.control);
    return result;
}

std::variant<std::monostate, RawSessionError> RawSession::checkFresh() const {
    if (!trusted_now_) return RawSessionError{"invalid_session_config"};
    std::variant<uint64_t, RawSessionError> now = RawSessionError{"trusted_time_unavailable"};
    try { now = trusted_now_(); }
    catch (...) { return RawSessionError{"trusted_time_unavailable"}; }
    if (const auto *error = std::get_if<RawSessionError>(&now)) return *error;
    if (authenticated_context_.expiresAtMs() <= std::get<uint64_t>(now))
        return RawSessionError{"session_expired"};
    return std::monostate{};
}

std::variant<std::vector<uint8_t>, RawSessionError> RawSession::encrypt(
    xovm::material::RawFrameHeader header, std::span<const uint8_t> plaintext) {
    if (header.session_id != server_hello_.session_id ||
        header.flags != server_hello_.key_version ||
        header.payload_length != plaintext.size() + 16 ||
        plaintext.size() > xovm::material::kRawMaxFramePayload || header.sequence != send_sequence_ ||
        send_sequence_ == std::numeric_limits<uint64_t>::max())
        return RawSessionError{"invalid_frame"};
    if (auto fresh = checkFresh(); std::holds_alternative<RawSessionError>(fresh))
        return std::get<RawSessionError>(std::move(fresh));
    header.flags = server_hello_.key_version;
    std::array<uint8_t, 16> tag{};
    auto ciphertext = seal(keys_.server_to_client, header, plaintext, transcript_hash_,
                           xovm::material::RawFrameDirection::ServerToClient, tag);
    if (auto *error = std::get_if<RawSessionError>(&ciphertext)) return *error;
    auto result = std::get<std::vector<uint8_t>>(std::move(ciphertext));
    result.insert(result.end(), tag.begin(), tag.end());
    ++send_sequence_;
    return result;
}

std::variant<std::vector<uint8_t>, RawSessionError> RawSession::decrypt(
    const xovm::material::RawFrameHeader &header, std::span<const uint8_t> ciphertext,
    std::span<const uint8_t, 16> tag) {
    if (header.payload_length != ciphertext.size() + tag.size() ||
        ciphertext.size() > xovm::material::kRawMaxFramePayload)
        return RawSessionError{"invalid_frame_length"};
    if (header.session_id != server_hello_.session_id || header.flags != server_hello_.key_version ||
        header.sequence != receive_sequence_ ||
        receive_sequence_ == std::numeric_limits<uint64_t>::max())
        return RawSessionError{"replay_detected"};
    if (auto fresh = checkFresh(); std::holds_alternative<RawSessionError>(fresh))
        return std::get<RawSessionError>(std::move(fresh));
    auto plaintext = open(keys_.client_to_server, header, ciphertext, tag, transcript_hash_,
                          xovm::material::RawFrameDirection::ClientToServer);
    if (auto *error = std::get_if<RawSessionError>(&plaintext)) return *error;
    ++receive_sequence_;
    return plaintext;
}

} // namespace xovm::cloud_material
