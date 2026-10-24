#include "material_protocol.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>
#include <string_view>

namespace xovm::material {
namespace {
using nlohmann::json;
template<class T, void (*F)(T *)> using Handle = std::unique_ptr<T, decltype(F)>;

constexpr std::string_view kSuite = "X25519-Ed25519-HKDF-SHA256-AES256GCM";
constexpr size_t kMaxRequest = 8192;
constexpr size_t kMaxTrustBundle = 65536;
constexpr size_t kMaxCiphertext = 11250348;

[[noreturn]] void fail(const char *code) { throw ProtocolError{code}; }

void closed(const json &value, std::initializer_list<const char *> fields) {
    if (!value.is_object() || value.size() != fields.size()) fail("invalid_schema");
    for (const char *field : fields) if (!value.contains(field)) fail("invalid_schema");
}

const std::string &text(const json &value) {
    if (!value.is_string()) fail("invalid_type");
    return value.get_ref<const std::string &>();
}

uint32_t u32(const json &value, uint32_t minimum = 0,
             uint32_t maximum = std::numeric_limits<uint32_t>::max()) {
    if (!value.is_number_unsigned()) fail("invalid_u32");
    const auto number = value.get<uint64_t>();
    if (number < minimum || number > maximum) fail("invalid_u32");
    return static_cast<uint32_t>(number);
}

uint64_t u64(const json &value) {
    const auto &valueText = text(value);
    if (valueText.empty() || valueText.size() > 20 ||
        (valueText.size() > 1 && valueText.front() == '0')) fail("invalid_u64");
    uint64_t result = 0;
    for (char character : valueText) {
        if (character < '0' || character > '9') fail("invalid_u64");
        const auto digit = static_cast<uint64_t>(character - '0');
        if (result > (UINT64_MAX - digit) / 10) fail("u64_overflow");
        result = result * 10 + digit;
    }
    return result;
}

bool isId(std::string_view value) {
    if (value.empty() || value.size() > 64) return false;
    const auto first = value.front();
    if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') ||
          (first >= '0' && first <= '9'))) return false;
    return std::all_of(value.begin(), value.end(), [](char character) {
        return (character >= 'A' && character <= 'Z') ||
               (character >= 'a' && character <= 'z') ||
               (character >= '0' && character <= '9') || character == '.' ||
               character == '_' || character == '-';
    });
}

void checkId(std::string_view value) {
    if (!isId(value)) fail("invalid_id");
}

void checkHash(std::string_view value) {
    if (value.size() != 64 || !std::all_of(value.begin(), value.end(), [](char character) {
        return (character >= '0' && character <= '9') ||
               (character >= 'a' && character <= 'f');
    })) fail("invalid_hash");
}

uint8_t unhexDigit(char value) {
    if (value >= '0' && value <= '9') return static_cast<uint8_t>(value - '0');
    if (value >= 'a' && value <= 'f') return static_cast<uint8_t>(value - 'a' + 10);
    fail("invalid_hash");
}

std::array<uint8_t, 32> unhex32(std::string_view value) {
    checkHash(value);
    std::array<uint8_t, 32> result{};
    for (size_t index = 0; index < result.size(); ++index)
        result[index] = static_cast<uint8_t>((unhexDigit(value[index * 2]) << 4) |
                                             unhexDigit(value[index * 2 + 1]));
    return result;
}

std::string hex(std::span<const uint8_t> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes) {
        result += digits[byte >> 4];
        result += digits[byte & 15];
    }
    return result;
}

int base64Value(char character) {
    if (character >= 'A' && character <= 'Z') return character - 'A';
    if (character >= 'a' && character <= 'z') return character - 'a' + 26;
    if (character >= '0' && character <= '9') return character - '0' + 52;
    if (character == '+') return 62;
    if (character == '/') return 63;
    return -1;
}

std::vector<uint8_t> base64(const json &value, size_t exact = SIZE_MAX,
                            size_t maximum = SIZE_MAX) {
    const auto &encoded = text(value);
    if (encoded.empty() || encoded.size() % 4 ||
        (maximum != SIZE_MAX && encoded.size() > maximum * 4 / 3 + 4))
        fail("invalid_base64");
    const size_t padding = encoded.ends_with("==") ? 2 : encoded.ends_with("=") ? 1 : 0;
    const size_t end = encoded.size() - padding;
    for (size_t index = 0; index < end; ++index)
        if (base64Value(encoded[index]) < 0) fail("invalid_base64");
    for (size_t index = end; index < encoded.size(); ++index)
        if (encoded[index] != '=') fail("invalid_base64");
    if (!end || (padding == 2 && (base64Value(encoded[end - 1]) & 15)) ||
        (padding == 1 && (base64Value(encoded[end - 1]) & 3))) fail("invalid_base64");
    const size_t decodedSize = 3 * (encoded.size() / 4) - padding;
    if ((exact != SIZE_MAX && decodedSize != exact) || decodedSize > maximum)
        fail("invalid_base64");
    std::vector<uint8_t> result(decodedSize);
    uint32_t bits = 0;
    unsigned count = 0;
    size_t output = 0;
    for (size_t index = 0; index < end; ++index) {
        bits = (bits << 6) | static_cast<uint32_t>(base64Value(encoded[index]));
        count += 6;
        if (count >= 8) {
            count -= 8;
            result[output++] = static_cast<uint8_t>(bits >> count);
        }
    }
    return result;
}

std::vector<uint8_t> frame(std::string_view label,
                           std::initializer_list<std::span<const uint8_t>> parts) {
    size_t size = label.size() + 1;
    for (auto part : parts) {
        if (part.size() > UINT32_MAX || size > SIZE_MAX - part.size() - 4) fail("invalid_frame");
        size += part.size() + 4;
    }
    std::vector<uint8_t> result;
    result.reserve(size);
    result.insert(result.end(), label.begin(), label.end());
    result.push_back(0);
    for (auto part : parts) {
        const auto length = static_cast<uint32_t>(part.size());
        result.push_back(static_cast<uint8_t>(length >> 24));
        result.push_back(static_cast<uint8_t>(length >> 16));
        result.push_back(static_cast<uint8_t>(length >> 8));
        result.push_back(static_cast<uint8_t>(length));
        result.insert(result.end(), part.begin(), part.end());
    }
    return result;
}

std::array<uint8_t, 32> sha256(std::span<const uint8_t> bytes) {
    std::array<uint8_t, 32> result{};
    SHA256(bytes.data(), bytes.size(), result.data());
    return result;
}

bool ed25519Verify(std::span<const uint8_t, 32> publicKey,
                   std::span<const uint8_t> message,
                   std::span<const uint8_t, 64> signature) {
    Handle<EVP_PKEY, EVP_PKEY_free> key(
        EVP_PKEY_new_raw_public_key_ex(nullptr, "ED25519", nullptr,
                                       publicKey.data(), publicKey.size()), EVP_PKEY_free);
    Handle<EVP_MD_CTX, EVP_MD_CTX_free> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    return key && context && EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr,
                                                  key.get()) == 1 &&
           EVP_DigestVerify(context.get(), signature.data(), signature.size(),
                            message.data(), message.size()) == 1;
}

void validateX25519(std::span<const uint8_t, 32> key) {
    static constexpr std::array<uint8_t, 32> prime = {
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    };
    if (key.back() & 0x80) fail("invalid_key");
    for (size_t index = key.size(); index-- > 0;) {
        if (key[index] < prime[index]) return;
        if (key[index] > prime[index]) fail("invalid_key");
    }
    fail("invalid_key");
}

std::array<uint8_t, 32> x25519(std::span<const uint8_t, 32> privateKey,
                               std::span<const uint8_t, 32> publicKey) {
    validateX25519(publicKey);
    Handle<EVP_PKEY, EVP_PKEY_free> local(
        EVP_PKEY_new_raw_private_key_ex(nullptr, "X25519", nullptr,
                                        privateKey.data(), privateKey.size()), EVP_PKEY_free);
    Handle<EVP_PKEY, EVP_PKEY_free> peer(
        EVP_PKEY_new_raw_public_key_ex(nullptr, "X25519", nullptr,
                                       publicKey.data(), publicKey.size()), EVP_PKEY_free);
    Handle<EVP_PKEY_CTX, EVP_PKEY_CTX_free> context(
        local ? EVP_PKEY_CTX_new(local.get(), nullptr) : nullptr, EVP_PKEY_CTX_free);
    std::array<uint8_t, 32> shared{};
    size_t size = shared.size();
    if (!local || !peer || !context || EVP_PKEY_derive_init(context.get()) != 1 ||
        EVP_PKEY_derive_set_peer(context.get(), peer.get()) != 1 ||
        EVP_PKEY_derive(context.get(), shared.data(), &size) != 1 || size != shared.size() ||
        std::all_of(shared.begin(), shared.end(), [](uint8_t value) { return value == 0; })) {
        OPENSSL_cleanse(shared.data(), shared.size());
        fail("invalid_key");
    }
    return shared;
}

struct PrivateKeyCopy {
    std::array<uint8_t, 32> bytes;
    ~PrivateKeyCopy() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};

std::vector<uint8_t> hkdf(std::span<const uint8_t> input,
                          std::span<const uint8_t> salt,
                          std::span<const uint8_t> info, size_t outputSize) {
    Handle<EVP_PKEY_CTX, EVP_PKEY_CTX_free> context(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    std::vector<uint8_t> result(outputSize);
    size_t size = result.size();
    if (!context || EVP_PKEY_derive_init(context.get()) != 1 ||
        EVP_PKEY_CTX_set_hkdf_mode(context.get(), EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) != 1 ||
        EVP_PKEY_CTX_set_hkdf_md(context.get(), EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_key(context.get(), input.data(), static_cast<int>(input.size())) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_salt(context.get(), salt.data(), static_cast<int>(salt.size())) != 1 ||
        EVP_PKEY_CTX_add1_hkdf_info(context.get(), info.data(), static_cast<int>(info.size())) != 1 ||
        EVP_PKEY_derive(context.get(), result.data(), &size) != 1 || size != outputSize) {
        OPENSSL_cleanse(result.data(), result.size());
        fail("kdf_failure");
    }
    return result;
}

std::vector<uint8_t> decrypt(std::span<const uint8_t, 32> key,
                             std::span<const uint8_t, 12> iv,
                             std::span<const uint8_t> aad,
                             std::span<const uint8_t> ciphertext,
                             std::span<const uint8_t, 16> tag) {
    Handle<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> context(EVP_CIPHER_CTX_new(),
                                                        EVP_CIPHER_CTX_free);
    std::vector<uint8_t> plaintext(ciphertext.size() + 16);
    int output = 0;
    int final = 0;
    if (!context || EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr,
                                       nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv.data()) != 1 ||
        EVP_DecryptUpdate(context.get(), nullptr, &output, aad.data(),
                          static_cast<int>(aad.size())) != 1 ||
        EVP_DecryptUpdate(context.get(), plaintext.data(), &output, ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(tag.size()), const_cast<uint8_t *>(tag.data())) != 1 ||
        EVP_DecryptFinal_ex(context.get(), plaintext.data() + output, &final) != 1) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        fail("bad_tag");
    }
    plaintext.resize(static_cast<size_t>(output + final));
    if (plaintext.size() != ciphertext.size()) fail("invalid_plaintext");
    return plaintext;
}

class EnvelopeScanner {
    std::string_view input_;
    size_t position_ = 0;

    int at() const {
        return position_ < input_.size() ? static_cast<unsigned char>(input_[position_]) : -1;
    }
    void take(int wanted) {
        if (at() != wanted) fail("invalid_canonical");
        ++position_;
    }
    std::string_view string(size_t limit, bool key = false) {
        take('"');
        const size_t start = position_;
        size_t count = 0;
        while (position_ < input_.size() && at() != '"') {
            if (++count > limit) fail("string_limit");
            int current = at();
            ++position_;
            if (current < 32 || current > 126) fail("invalid_ascii");
            if (current == '\\') {
                current = at();
                ++position_;
                if (key || (current != '"' && current != '\\')) fail("invalid_canonical");
            }
        }
        const size_t end = position_;
        take('"');
        return input_.substr(start, end - start);
    }
    void value(unsigned depth, std::string_view owner = {}) {
        if (depth > 8) fail("depth_limit");
        if (at() == '{') {
            ++position_;
            size_t count = 0;
            std::string_view previous;
            if (at() == '}') { ++position_; return; }
            while (true) {
                if (++count > 40) fail("object_limit");
                const auto key = string(64, true);
                if (key.empty() || key <= previous || key.front() < 'a' || key.front() > 'z' ||
                    !std::all_of(key.begin(), key.end(), [](char character) {
                        return (character >= 'a' && character <= 'z') ||
                               (character >= '0' && character <= '9') || character == '_';
                    })) fail("invalid_key_order");
                previous = key;
                take(':');
                value(depth + 1, key);
                if (at() == '}') { ++position_; break; }
                take(',');
            }
            return;
        }
        if (at() == '[') {
            ++position_;
            size_t count = 0;
            if (at() == ']') { ++position_; return; }
            while (true) {
                if (++count > 256) fail("array_limit");
                value(depth + 1);
                if (at() == ']') { ++position_; break; }
                take(',');
            }
            return;
        }
        if (at() == '"') {
            string(owner == "ciphertext" ? 15000000 : 256);
            return;
        }
        if (at() >= '0' && at() <= '9') {
            const int first = at();
            const size_t start = position_;
            uint64_t number = 0;
            while (at() >= '0' && at() <= '9') {
                if (position_ - start == 10) fail("number_limit");
                number = number * 10 + at() - '0';
                ++position_;
            }
            if (position_ - start > 1 && first == '0') fail("invalid_canonical");
            if (number > UINT32_MAX) fail("invalid_u32");
            return;
        }
        fail("invalid_canonical");
    }

public:
    explicit EnvelopeScanner(std::span<const uint8_t> input)
        : input_(reinterpret_cast<const char *>(input.data()), input.size()) {}
    void scan() {
        if (input_.size() > kMaxMaterialResponse) fail("response_size_limit");
        value(1);
        if (position_ != input_.size()) fail("invalid_canonical");
    }
};

json parseEnvelope(std::span<const uint8_t> bytes) {
    EnvelopeScanner(bytes).scan();
    const auto *begin = reinterpret_cast<const char *>(bytes.data());
    auto value = json::parse(begin, begin + bytes.size());
    const auto canonical = value.dump();
    if (canonical.size() != bytes.size() ||
        !std::equal(canonical.begin(), canonical.end(), bytes.begin()))
        fail("invalid_canonical");
    return value;
}

json parseSmallCanonical(std::span<const uint8_t> bytes, size_t maximum) {
    if (bytes.size() > maximum) fail("size_limit");
    auto decoded = decodeCanonical(bytes);
    if (auto *error = std::get_if<PackageError>(&decoded)) fail(error->code.c_str());
    return std::move(std::get<json>(decoded));
}

template<size_t N>
std::array<uint8_t, N> exactArray(const std::vector<uint8_t> &bytes) {
    if (bytes.size() != N) fail("invalid_length");
    std::array<uint8_t, N> result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

MaterialBinding expectedBinding(const json &binding) {
    auto parsed = parseMaterialBinding(binding);
    if (auto *error = std::get_if<PackageError>(&parsed)) fail(error->code.c_str());
    return std::get<MaterialBinding>(std::move(parsed));
}

template<class T, class F> std::variant<T, ProtocolError> guarded(F callback) {
    try {
        return callback();
    } catch (const ProtocolError &error) {
        return error;
    } catch (const PackageError &error) {
        return ProtocolError{error.code};
    } catch (const std::bad_alloc &) {
        return ProtocolError{"allocation_failed"};
    } catch (const json::exception &) {
        return ProtocolError{"invalid_schema"};
    }
}
} // namespace

VerifiedTrustBundle::VerifiedTrustBundle(Token, std::vector<SigningKey> keys,
                                         uint64_t trustEpoch,
                                         std::array<uint8_t, 32> counterEpoch,
                                         uint64_t issuedAtMs, uint64_t validUntilMs)
    : keys_(std::move(keys)), trust_epoch_(trustEpoch), counter_epoch_(counterEpoch),
      valid_until_ms_(validUntilMs) {
    (void)issuedAtMs;
}

PendingRequest::PendingRequest(std::vector<uint8_t> canonicalRequest,
                               std::array<uint8_t, 32> clientPrivateKey,
                               VerifiedTrustBundle trustBundle, ExpectedMaterial expected,
                               uint64_t sentBootNs, uint64_t receivedBootNs)
    : request_bytes_(std::move(canonicalRequest)), client_private_key_(clientPrivateKey),
      trust_bundle_(std::move(trustBundle)), expected_(std::move(expected)),
      sent_boot_ns_(sentBootNs), received_boot_ns_(receivedBootNs) {}

PendingRequest::~PendingRequest() {
    OPENSSL_cleanse(client_private_key_.data(), client_private_key_.size());
}

VerifiedPackage::~VerifiedPackage() {
    OPENSSL_cleanse(package_.bytecode.data(), package_.bytecode.size());
    OPENSSL_cleanse(package_.decode_map.data(),
                    package_.decode_map.size() * sizeof(package_.decode_map[0]));
}

struct ProtocolAccess {
    static VerifiedTrustBundle trust(std::span<const uint8_t> bytes,
                                     const InstalledTrust &installed) {
        auto bundle = parseSmallCanonical(bytes, kMaxTrustBundle);
        closed(bundle, {"body", "signature"});
        const auto &body = bundle.at("body");
        closed(body, {"format_version", "protocol_version", "software_id", "root_key_id",
                      "trust_epoch", "counter_epoch", "issued_at_ms", "valid_until_ms", "keys"});
        u32(body.at("format_version"), 1, 1);
        u32(body.at("protocol_version"), 2, 2);
        checkId(text(body.at("software_id")));
        checkId(text(body.at("root_key_id")));
        if (text(body.at("software_id")) != installed.software_id ||
            text(body.at("root_key_id")) != installed.root_key_id) fail("invalid_trust_bundle");
        const auto trustEpoch = u64(body.at("trust_epoch"));
        const auto issuedAt = u64(body.at("issued_at_ms"));
        const auto validUntil = u64(body.at("valid_until_ms"));
        if (!trustEpoch || issuedAt >= validUntil || installed.trusted_upper_ms < installed.trusted_lower_ms ||
            installed.trusted_upper_ms - installed.trusted_lower_ms > 5000 ||
            installed.trusted_lower_ms < issuedAt || installed.trusted_upper_ms >= validUntil)
            fail("invalid_trust_bundle");
        const auto counterEpoch = unhex32(text(body.at("counter_epoch")));
        if (std::all_of(counterEpoch.begin(), counterEpoch.end(), [](uint8_t value) { return value == 0; }))
            fail("invalid_trust_bundle");
        const auto &keyArray = body.at("keys");
        if (!keyArray.is_array() || keyArray.empty() || keyArray.size() > 64)
            fail("invalid_trust_bundle");
        std::vector<VerifiedTrustBundle::SigningKey> keys;
        std::string previous;
        for (const auto &key : keyArray) {
            closed(key, {"key_id", "public_key", "not_before_ms", "signing_until_ms",
                         "not_after_ms", "status"});
            const auto keyId = text(key.at("key_id"));
            checkId(keyId);
            if (keyId <= previous) fail("invalid_trust_bundle");
            previous = keyId;
            const auto publicKey = exactArray<32>(base64(key.at("public_key"), 32));
            const auto notBefore = u64(key.at("not_before_ms"));
            const auto signingUntil = u64(key.at("signing_until_ms"));
            const auto notAfter = u64(key.at("not_after_ms"));
            const auto status = text(key.at("status"));
            if (!(notBefore < signingUntil && signingUntil <= notAfter) ||
                (status != "active" && status != "retired" && status != "revoked"))
                fail("invalid_trust_bundle");
            keys.push_back({keyId, publicKey, notBefore, signingUntil, notAfter, status});
        }
        const auto bodyBytesText = body.dump();
        const auto bodyBytes = std::span(reinterpret_cast<const uint8_t *>(bodyBytesText.data()),
                                         bodyBytesText.size());
        const auto input = frame("XOVM2/trust-bundle", {bodyBytes});
        const auto signature = exactArray<64>(base64(bundle.at("signature"), 64));
        if (!ed25519Verify(installed.root_public_key, input, signature)) fail("bad_signature");
        return VerifiedTrustBundle(VerifiedTrustBundle::Token{}, std::move(keys), trustEpoch,
                                   counterEpoch, issuedAt, validUntil);
    }

    static VerifiedPackage authenticate(std::span<const uint8_t> response,
                                        PendingRequest &pending) {
        if (pending.consumed_) fail("invalid_pending_request");
        pending.consumed_ = true;
        PrivateKeyCopy clientPrivateKey{pending.client_private_key_};
        OPENSSL_cleanse(pending.client_private_key_.data(), pending.client_private_key_.size());
        auto request = parseSmallCanonical(pending.request_bytes_, kMaxRequest);
        closed(request, {"protocol_version", "suite", "type", "software_id", "build_id",
                         "final_artifact_hash", "request_id", "client_nonce", "client_ephemeral_key",
                         "session_id", "counter_epoch", "region_id", "engine_abi_hash", "mode",
                         "previous_generation"});
        if (u32(request.at("protocol_version"), 2, 2) != 2 ||
            text(request.at("suite")) != kSuite || text(request.at("type")) != "material.issue")
            fail("invalid_request");
        if (text(request.at("software_id")) != pending.expected_.software_id ||
            text(request.at("build_id")) != pending.expected_.build_id ||
            text(request.at("final_artifact_hash")) != pending.expected_.final_artifact_hash ||
            text(request.at("session_id")) != pending.expected_.session_id ||
            text(request.at("counter_epoch")) != pending.expected_.counter_epoch ||
            text(request.at("region_id")) != pending.expected_.region_id ||
            text(request.at("engine_abi_hash")) != pending.expected_.engine_abi_hash ||
            text(request.at("mode")) != pending.expected_.mode)
            fail("request_mismatch");
        const auto requestHash = sha256(frame("XOVM2/request", {pending.request_bytes_}));

        auto envelope = parseEnvelope(response);
        closed(envelope, {"transcript", "ciphertext", "tag", "signature"});
        const auto &transcript = envelope.at("transcript");
        closed(transcript, {"protocol_version", "suite", "type", "software_id", "build_id",
                            "final_artifact_hash", "request_id", "request_hash", "client_nonce",
                            "client_ephemeral_key", "server_nonce", "server_ephemeral_key",
                            "server_key_id", "trust_epoch", "session_id", "counter_epoch", "counter",
                            "issued_at_ms", "auth_valid_until_ms", "session_valid_until_ms",
                            "accept_for_ms", "payload_hash", "binding"});
        if (u32(transcript.at("protocol_version"), 2, 2) != 2 ||
            text(transcript.at("suite")) != kSuite ||
            text(transcript.at("type")) != text(request.at("type"))) fail("response_mismatch");
        for (const char *field : {"software_id", "build_id", "final_artifact_hash", "request_id",
                                  "client_nonce", "client_ephemeral_key", "session_id", "counter_epoch"})
            if (transcript.at(field) != request.at(field)) fail("response_mismatch");
        if (text(transcript.at("software_id")) != pending.expected_.software_id ||
            text(transcript.at("build_id")) != pending.expected_.build_id ||
            text(transcript.at("final_artifact_hash")) != pending.expected_.final_artifact_hash ||
            text(transcript.at("session_id")) != pending.expected_.session_id ||
            text(transcript.at("counter_epoch")) != pending.expected_.counter_epoch ||
            text(transcript.at("request_hash")) != hex(requestHash)) fail("response_mismatch");
        if (u64(transcript.at("trust_epoch")) != pending.trust_bundle_.trust_epoch_ ||
            unhex32(text(transcript.at("counter_epoch"))) != pending.trust_bundle_.counter_epoch_)
            fail("counter_epoch_mismatch");
        const auto keyId = text(transcript.at("server_key_id"));
        const auto found = std::find_if(pending.trust_bundle_.keys_.begin(),
            pending.trust_bundle_.keys_.end(), [&](const auto &key) { return key.key_id == keyId; });
        if (found == pending.trust_bundle_.keys_.end()) fail("unknown_key_id");
        if (found->status == "revoked") fail("revoked_key");
        const auto issuedAt = u64(transcript.at("issued_at_ms"));
        const auto acceptForMs = u32(transcript.at("accept_for_ms"), 1, 120000);
        if (issuedAt < found->not_before_ms || issuedAt >= found->signing_until_ms ||
            issuedAt > UINT64_MAX - acceptForMs || issuedAt + acceptForMs > found->not_after_ms ||
            issuedAt + acceptForMs > pending.trust_bundle_.valid_until_ms_)
            fail("key_unavailable");
        const auto ciphertext = base64(envelope.at("ciphertext"), SIZE_MAX, kMaxCiphertext);
        const auto tag = exactArray<16>(base64(envelope.at("tag"), 16));
        const auto signature = exactArray<64>(base64(envelope.at("signature"), 64));
        const auto transcriptText = transcript.dump();
        const auto transcriptBytes = std::span(
            reinterpret_cast<const uint8_t *>(transcriptText.data()), transcriptText.size());
        const auto signatureInput = frame("XOVM2/signature", {transcriptBytes, ciphertext, tag});
        if (!ed25519Verify(found->public_key, signatureInput, signature)) fail("bad_signature");

        const auto serverPublic = exactArray<32>(base64(transcript.at("server_ephemeral_key"), 32));
        auto shared = x25519(clientPrivateKey.bytes, serverPublic);
        std::vector<uint8_t> key;
        std::vector<uint8_t> iv;
        std::vector<uint8_t> plaintext;
        try {
            const auto transcriptHash = sha256(frame("XOVM2/transcript", {transcriptBytes}));
            const auto keyInfo = frame("XOVM2/response-key", {transcriptHash});
            const auto ivInfo = frame("XOVM2/response-iv", {transcriptHash});
            key = hkdf(shared, transcriptHash, keyInfo, 32);
            iv = hkdf(shared, transcriptHash, ivInfo, 12);
            const auto aad = frame("XOVM2/aad", {transcriptBytes});
            plaintext = decrypt(exactArray<32>(key), exactArray<12>(iv), aad, ciphertext, tag);
            if (hex(sha256(plaintext)) != text(transcript.at("payload_hash")))
                fail("payload_hash_mismatch");
            auto binding = expectedBinding(transcript.at("binding"));
            if (binding.build_id != pending.expected_.build_id ||
                binding.region_id != pending.expected_.region_id ||
                binding.session_id != pending.expected_.session_id ||
                binding.request_hash != hex(requestHash) || binding.mode != pending.expected_.mode ||
                binding.engine_abi_hash != pending.expected_.engine_abi_hash)
                fail("binding_mismatch");
            auto parsed = parseExecutionPackage(plaintext, binding);
            if (auto *error = std::get_if<PackageError>(&parsed)) fail(error->code.c_str());
            const auto &package = std::get<ParsedPackage>(parsed);
            if (package.binding.generation <= u64(request.at("previous_generation")))
                fail("generation_replay");
            if ((package.binding.mode == "session" && package.binding.lease_ms != 0) ||
                (package.binding.mode == "lease" && package.binding.lease_ms != acceptForMs))
                fail("binding_mismatch");
            const auto authUntil = u64(transcript.at("auth_valid_until_ms"));
            const auto sessionUntil = u64(transcript.at("session_valid_until_ms"));
            if (issuedAt >= authUntil || issuedAt >= sessionUntil ||
                issuedAt + acceptForMs > authUntil || issuedAt + acceptForMs > sessionUntil ||
                pending.sent_boot_ns_ > UINT64_MAX - static_cast<uint64_t>(acceptForMs) * 1000000 ||
                pending.received_boot_ns_ >= pending.sent_boot_ns_ +
                                             static_cast<uint64_t>(acceptForMs) * 1000000)
                fail("expired_response");
            auto result = VerifiedPackage(VerifiedPackage::Token{},
                std::get<ParsedPackage>(std::move(parsed)), pending.sent_boot_ns_,
                pending.received_boot_ns_);
            OPENSSL_cleanse(shared.data(), shared.size());
            OPENSSL_cleanse(key.data(), key.size());
            OPENSSL_cleanse(iv.data(), iv.size());
            OPENSSL_cleanse(plaintext.data(), plaintext.size());
            return result;
        } catch (...) {
            OPENSSL_cleanse(shared.data(), shared.size());
            OPENSSL_cleanse(key.data(), key.size());
            OPENSSL_cleanse(iv.data(), iv.size());
            OPENSSL_cleanse(plaintext.data(), plaintext.size());
            throw;
        }
    }
};

TrustBundleResult verifyTrustBundle(std::span<const uint8_t> bytes,
                                    const InstalledTrust &installed) {
    return guarded<VerifiedTrustBundle>([&] { return ProtocolAccess::trust(bytes, installed); });
}

AuthenticationResult authenticateResponse(std::span<const uint8_t> response,
                                           PendingRequest &pending) {
    return guarded<VerifiedPackage>([&] { return ProtocolAccess::authenticate(response, pending); });
}

} // namespace xovm::material
