#include "protocol_service.h"

#include <openssl/evp.h>
#include <limits>

namespace xovm::cloud_material {
namespace {

using Json = nlohmann::json;

std::string hexBytes(std::span<const std::uint8_t> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (auto byte : bytes) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}

std::string base64Bytes(std::span<const std::uint8_t> bytes) {
    std::string result(4 * ((bytes.size() + 2) / 3), '\0');
    const int size = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(result.data()),
                                     bytes.data(), static_cast<int>(bytes.size()));
    if (size < 0) throw xovm::cloud_material::BackendError{"key_unavailable"};
    result.resize(static_cast<size_t>(size));
    return result;
}

std::vector<std::uint8_t> randomExact(const xovm::cloud_material::ProtocolService::RandomBytes &random,
                                      size_t size) {
    if (!random) throw xovm::cloud_material::BackendError{"key_unavailable"};
    auto result = random(size);
    if (const auto *error = std::get_if<xovm::cloud_material::BackendError>(&result)) throw *error;
    auto bytes = std::get<xovm::cloud_material::Bytes>(std::move(result));
    if (bytes.size() != size) throw xovm::cloud_material::BackendError{"key_unavailable"};
    std::vector<std::uint8_t> output;
    output.reserve(size);
    for (auto byte : bytes) output.push_back(std::to_integer<std::uint8_t>(byte));
    if (std::all_of(output.begin(), output.end(), [](auto byte) { return byte == 0; }))
        throw xovm::cloud_material::BackendError{"key_unavailable"};
    return output;
}

std::array<std::uint8_t, 32> publicX25519(std::span<const std::uint8_t, 32> privateKey) {
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(nullptr, "X25519", nullptr,
                                                     privateKey.data(), privateKey.size());
    std::array<std::uint8_t, 32> output{};
    size_t size = output.size();
    if (!key || EVP_PKEY_get_raw_public_key(key, output.data(), &size) != 1 || size != output.size()) {
        EVP_PKEY_free(key);
        throw xovm::cloud_material::BackendError{"key_unavailable"};
    }
    EVP_PKEY_free(key);
    return output;
}

std::uint64_t checkedAdd(std::uint64_t left, std::uint64_t right) {
    if (left > UINT64_MAX - right) throw xovm::cloud_material::BackendError{"counter_exhausted"};
    return left + right;
}

std::string u64(std::uint64_t value) { return std::to_string(value); }

std::string sha256Hex(std::span<const std::byte> bytes) {
    std::array<std::uint8_t, 32> digest{};
    unsigned int length = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), digest.data(), &length, EVP_sha256(), nullptr) != 1 ||
        length != digest.size()) throw BackendError{"key_unavailable"};
    return hexBytes(digest);
}
}

namespace {
std::string requestDigest(std::span<const std::byte> bytes) {
    std::vector<std::uint8_t> framed{'X','O','V','M','2','/','r','e','q','u','e','s','t',0};
    const auto size = static_cast<std::uint32_t>(bytes.size());
    framed.insert(framed.end(), {static_cast<std::uint8_t>(size >> 24),
        static_cast<std::uint8_t>(size >> 16), static_cast<std::uint8_t>(size >> 8),
        static_cast<std::uint8_t>(size)});
    for (std::byte value : bytes) framed.push_back(std::to_integer<std::uint8_t>(value));
    std::array<std::uint8_t, 32> digest{};
    unsigned int length = 0;
    if (EVP_Digest(framed.data(), framed.size(), digest.data(), &length,
                   EVP_sha256(), nullptr) != 1 || length != digest.size())
        throw BackendError{"key_unavailable"};
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (auto byte : digest) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 15]);
    }
    return result;
}
}

std::variant<Bytes, BackendError> ProtocolService::handle(
    std::span<const std::byte> requestBytes, const std::string &relayCredential) {
    auto parsed = parseCanonicalRequest(requestBytes);
    if (const auto *error = std::get_if<BackendError>(&parsed)) return *error;
    if (!providers_.relay_authenticator || !providers_.anonymous_policy ||
        !providers_.snapshots || !providers_.state || !providers_.trusted_now ||
        (!providers_.build_payload && !providers_.issue &&
        !providers_.authorize_control))
        return BackendError{"authority_unavailable"};
    const auto &request = std::get<Request>(parsed);
    RequestFacts facts;
    try {
        const auto &value = request.value;
        facts.request_id = value.at("request_id").get<std::string>();
        facts.request_digest = requestDigest(requestBytes);
        facts.software_id = value.at("software_id").get<std::string>();
        facts.build_id = value.at("build_id").get<std::string>();
        facts.final_artifact_hash = value.at("final_artifact_hash").get<std::string>();
        facts.type = value.at("type").get<std::string>();
        if (facts.type == "material.issue") {
            facts.region_id = value.at("region_id").get<std::string>();
            facts.mode = value.at("mode").get<std::string>();
        }
    } catch (...) {
        return BackendError{"invalid_request"};
    }
    std::variant<std::uint64_t, BackendError> time = BackendError{"authority_unavailable"};
    try { time = providers_.trusted_now(); } catch (...) { }
    if (const auto *error = std::get_if<BackendError>(&time)) return *error;
    const auto now = std::get<std::uint64_t>(time);
    if (facts.mode == "operation") return BackendError{"operation_not_implemented"};
    auto relayGrant = providers_.relay_authenticator->authenticate(relayCredential, facts, now);
    if (const auto *error = std::get_if<BackendError>(&relayGrant)) return *error;
    auto snapshot = providers_.snapshots->acquire();
    if (!snapshot || !providers_.snapshots->ready()) return BackendError{"authority_unavailable"};
    auto reservationResult = providers_.anonymous_policy->reserve(*snapshot, facts, now, 1);
    if (const auto *error = std::get_if<BackendError>(&reservationResult)) return *error;
    auto reservation = std::get<AnonymousPolicy::Reservation>(std::move(reservationResult));
    const auto &grant = reservation.grant();
    auto issue = providers_.issue;
    std::variant<Bytes, BackendError> result;
    if (!providers_.build_payload && facts.type == "material.issue") {
        result = handle(request, grant, *providers_.snapshots,
                        *providers_.state, now, issue, snapshot);
    } else {
        result = handle(request, grant, *providers_.snapshots, *providers_.state, now,
                   [this, &facts, &grant, snapshot, now](const Request &request, const AnonymousGrant &,
                                  SessionState::Transaction &tx) -> std::variant<Bytes, BackendError> {
        try {
            auto random = [this](size_t size) { return providers_.random_bytes(size); };
            if (facts.type != "material.issue") {
                if (!providers_.authorize_control || !providers_.random_bytes)
                    return BackendError{"authority_unavailable"};
                auto authorization = providers_.authorize_control(request, facts, now);
                if (const auto *error = std::get_if<BackendError>(&authorization)) return *error;
                const auto control = std::get<ControlAuthorization>(authorization);
                if (control.counter_epoch.size() != 64 ||
                    !std::all_of(control.counter_epoch.begin(), control.counter_epoch.end(),
                        [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }) ||
                    control.auth_valid_until_ms <= now ||
                    control.auth_valid_until_ms > grant.valid_until_ms_ ||
                    (facts.type != "session.close" &&
                     (!control.control_valid_for_ms || control.control_valid_for_ms > 86400000)))
                    return BackendError{"authority_unavailable"};
                auto issuedAtResult = providers_.trusted_now();
                if (const auto *error = std::get_if<BackendError>(&issuedAtResult)) return *error;
                const auto issuedAt = std::get<std::uint64_t>(issuedAtResult);
                if (issuedAt >= control.auth_valid_until_ms) return BackendError{"unauthorized"};
                const auto ttl = facts.type == "session.close" ? 0u :
                    static_cast<std::uint32_t>(std::min<std::uint64_t>(
                        control.control_valid_for_ms, control.auth_valid_until_ms - issuedAt));
                if (facts.type != "session.close" && !ttl) return BackendError{"unauthorized"};
                auto serverPrivate = randomExact(random, 32);
                auto serverNonce = randomExact(random, 32);
                const auto serverPublic = publicX25519(
                    std::span<const std::uint8_t, 32>(serverPrivate.data(), 32));
                std::string sessionId, epoch = control.counter_epoch;
                if (facts.type == "session.open") {
                    const auto randomId = randomExact(random, 32);
                    sessionId = hexBytes(randomId);
                } else {
                    sessionId = request.value.at("session_id").get<std::string>();
                    epoch = request.value.at("counter_epoch").get<std::string>();
                    if (epoch != control.counter_epoch) return BackendError{"counter_epoch_mismatch"};
                }
                const auto serverPublicBase64 = base64Bytes(serverPublic);
                const auto serverNonceHex = hexBytes(serverNonce);
                StateResult stateResult;
                if (facts.type == "session.open") {
                    stateResult = tx.openSession(sessionId, epoch, issuedAt + ttl, serverNonceHex,
                        serverPublicBase64, request.value.at("client_nonce").get<std::string>(),
                        request.value.at("client_ephemeral_key").get<std::string>());
                } else {
                    const auto requestSessionId = request.value.at("session_id").get<std::string>();
                    const auto close = facts.type == "session.close";
                    stateResult = tx.controlSession(requestSessionId, epoch, issuedAt,
                        close ? issuedAt : issuedAt + ttl, close, serverNonceHex,
                        serverPublicBase64, request.value.at("client_nonce").get<std::string>(),
                        request.value.at("client_ephemeral_key").get<std::string>());
                }
                if (stateResult.counter_epoch != epoch || stateResult.session_id != sessionId)
                    return BackendError{"unauthorized"};
                Json payload{{"format_version", 1}, {"session_id", sessionId},
                    {"counter_epoch", epoch}, {"control_valid_for_ms", ttl},
                    {"session_valid_until_ms", u64(stateResult.valid_until_ms)}};
                const auto payloadText = payload.dump();
                Bytes payloadBytes;
                for (unsigned char c : payloadText) payloadBytes.push_back(static_cast<std::byte>(c));
                const auto controlWindow = facts.type == "session.close"
                    ? UINT64_MAX : control.control_valid_for_ms;
                const auto signingWindow = providers_.signing.not_after_ms > issuedAt
                    ? providers_.signing.not_after_ms - issuedAt : 0;
                const auto bundleWindow = providers_.signing.bundle_valid_until_ms > issuedAt
                    ? providers_.signing.bundle_valid_until_ms - issuedAt : 0;
                const auto acceptWindow = std::min<std::uint64_t>(120000, controlWindow);
                const auto acceptFor = static_cast<std::uint32_t>(std::min(
                    acceptWindow, std::min(control.auth_valid_until_ms - issuedAt,
                                           std::min(signingWindow, bundleWindow))));
                if (!acceptFor || !providers_.signing.available())
                    return BackendError{"key_unavailable"};
                Json binding{{"session_id", sessionId}, {"request_hash", facts.request_digest},
                    {"control_valid_for_ms", ttl}};
                Json transcript{{"protocol_version", 2}, {"suite", kProtocolSuite},
                    {"type", facts.type}, {"software_id", facts.software_id},
                    {"build_id", facts.build_id}, {"final_artifact_hash", facts.final_artifact_hash},
                    {"request_id", facts.request_id}, {"request_hash", facts.request_digest},
                    {"client_nonce", request.value.at("client_nonce")},
                    {"client_ephemeral_key", request.value.at("client_ephemeral_key")},
                    {"server_nonce", serverNonceHex}, {"server_ephemeral_key", serverPublicBase64},
                    {"server_key_id", providers_.signing.key_id},
                    {"trust_epoch", u64(providers_.signing.trust_epoch)},
                    {"session_id", sessionId}, {"counter_epoch", epoch},
                    {"counter", u64(stateResult.counter)}, {"issued_at_ms", u64(issuedAt)},
                    {"auth_valid_until_ms", u64(control.auth_valid_until_ms)},
                    {"session_valid_until_ms", u64(stateResult.valid_until_ms)},
                    {"accept_for_ms", acceptFor}, {"payload_hash", sha256Hex(payloadBytes)},
                    {"binding", binding}};
                std::array<std::uint8_t, 36> decoded{};
                const auto encodedClient = request.value.at("client_ephemeral_key").get<std::string>();
                const int decodedLength = EVP_DecodeBlock(decoded.data(),
                    reinterpret_cast<const unsigned char *>(encodedClient.data()),
                    static_cast<int>(encodedClient.size()));
                const auto padding = encodedClient.ends_with("==") ? 2 :
                    encodedClient.ends_with("=") ? 1 : 0;
                if (decodedLength < 0 || decodedLength - padding != 32)
                    return BackendError{"invalid_key"};
                std::array<std::uint8_t, 32> clientPublic{};
                std::copy_n(decoded.begin(), clientPublic.size(), clientPublic.begin());
                std::array<std::uint8_t, 32> privateArray{};
                std::copy(serverPrivate.begin(), serverPrivate.end(), privateArray.begin());
                auto sealed = sealResponse(transcript, payloadBytes, clientPublic, privateArray,
                                           providers_.sign);
                OPENSSL_cleanse(serverPrivate.data(), serverPrivate.size());
                if (const auto *error = std::get_if<BackendError>(&sealed)) return *error;
                return std::get<Bytes>(std::move(sealed));
            }
            auto serverPrivate = randomExact(random, 32);
            auto serverNonce = randomExact(random, 32);
            const auto serverPublic = publicX25519(std::span<const std::uint8_t, 32>(
                serverPrivate.data(), 32));
            auto payload = providers_.build_payload(request, facts, *snapshot, tx);
            if (const auto *error = std::get_if<BackendError>(&payload)) return *error;
            auto issued = std::get<IssuedPayload>(std::move(payload));
            const auto issuedAt = std::get<std::uint64_t>(providers_.trusted_now());
            const auto responseWindow = std::min<std::uint64_t>(120000,
                issuedAt < issued.session_valid_until_ms ? issued.session_valid_until_ms - issuedAt : 0);
            if (!responseWindow || !providers_.signing.available() ||
                providers_.signing.not_after_ms <= issuedAt ||
                providers_.signing.bundle_valid_until_ms <= issuedAt)
                return BackendError{"key_unavailable"};
            const auto acceptFor = static_cast<std::uint32_t>(std::min<std::uint64_t>(responseWindow,
                std::min(providers_.signing.not_after_ms - issuedAt,
                         providers_.signing.bundle_valid_until_ms - issuedAt)));
            if (!acceptFor) return BackendError{"key_unavailable"};
            const auto serverPublicBase64 = base64Bytes(serverPublic);
            const auto serverNonceHex = hexBytes(serverNonce);
            tx.claimServer(serverNonceHex, serverPublicBase64);
            const auto payloadText = issued.payload.dump();
            std::vector<std::byte> payloadBytes;
            for (unsigned char byte : payloadText) payloadBytes.push_back(static_cast<std::byte>(byte));
            Json transcript{{"protocol_version", 2}, {"suite", kProtocolSuite},
                {"type", facts.type}, {"software_id", facts.software_id},
                {"build_id", facts.build_id}, {"final_artifact_hash", facts.final_artifact_hash},
                {"request_id", facts.request_id}, {"request_hash", facts.request_digest},
                {"client_nonce", request.value.at("client_nonce")},
                {"client_ephemeral_key", request.value.at("client_ephemeral_key")},
                {"server_nonce", serverNonceHex},
                {"server_ephemeral_key", serverPublicBase64},
                {"server_key_id", providers_.signing.key_id},
                {"trust_epoch", u64(providers_.signing.trust_epoch)},
                {"session_id", issued.session_id}, {"counter_epoch", issued.counter_epoch},
                {"counter", u64(issued.counter)}, {"issued_at_ms", u64(issuedAt)},
                {"auth_valid_until_ms", u64(std::min(grant.valid_until_ms_, issuedAt + acceptFor))},
                {"session_valid_until_ms", u64(issued.session_valid_until_ms)},
                {"accept_for_ms", acceptFor}, {"payload_hash", sha256Hex(payloadBytes)},
                {"binding", issued.binding}};
            std::array<std::uint8_t, 32> privateArray{};
            std::copy(serverPrivate.begin(), serverPrivate.end(), privateArray.begin());
            std::array<std::uint8_t, 36> decodedClientPublic{};
            const auto decoded = request.value.at("client_ephemeral_key").get<std::string>();
            const int decodedSize = EVP_DecodeBlock(decodedClientPublic.data(),
                reinterpret_cast<const unsigned char *>(decoded.data()),
                static_cast<int>(decoded.size()));
            const auto padding = decoded.ends_with("==") ? 2 : decoded.ends_with("=") ? 1 : 0;
            if (decodedSize < 0 || static_cast<std::size_t>(decodedSize - padding) != 32)
                return BackendError{"invalid_key"};
            std::array<std::uint8_t, 32> clientPublic{};
            std::copy_n(decodedClientPublic.begin(), clientPublic.size(), clientPublic.begin());
            auto sealed = sealResponse(transcript, payloadBytes, clientPublic, privateArray,
                                       providers_.sign);
            OPENSSL_cleanse(serverPrivate.data(), serverPrivate.size());
            if (const auto *error = std::get_if<BackendError>(&sealed)) return *error;
            return std::get<Bytes>(std::move(sealed));
        } catch (const BackendError &error) {
            return error;
        } catch (const std::runtime_error &error) {
            static constexpr std::array<std::string_view, 10> stateErrors = {
                "request_conflict", "session_closed", "unauthorized", "replay_detected",
                "counter_exhausted", "state_capacity", "commit_failed", "invalid_key",
                "state_failed", "build_unavailable"};
            const std::string_view code(error.what());
            if (std::find(stateErrors.begin(), stateErrors.end(), code) != stateErrors.end())
                return BackendError{std::string(code)};
            return BackendError{"key_unavailable"};
        } catch (...) {
            return BackendError{"key_unavailable"};
        }
                   }, snapshot);
    }
    if (std::holds_alternative<BackendError>(result)) return result;
    if (!reservation.commit()) return BackendError{"build_unavailable"};
    return result;
}

std::variant<std::monostate, BackendError> ProtocolService::authorizeMode(
    const RequestFacts &facts) const {
    if (facts.mode == "operation") return BackendError{"operation_not_implemented"};
    return std::monostate{};
}

std::variant<Bytes, BackendError> ProtocolService::handle(
    const Request &request, const AnonymousGrant &grant, SnapshotManager &snapshots,
    SessionState &state, std::uint64_t trustedNow, const Issue &issue,
    SnapshotManager::SnapshotHandle snapshot) {
    RequestFacts facts;
    const auto &value = request.value;
    try {
        facts.request_id = value.at("request_id").get<std::string>();
        facts.request_digest = grant.request_digest_;
        facts.software_id = value.at("software_id").get<std::string>();
        facts.build_id = value.at("build_id").get<std::string>();
        facts.final_artifact_hash = value.at("final_artifact_hash").get<std::string>();
        facts.type = value.at("type").get<std::string>();
        if (facts.type == "material.issue") {
            facts.region_id = value.at("region_id").get<std::string>();
            facts.mode = value.at("mode").get<std::string>();
        }
    } catch (...) {
        return BackendError{"invalid_request"};
    }
    if (facts.type == "material.issue") {
        auto mode = authorizeMode(facts);
        if (const auto *error = std::get_if<BackendError>(&mode)) return *error;
    }
    if (!snapshot) snapshot = snapshots.acquire();
    auto guard = snapshots.beginIssuance(snapshot, facts.build_id);
    if (!guard) return BackendError{"build_unavailable"};
    if (grant.build_id_ != facts.build_id || grant.valid_until_ms_ <= trustedNow ||
        (facts.type == "material.issue" && !grant.scopes_.contains("material.issue")) ||
        (facts.type != "material.issue" && !grant.scopes_.contains("session.control")))
        return BackendError{"unauthorized"};
    auto stateResult = state.transact(facts, grant, trustedNow, [&](SessionState::Transaction &tx) {
        auto response = issue(request, grant, tx);
        if (const auto *error = std::get_if<BackendError>(&response))
            throw std::runtime_error(error->code);
        auto bytes = std::get<Bytes>(std::move(response));
        tx.setResponse(bytes);
        return StateResult{};
    });
    if (const auto *error = std::get_if<BackendError>(&stateResult)) return *error;
    guard.finishCommit();
    return std::get<StateResult>(stateResult).response;
}

} // namespace xovm::cloud_material
