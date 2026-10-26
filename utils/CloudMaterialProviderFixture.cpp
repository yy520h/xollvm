#include "runtime_providers.h"

#include <openssl/evp.h>
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace xovm::cloud_material {
namespace {

std::string hex(std::span<const std::uint8_t> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}

std::variant<xovm::material::WindowMaterial, BackendError> buildWindowMaterial(
    const xovm::material::WindowAcquireRequest &request) {
    const auto encoded = xovm::material::encodeWindowAcquireRequest(request);
    if (encoded.empty()) return BackendError{"window_material_unavailable"};

    auto derive = [&encoded](std::uint8_t domain)
        -> std::variant<std::array<std::uint8_t, 32>, BackendError> {
        constexpr std::string_view label = "XOVM2/fixture-window-material";
        std::vector<std::uint8_t> input(label.begin(), label.end());
        input.push_back(0);
        input.push_back(domain);
        input.insert(input.end(), encoded.begin(), encoded.end());
        std::array<std::uint8_t, 32> digest{};
        unsigned digestSize = 0;
        if (EVP_Digest(input.data(), input.size(), digest.data(), &digestSize,
                       EVP_sha256(), nullptr) != 1 ||
            digestSize != digest.size())
            return BackendError{"window_material_unavailable"};
        return digest;
    };

    xovm::material::WindowMaterial material{};
    std::array<std::array<std::uint8_t, 32> *, 6> fields = {
        &material.window, &material.permutation, &material.decode,
        &material.chaff, &material.integrity, &material.jit};
    for (std::uint8_t domain = 0; domain < fields.size(); ++domain) {
        auto value = derive(domain);
        if (const auto *error = std::get_if<BackendError>(&value)) return *error;
        *fields[domain] = std::get<std::array<std::uint8_t, 32>>(std::move(value));
    }
    return material;
}

std::string packageHash(nlohmann::json package) {
    package.at("binding").erase("package_hash");
    const auto text = package.dump();
    std::vector<std::uint8_t> input;
    constexpr std::string_view label = "XOVM2/package";
    input.insert(input.end(), label.begin(), label.end());
    input.push_back(0);
    const auto size = static_cast<std::uint32_t>(text.size());
    input.insert(input.end(), {static_cast<std::uint8_t>(size >> 24),
                               static_cast<std::uint8_t>(size >> 16),
                               static_cast<std::uint8_t>(size >> 8),
                               static_cast<std::uint8_t>(size)});
    input.insert(input.end(), text.begin(), text.end());
    std::array<std::uint8_t, 32> digest{};
    unsigned digestSize = 0;
    if (EVP_Digest(input.data(), input.size(), digest.data(), &digestSize, EVP_sha256(), nullptr) != 1 ||
        digestSize != digest.size())
        throw BackendError{"key_unavailable"};
    return hex(digest);
}

std::string base64(std::span<const std::uint8_t> bytes) {
    std::string result(4 * ((bytes.size() + 2) / 3), '\0');
    const auto size = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(result.data()),
                                       bytes.data(), static_cast<int>(bytes.size()));
    if (size < 0) throw BackendError{"key_unavailable"};
    result.resize(static_cast<std::size_t>(size));
    return result;
}

constexpr std::array<std::uint8_t, 32> kSigningSeed = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
constexpr std::array<std::uint8_t, 32> kRootSeed = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};

std::array<std::uint8_t, 32> edPublic(std::span<const std::uint8_t, 32> seed) {
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(nullptr, "ED25519", nullptr,
                                                    seed.data(), seed.size());
    std::array<std::uint8_t, 32> result{};
    size_t size = result.size();
    if (!key || EVP_PKEY_get_raw_public_key(key, result.data(), &size) != 1 || size != result.size()) {
        EVP_PKEY_free(key);
        throw BackendError{"key_unavailable"};
    }
    EVP_PKEY_free(key);
    return result;
}

std::array<std::uint8_t, 64> edSign(std::span<const std::uint8_t> message,
                                    std::span<const std::uint8_t, 32> seed) {
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(nullptr, "ED25519", nullptr,
                                                    seed.data(), seed.size());
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    std::array<std::uint8_t, 64> result{};
    size_t size = result.size();
    const bool ok = key && context && EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key) == 1 &&
        EVP_DigestSign(context, result.data(), &size, message.data(), message.size()) == 1 &&
        size == result.size();
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    if (!ok) throw BackendError{"key_unavailable"};
    return result;
}

std::vector<std::uint8_t> trustBundle() {
    const auto signingPublic = edPublic(kSigningSeed);
    nlohmann::json body{
        {"format_version", 1}, {"protocol_version", 2}, {"software_id", "fixture.software"},
        {"root_key_id", "fixture-root-key"}, {"trust_epoch", "1"},
        {"counter_epoch", std::string(64, 'e')}, {"issued_at_ms", "1000"},
        {"valid_until_ms", "900000"}, {"keys", nlohmann::json::array({nlohmann::json{
            {"key_id", "fixture-key"}, {"public_key", base64(signingPublic)},
            {"not_before_ms", "1000"}, {"signing_until_ms", "900000"},
            {"not_after_ms", "900000"}, {"status", "active"}}})}};
    const auto bodyText = body.dump();
    std::vector<std::uint8_t> bodyBytes(bodyText.begin(), bodyText.end());
    std::vector<std::uint8_t> input{'X','O','V','M','2','/','t','r','u','s','t','-','b','u','n','d','l','e',0};
    const auto size = static_cast<std::uint32_t>(bodyBytes.size());
    input.insert(input.end(), {static_cast<std::uint8_t>(size >> 24),
                               static_cast<std::uint8_t>(size >> 16),
                               static_cast<std::uint8_t>(size >> 8),
                               static_cast<std::uint8_t>(size)});
    input.insert(input.end(), bodyBytes.begin(), bodyBytes.end());
    const auto signature = edSign(input, kRootSeed);
    nlohmann::json bundle{{"body", body}, {"signature", base64(signature)}};
    const auto encoded = bundle.dump();
    return std::vector<std::uint8_t>(encoded.begin(), encoded.end());
}

RuntimeProviderBundle provider(ProviderRole role) {
    RuntimeProviderBundle result;
    if (role == ProviderRole::trusted_time) {
        result.trusted_now = [] {
            return std::variant<std::uint64_t, BackendError>(std::uint64_t{1000});
        };
        return result;
    }
    if (role == ProviderRole::signing_key) {
        auto sequence = std::make_shared<std::uint8_t>(7);
        result.random_bytes = [sequence](std::size_t size) {
            const auto value = (*sequence)++;
            return std::variant<Bytes, BackendError>(Bytes(size, static_cast<std::byte>(value)));
        };
        result.sign = [](std::span<const std::uint8_t> message) {
            try {
                return std::variant<std::array<std::uint8_t, 64>, BackendError>(
                    edSign(message, kSigningSeed));
            } catch (const BackendError &error) {
                return std::variant<std::array<std::uint8_t, 64>, BackendError>(error);
            }
        };
        result.signing.key_id = "fixture-key";
        result.signing.trust_epoch = 1;
        result.signing.not_after_ms = 1000000;
        result.signing.bundle_valid_until_ms = 1000000;
        return result;
    }
    if (role == ProviderRole::anonymous_policy) {
        result.validate_pair = [](const ImportRecord &, std::string &) { return true; };
        result.configure_policy = [](const BuildSnapshot &snapshot, AnonymousPolicy &policy,
                                     std::string &) {
            snapshot.forEachBuild([&policy](const StoredBuild &build) {
                policy.setRule(build.registration.build_id, AnonymousPolicy::BuildRule{
                    .software_id = build.registration.software_id,
                    .final_artifact_hash = build.final_artifact_hash,
                    .regions = {"2222222222222222222222222222222222222222222222222222222222222222"},
                    .modes = {"lease"},
                    .valid_until_ms = 900000,
                    .revision = build.policy_revision,
                    .request_budget = 100,
                    .enabled = true,
                });
            });
            return true;
        };
        result.authorize_control = [](const Request &, const RequestFacts &, std::uint64_t) {
            return ProtocolService::ControlAuthorization{
                .counter_epoch = std::string(64, 'e'),
                .auth_valid_until_ms = 100000,
                .control_valid_for_ms = 10000,
            };
        };
        result.authorize_admin = [](std::string_view, std::string_view, std::string_view,
                                   const std::string &) {
            return std::variant<AdminPrincipal, BackendError>(
                 AdminPrincipal{"fixture.software", {"build.publish", "build.revoke"}});
        };
        result.raw_api.announcement = [] {
            AnnouncementResponse response;
            response.announcement_id = "fixture-announcement";
            response.version = 1;
            response.priority = 1;
            response.issued_at_ms = 1000;
            response.expires_at_ms = 900000;
            response.content = "fixture";
            response.signature = {0x01};
            return std::variant<AnnouncementResponse, CloudApiError>(std::move(response));
        };
        result.raw_api.update = [](std::string_view version) {
            UpdateResponse response;
            response.version = std::string(version);
            response.artifact_hash.fill(0x22);
            response.size = 4;
            response.chunk_count = 1;
            response.signature = {0x02};
            return std::variant<UpdateResponse, CloudApiError>(std::move(response));
        };
        result.build_window_material = buildWindowMaterial;
        result.raw_api.variables = [](std::string_view) {
            RemoteVariablesResponse response;
            response.version = 1;
            response.expires_at_ms = 900000;
            response.canonical_variables = {'f', 'i', 'x', 't', 'u', 'r', 'e'};
            response.signature = {0x03};
            return std::variant<RemoteVariablesResponse, CloudApiError>(std::move(response));
        };
        result.raw_api.account_login = [](std::string_view, std::span<const uint8_t>) {
            LoginResponse response;
            response.session_id.fill(0x44);
            response.expires_at_ms = 900000;
            response.generation = 1;
            response.allowed_regions = {std::string(64, '2')};
            return std::variant<LoginResponse, CloudApiError>(std::move(response));
        };
        result.raw_api.card_login = [](std::span<const uint8_t>, std::span<const uint8_t>) {
            LoginResponse response;
            response.session_id.fill(0x55);
            response.expires_at_ms = 900000;
            response.generation = 1;
            response.allowed_regions = {std::string(64, '2')};
            return std::variant<LoginResponse, CloudApiError>(std::move(response));
        };
        result.build_payload = [](const Request &request, const RequestFacts &facts,
                                  const BuildSnapshot &snapshot, SessionState::Transaction &tx) {
            const auto *build = snapshot.find(facts.build_id);
            if (!build || build->registration.software_id != facts.software_id ||
                build->final_artifact_hash != facts.final_artifact_hash)
                return std::variant<ProtocolService::IssuedPayload, BackendError>(
                    BackendError{"build_unavailable"});
            if (!build->registration.verifier_sidecars.contains(facts.region_id))
                return std::variant<ProtocolService::IssuedPayload, BackendError>(
                    BackendError{"build_unavailable"});
            const auto sessionId = request.value.at("session_id").get<std::string>();
            const auto clientNonce = request.value.at("client_nonce").get<std::string>();
            const auto clientKey = request.value.at("client_ephemeral_key").get<std::string>();
            const auto state = tx.allocate(sessionId, facts.region_id, clientNonce, clientKey);
            const auto counterEpoch = request.value.at("counter_epoch").get<std::string>();
            const auto engineHash = request.value.at("engine_abi_hash").get<std::string>();
            const auto mode = request.value.at("mode").get<std::string>();
            constexpr std::array<std::uint8_t, 4> bytecode = {0x58, 0x4f, 0x56, 0x32};
            nlohmann::json binding{{"build_id", facts.build_id},
                {"region_id", facts.region_id}, {"session_id", sessionId},
                {"generation", std::to_string(state.generation)},
                {"request_hash", facts.request_digest}, {"mode", mode},
                {"lease_ms", mode == "lease" ? 120000u : 0u},
                {"engine_abi_hash", engineHash}, {"package_hash", std::string(64, '0')}};
            nlohmann::json package{
                {"format_version", 1}, {"binding", binding}, {"bytecode_size", bytecode.size()},
                {"encoded_bc", base64(bytecode)},
                {"decode_map", nlohmann::json::array({0, 1, 2, 3})},
                {"static_decode_descriptor", {
                    {"decode_salt", 7}, {"isa_version", 1},
                    {"layout_hash", std::string(64, '6')},
                    {"operand_encoding_hash", std::string(64, '7')}}}};
            for (int index = 4; index < 256; ++index) package["decode_map"].push_back(65535);
            package["binding"]["package_hash"] = packageHash(package);
            const auto bindingValue = package["binding"];
            return std::variant<ProtocolService::IssuedPayload, BackendError>(
                ProtocolService::IssuedPayload{
                    .payload = std::move(package), .binding = bindingValue,
                    .session_id = sessionId, .counter_epoch = counterEpoch,
                    .counter = state.counter, .session_valid_until_ms = 900000});
        };
        return result;
    }
    result.artifact_evidence = [](const std::string &, const std::string &) {
        return std::variant<Bytes, BackendError>(Bytes{std::byte{'e'}});
    };
    result.validate_final_artifact = [](const std::string &, const std::string &,
                                        std::span<const std::byte>, std::string &) { return true; };
    result.trust_handler = [](std::string_view software) {
        if (software != "fixture.software") return std::variant<Bytes, BackendError>(BackendError{"not_found"});
        const auto bytes = trustBundle();
        Bytes result;
        result.reserve(bytes.size());
        for (const auto byte : bytes) result.push_back(static_cast<std::byte>(byte));
        return std::variant<Bytes, BackendError>(std::move(result));
    };
    return result;
}

extern "C" void xovm_register_runtime_providers() {
    RuntimeProviderFactory::registerProvider("fixture",
        [](ProviderRole role, const BackendConfig &) -> std::variant<RuntimeProviderBundle, BackendError> {
            return provider(role);
        });
}
} // namespace
} // namespace xovm::cloud_material
