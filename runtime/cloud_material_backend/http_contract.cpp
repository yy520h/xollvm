#include "http_contract.h"

#include <nlohmann/json.hpp>

#include <array>
#include <unordered_set>

namespace xovm::cloud_material {
namespace {
using nlohmann::json;

struct EnvelopeCheck {
    bool duplicate_key = false;
    std::vector<std::unordered_set<std::string>> object_keys;
};

int base64Value(char character) {
    if (character >= 'A' && character <= 'Z') return character - 'A';
    if (character >= 'a' && character <= 'z') return character - 'a' + 26;
    if (character >= '0' && character <= '9') return character - '0' + 52;
    if (character == '+') return 62;
    if (character == '/') return 63;
    return -1;
}

void checkEnvelopeDepth(std::span<const std::byte> body) {
    size_t depth = 0;
    bool inString = false;
    bool escaped = false;
    for (const std::byte byte : body) {
        const char character = static_cast<char>(byte);
        if (inString) {
            if (escaped) escaped = false;
            else if (character == '\\') escaped = true;
            else if (character == '"') inString = false;
            continue;
        }
        if (character == '"') inString = true;
        else if (character == '{' || character == '[') {
            if (++depth > 1) throw BackendError{"json_depth_limit"};
        } else if (character == '}' || character == ']') {
            if (depth) --depth;
        }
    }
}

std::vector<std::byte> decodeRequestBase64(const std::string &encoded) {
    if (encoded.size() > 4 * ((kMaxCanonicalRequest + 2) / 3) ||
        encoded.size() % 4 != 0) throw BackendError{"invalid_base64"};
    const size_t padding = encoded.ends_with("==") ? 2 : encoded.ends_with("=") ? 1 : 0;
    if (encoded.empty() || padding > 2) throw BackendError{"invalid_base64"};
    const size_t end = encoded.size() - padding;
    for (size_t index = 0; index < end; ++index) {
        if (base64Value(encoded[index]) < 0) throw BackendError{"invalid_base64"};
    }
    for (size_t index = end; index < encoded.size(); ++index) {
        if (encoded[index] != '=') throw BackendError{"invalid_base64"};
    }
    if (end == 0 || (padding == 2 && (base64Value(encoded[end - 1]) & 15)) ||
        (padding == 1 && (base64Value(encoded[end - 1]) & 3)))
        throw BackendError{"invalid_base64"};

    const size_t decodedSize = 3 * (encoded.size() / 4) - padding;
    if (decodedSize > kMaxCanonicalRequest) throw BackendError{"request_size_limit"};
    std::vector<std::byte> decoded(decodedSize);
    uint32_t bits = 0;
    unsigned count = 0;
    size_t output = 0;
    for (size_t index = 0; index < end; ++index) {
        bits = (bits << 6) | static_cast<uint32_t>(base64Value(encoded[index]));
        count += 6;
        if (count >= 8) {
            count -= 8;
            decoded[output++] = static_cast<std::byte>(bits >> count);
        }
    }
    return decoded;
}

} // namespace

RelayRequestResult parseRelayEnvelope(std::span<const std::byte> body) {
    try {
        if (body.size() > kMaxRelayRequestEnvelope)
            throw BackendError{"request_size_limit"};
        checkEnvelopeDepth(body);
        const auto *begin = reinterpret_cast<const char *>(body.data());
        EnvelopeCheck check;
        const auto callback = [&check](int depth, json::parse_event_t event,
                                       json &parsed) {
            if (event == json::parse_event_t::object_start) {
                if (check.object_keys.size() <= static_cast<size_t>(depth))
                    check.object_keys.resize(static_cast<size_t>(depth) + 1);
                check.object_keys[static_cast<size_t>(depth)].clear();
            } else if (event == json::parse_event_t::key) {
                const int objectDepth = depth - 1;
                if (objectDepth < 0 ||
                    check.object_keys.size() <= static_cast<size_t>(objectDepth) ||
                    !check.object_keys[static_cast<size_t>(objectDepth)].insert(
                         parsed.get<std::string>()).second) {
                    check.duplicate_key = true;
                }
            }
            return true;
        };
        const auto envelope = json::parse(begin, begin + body.size(), callback,
                                          true, false);
        if (check.duplicate_key) throw BackendError{"invalid_json"};
        if (!envelope.is_object() || envelope.size() != 2 ||
            !envelope.contains("protocol") || !envelope.contains("request_b64"))
            throw BackendError{"invalid_schema"};
        if (!envelope.at("protocol").is_string() ||
            envelope.at("protocol") != "xovm2_relay")
            throw BackendError{"invalid_protocol"};
        if (!envelope.at("request_b64").is_string())
            throw BackendError{"invalid_type"};
        auto requestBytes = decodeRequestBase64(
            envelope.at("request_b64").get_ref<const std::string &>());
        auto request = parseCanonicalRequest(requestBytes);
        if (const auto *error = std::get_if<BackendError>(&request)) throw *error;
        return RelayRequest{std::move(requestBytes)};
    } catch (const BackendError &error) {
        return error;
    } catch (const json::exception &) {
        return BackendError{"invalid_json"};
    } catch (const std::bad_alloc &) {
        return BackendError{"allocation_failed"};
    }
}

} // namespace xovm::cloud_material
