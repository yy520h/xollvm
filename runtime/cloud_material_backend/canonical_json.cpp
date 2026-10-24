#include "canonical_json.h"

#include "material_package.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <string_view>

namespace xovm::cloud_material {
namespace {
using nlohmann::json;

[[noreturn]] void fail(const char *code) {
    throw BackendError{code};
}

std::string_view text(const json &value) {
    if (!value.is_string()) fail("invalid_type");
    return value.get_ref<const std::string &>();
}

void closed(const json &value, std::initializer_list<const char *> fields) {
    if (!value.is_object() || value.size() != fields.size()) fail("invalid_schema");
    for (const char *field : fields) {
        if (!value.contains(field)) fail("invalid_schema");
    }
}

void checkId(std::string_view value) {
    if (value.empty() || value.size() > 64 ||
        !std::isalnum(static_cast<unsigned char>(value.front()))) fail("invalid_id");
    for (const char character : value) {
        if (!((character >= 'A' && character <= 'Z') ||
              (character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') || character == '.' ||
              character == '_' || character == '-')) fail("invalid_id");
    }
}

void checkHash(std::string_view value, bool random = false) {
    if (value.size() != 64 ||
        !std::all_of(value.begin(), value.end(), [](char character) {
            return (character >= '0' && character <= '9') ||
                   (character >= 'a' && character <= 'f');
        })) fail("invalid_hash");
    if (random && std::all_of(value.begin(), value.end(),
                              [](char character) { return character == '0'; }))
        fail("invalid_random_value");
}

uint64_t u64(const json &value) {
    const auto string = text(value);
    if (string.empty() || string.size() > 20 ||
        (string.size() > 1 && string.front() == '0')) fail("invalid_u64");
    uint64_t number = 0;
    for (const char character : string) {
        if (character < '0' || character > '9') fail("invalid_u64");
        const auto digit = static_cast<uint64_t>(character - '0');
        if (number > (UINT64_MAX - digit) / 10) fail("u64_overflow");
        number = number * 10 + digit;
    }
    return number;
}

int base64Value(char character) {
    if (character >= 'A' && character <= 'Z') return character - 'A';
    if (character >= 'a' && character <= 'z') return character - 'a' + 26;
    if (character >= '0' && character <= '9') return character - '0' + 52;
    if (character == '+') return 62;
    if (character == '/') return 63;
    return -1;
}

std::array<uint8_t, 32> publicKey(const json &value) {
    const auto encoded = text(value);
    if (encoded.size() != 44 || !encoded.ends_with('=')) fail("invalid_base64");
    std::array<uint8_t, 32> decoded{};
    uint32_t bits = 0;
    unsigned count = 0;
    size_t output = 0;
    for (size_t index = 0; index < encoded.size() - 1; ++index) {
        const int digit = base64Value(encoded[index]);
        if (digit < 0) fail("invalid_base64");
        bits = (bits << 6) | static_cast<uint32_t>(digit);
        count += 6;
        if (count >= 8) {
            count -= 8;
            if (output >= decoded.size()) fail("invalid_base64");
            decoded[output++] = static_cast<uint8_t>(bits >> count);
        }
    }
    if (output != decoded.size() || (base64Value(encoded[42]) & 3) != 0)
        fail("invalid_base64");
    static constexpr std::array<uint8_t, 32> prime = {
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    };
    if (decoded.back() & 0x80) fail("invalid_key");
    for (size_t index = decoded.size(); index-- > 0;) {
        if (decoded[index] < prime[index]) break;
        if (decoded[index] > prime[index] || index == 0) fail("invalid_key");
    }
    return decoded;
}

void validateRequest(const json &request) {
    const auto type = text(request.at("type"));
    if (type == "session.open") {
        closed(request, {"protocol_version", "suite", "type", "software_id", "build_id",
                         "final_artifact_hash", "request_id", "client_nonce",
                         "client_ephemeral_key"});
    } else if (type == "session.renew" || type == "session.close") {
        closed(request, {"protocol_version", "suite", "type", "software_id", "build_id",
                         "final_artifact_hash", "request_id", "client_nonce",
                         "client_ephemeral_key", "session_id", "counter_epoch",
                         "previous_counter"});
        checkHash(text(request.at("session_id")), true);
        checkHash(text(request.at("counter_epoch")), true);
        (void)u64(request.at("previous_counter"));
    } else if (type == "material.issue") {
        closed(request, {"protocol_version", "suite", "type", "software_id", "build_id",
                         "final_artifact_hash", "request_id", "client_nonce",
                         "client_ephemeral_key", "session_id", "counter_epoch", "region_id",
                         "engine_abi_hash", "mode", "previous_generation"});
        checkHash(text(request.at("session_id")), true);
        checkHash(text(request.at("counter_epoch")), true);
        checkHash(text(request.at("region_id")));
        checkHash(text(request.at("engine_abi_hash")));
        const auto mode = text(request.at("mode"));
        if (mode != "session" && mode != "lease" && mode != "operation")
            fail("invalid_mode");
        (void)u64(request.at("previous_generation"));
    } else {
        fail("invalid_request_type");
    }

    if (!request.at("protocol_version").is_number_unsigned() ||
        request.at("protocol_version").get<uint64_t>() != 2) fail("unsupported_version");
    if (text(request.at("suite")) != kProtocolSuite) fail("unsupported_suite");
    checkId(text(request.at("software_id")));
    checkHash(text(request.at("build_id")));
    checkHash(text(request.at("final_artifact_hash")));
    checkHash(text(request.at("request_id")), true);
    checkHash(text(request.at("client_nonce")), true);
    (void)publicKey(request.at("client_ephemeral_key"));
}

} // namespace

RequestResult parseCanonicalRequest(std::span<const std::byte> bytes) {
    try {
        if (bytes.size() > kMaxCanonicalRequest) fail("request_size_limit");
        const auto *data = reinterpret_cast<const uint8_t *>(bytes.data());
        auto decoded = xovm::material::decodeCanonical({data, bytes.size()});
        if (const auto *error = std::get_if<xovm::material::PackageError>(&decoded))
            fail(error->code.c_str());
        auto value = std::get<json>(std::move(decoded));
        validateRequest(value);
        return Request{std::move(value), {bytes.begin(), bytes.end()}};
    } catch (const BackendError &error) {
        return error;
    } catch (const std::bad_alloc &) {
        return BackendError{"allocation_failed"};
    } catch (const json::exception &) {
        return BackendError{"invalid_schema"};
    }
}

} // namespace xovm::cloud_material
