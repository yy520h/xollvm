#include "canonical_json.h"
#include "http_contract.h"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace {
using nlohmann::json;
using xovm::cloud_material::BackendError;
using xovm::cloud_material::parseCanonicalRequest;
using xovm::cloud_material::parseRelayEnvelope;

struct TestState {
    unsigned assertions = 0;
    unsigned failures = 0;
    const char *test_name = "";
};

TestState state;

bool expect(bool condition, const char *expression, const char *file, int line) {
    ++state.assertions;
    if (condition) return true;
    ++state.failures;
    std::fprintf(stderr, "%s:%d: %s failed in %s\n", file, line, expression,
                 state.test_name);
    return false;
}

template <typename Left, typename Right>
bool expectEqual(const Left &left, const Right &right, const char *expression,
                 const char *file, int line) {
    return expect(left == right, expression, file, line);
}

#define EXPECT_TRUE(expression) \
    expect(static_cast<bool>(expression), #expression, __FILE__, __LINE__)
#define EXPECT_FALSE(expression) \
    expect(!static_cast<bool>(expression), "! (" #expression ")", __FILE__, __LINE__)
#define ASSERT_TRUE(expression) \
    do { \
        if (!EXPECT_TRUE(expression)) return; \
    } while (false)
#define ASSERT_FALSE(expression) \
    do { \
        if (!EXPECT_FALSE(expression)) return; \
    } while (false)
#define ASSERT_EQ(left, right) \
    do { \
        if (!expectEqual((left), (right), #left " == " #right, __FILE__, __LINE__)) \
            return; \
    } while (false)
#define EXPECT_EQ(left, right) \
    expectEqual((left), (right), #left " == " #right, __FILE__, __LINE__)
#define TEST(suite, name) static void suite##_##name()

constexpr char kSuite[] = "X25519-Ed25519-HKDF-SHA256-AES256GCM";
constexpr char kKey[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
constexpr char kPrimeKey[] = "7f///////////////////////////////////////38=";
constexpr char kHighBitKey[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA=";

json request(std::string type) {
    json value = {
        {"build_id", std::string(64, '1')},
        {"client_ephemeral_key", kKey},
        {"client_nonce", std::string(64, '2')},
        {"final_artifact_hash", std::string(64, '3')},
        {"protocol_version", 2},
        {"request_id", std::string(64, '4')},
        {"software_id", "test.software"},
        {"suite", kSuite},
        {"type", std::move(type)},
    };
    if (value["type"] == "session.renew" || value["type"] == "session.close") {
        value["counter_epoch"] = std::string(64, '5');
        value["previous_counter"] = "0";
        value["session_id"] = std::string(64, '6');
    } else if (value["type"] == "material.issue") {
        value["counter_epoch"] = std::string(64, '5');
        value["engine_abi_hash"] = std::string(64, '7');
        value["mode"] = "lease";
        value["previous_generation"] = "0";
        value["region_id"] = std::string(64, '8');
        value["session_id"] = std::string(64, '6');
    }
    return value;
}

std::vector<std::byte> bytes(std::string text) {
    std::vector<std::byte> result;
    result.reserve(text.size());
    for (unsigned char value : text) result.push_back(static_cast<std::byte>(value));
    return result;
}

std::vector<std::byte> canonical(const json &value) {
    return bytes(value.dump());
}

std::string base64(const std::vector<std::byte> &input) {
    constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    for (size_t index = 0; index < input.size(); index += 3) {
        const uint32_t a = std::to_integer<uint8_t>(input[index]);
        const uint32_t b = index + 1 < input.size()
                               ? std::to_integer<uint8_t>(input[index + 1])
                               : 0;
        const uint32_t c = index + 2 < input.size()
                               ? std::to_integer<uint8_t>(input[index + 2])
                               : 0;
        const uint32_t bits = (a << 16) | (b << 8) | c;
        result += alphabet[(bits >> 18) & 63];
        result += alphabet[(bits >> 12) & 63];
        result += index + 1 < input.size() ? alphabet[(bits >> 6) & 63] : '=';
        result += index + 2 < input.size() ? alphabet[bits & 63] : '=';
    }
    return result;
}

std::vector<std::byte> relayBody(const std::vector<std::byte> &requestBytes) {
    return canonical(json{{"protocol", "xovm2_relay"},
                          {"request_b64", base64(requestBytes)}});
}

bool rejected(auto result) {
    return std::holds_alternative<BackendError>(result);
}

TEST(CloudMaterialBackendProtocol, AcceptsSessionOpenAndPreservesCanonicalBytes) {
    const auto input = canonical(request("session.open"));
    auto parsed = parseCanonicalRequest(input);
    ASSERT_FALSE(rejected(parsed));
    EXPECT_EQ(std::get<xovm::cloud_material::Request>(parsed).original_bytes, input);
}

TEST(CloudMaterialBackendProtocol, AcceptsMaterialIssue) {
    EXPECT_FALSE(rejected(parseCanonicalRequest(canonical(request("material.issue")))));
}

TEST(CloudMaterialBackendProtocol, AcceptsSessionRenewAndClose) {
    EXPECT_FALSE(rejected(parseCanonicalRequest(canonical(request("session.renew")))));
    EXPECT_FALSE(rejected(parseCanonicalRequest(canonical(request("session.close")))));
}

TEST(CloudMaterialBackendProtocol, RejectsUnknownAndMissingFields) {
    auto unknown = request("session.open");
    unknown["unexpected"] = 1;
    EXPECT_TRUE(rejected(parseCanonicalRequest(canonical(unknown))));

    auto missing = request("session.open");
    missing.erase("software_id");
    EXPECT_TRUE(rejected(parseCanonicalRequest(canonical(missing))));
}

TEST(CloudMaterialBackendProtocol, RejectsDuplicateFields) {
    const auto input = bytes(
        "{\"build_id\":\"" + std::string(64, '1') +
        "\",\"client_ephemeral_key\":\"" + kKey +
        "\",\"client_nonce\":\"" + std::string(64, '2') +
        "\",\"final_artifact_hash\":\"" + std::string(64, '3') +
        "\",\"protocol_version\":2,\"request_id\":\"" + std::string(64, '4') +
        "\",\"software_id\":\"test.software\",\"suite\":\"" + kSuite +
        "\",\"type\":\"session.open\",\"type\":\"session.open\"}");
    EXPECT_TRUE(rejected(parseCanonicalRequest(input)));
}

TEST(CloudMaterialBackendProtocol, RejectsInvalidUtf8) {
    auto input = canonical(request("session.open"));
    input.insert(input.begin() + 1, std::byte{0xff});
    EXPECT_TRUE(rejected(parseCanonicalRequest(input)));
}

TEST(CloudMaterialBackendProtocol, RejectsNoncanonicalEncoding) {
    const auto valid = canonical(request("session.open"));
    const std::string validText(reinterpret_cast<const char *>(valid.data()), valid.size());
    EXPECT_TRUE(rejected(parseCanonicalRequest(bytes(" " + validText))));
    EXPECT_TRUE(rejected(parseCanonicalRequest(bytes(
        "{\"build_id\":\"" + std::string(64, '1') +
        "\",\"client_ephemeral_key\":\"" + kKey +
        "\",\"client_nonce\":\"" + std::string(64, '2') +
        "\",\"final_artifact_hash\":\"" + std::string(64, '3') +
        "\",\"protocol_version\":2.0,\"request_id\":\"" + std::string(64, '4') +
        "\",\"software_id\":\"test.software\",\"suite\":\"" + kSuite +
        "\",\"type\":\"session.open\"}"))));

    EXPECT_TRUE(rejected(parseCanonicalRequest(
        bytes("{\"z\":0,\"a\":0}"))));
}

TEST(CloudMaterialBackendProtocol, RejectsUnsupportedSuiteAndOversizedRequest) {
    auto unsupported = request("session.open");
    unsupported["suite"] = "unsupported";
    EXPECT_TRUE(rejected(parseCanonicalRequest(canonical(unsupported))));

    auto noncanonicalBase64 = request("session.open");
    noncanonicalBase64["client_ephemeral_key"] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=";
    EXPECT_TRUE(rejected(parseCanonicalRequest(canonical(noncanonicalBase64))));
    EXPECT_TRUE(rejected(parseCanonicalRequest(std::vector<std::byte>(8193))));
}

TEST(CloudMaterialBackendProtocol, RejectsNoncanonicalX25519Coordinates) {
    auto equalToPrime = request("session.open");
    equalToPrime["client_ephemeral_key"] = kPrimeKey;
    EXPECT_TRUE(rejected(parseCanonicalRequest(canonical(equalToPrime))));

    auto highBitSet = request("session.open");
    highBitSet["client_ephemeral_key"] = kHighBitKey;
    EXPECT_TRUE(rejected(parseCanonicalRequest(canonical(highBitSet))));
}

TEST(CloudMaterialBackendProtocol, RelayEnvelopeReturnsExactRequestBytes) {
    const auto original = canonical(request("session.open"));
    const auto envelope = relayBody(original);
    auto parsed = parseRelayEnvelope(envelope);
    if (const auto *error = std::get_if<BackendError>(&parsed))
        std::fprintf(stderr, "relay envelope rejected: %s\n", error->code.c_str());
    ASSERT_FALSE(rejected(parsed));
    EXPECT_EQ(std::get<xovm::cloud_material::RelayRequest>(parsed).request_bytes,
              original);
}

TEST(CloudMaterialBackendProtocol, RelayEnvelopeRejectsDuplicateFieldsAndBadBase64) {
    const auto duplicate = bytes(
        "{\"protocol\":\"xovm2_relay\",\"request_b64\":\"AA==\","
        "\"protocol\":\"xovm2_relay\"}");
    EXPECT_TRUE(rejected(parseRelayEnvelope(duplicate)));

    for (const auto *encoded : {"@@@=", "YQ", "YQ==\n", "AB=="}) {
        const auto body = canonical(json{{"protocol", "xovm2_relay"},
                                         {"request_b64", encoded}});
        EXPECT_TRUE(rejected(parseRelayEnvelope(body)));
    }
}

TEST(CloudMaterialBackendProtocol, RelayEnvelopeRejectsUnknownFields) {
    const auto body = canonical(json{{"ignored", true},
                                     {"protocol", "xovm2_relay"},
                                     {"request_b64", "AA=="}});
    EXPECT_TRUE(rejected(parseRelayEnvelope(body)));
}

TEST(CloudMaterialBackendProtocol, RelayEnvelopeRejectsExcessiveNestingBeforeJsonParse) {
    std::string nested = "{\"protocol\":\"xovm2_relay\",\"request_b64\":\"AA==\",\"x\":";
    nested.append(300, '[');
    nested += "0";
    nested.append(300, ']');
    nested += "}";
    auto parsed = parseRelayEnvelope(bytes(nested));
    ASSERT_TRUE(rejected(parsed));
    EXPECT_EQ(std::get<BackendError>(parsed).code, "json_depth_limit");
}

} // namespace

int main() {
    using Test = void (*)();
    const std::pair<const char *, Test> tests[] = {
        {"AcceptsSessionOpenAndPreservesCanonicalBytes", CloudMaterialBackendProtocol_AcceptsSessionOpenAndPreservesCanonicalBytes},
        {"AcceptsMaterialIssue", CloudMaterialBackendProtocol_AcceptsMaterialIssue},
        {"AcceptsSessionRenewAndClose", CloudMaterialBackendProtocol_AcceptsSessionRenewAndClose},
        {"RejectsUnknownAndMissingFields", CloudMaterialBackendProtocol_RejectsUnknownAndMissingFields},
        {"RejectsDuplicateFields", CloudMaterialBackendProtocol_RejectsDuplicateFields},
        {"RejectsInvalidUtf8", CloudMaterialBackendProtocol_RejectsInvalidUtf8},
        {"RejectsNoncanonicalEncoding", CloudMaterialBackendProtocol_RejectsNoncanonicalEncoding},
        {"RejectsUnsupportedSuiteAndOversizedRequest", CloudMaterialBackendProtocol_RejectsUnsupportedSuiteAndOversizedRequest},
        {"RelayEnvelopeReturnsExactRequestBytes", CloudMaterialBackendProtocol_RelayEnvelopeReturnsExactRequestBytes},
        {"RelayEnvelopeRejectsDuplicateFieldsAndBadBase64", CloudMaterialBackendProtocol_RelayEnvelopeRejectsDuplicateFieldsAndBadBase64},
        {"RelayEnvelopeRejectsUnknownFields", CloudMaterialBackendProtocol_RelayEnvelopeRejectsUnknownFields},
        {"RelayEnvelopeRejectsExcessiveNestingBeforeJsonParse", CloudMaterialBackendProtocol_RelayEnvelopeRejectsExcessiveNestingBeforeJsonParse},
    };

    unsigned failed_tests = 0;
    for (const auto &[name, test] : tests) {
        const unsigned before = state.failures;
        state.test_name = name;
        test();
        if (state.failures != before) {
            ++failed_tests;
            std::fprintf(stderr, "[FAIL] %s\n", name);
        } else {
            std::fprintf(stdout, "[PASS] %s\n", name);
        }
    }
    std::fprintf(stdout, "%zu tests, %u assertions, %u failures\n",
                 std::size(tests), state.assertions, state.failures);
    return failed_tests == 0 ? 0 : 1;
}
