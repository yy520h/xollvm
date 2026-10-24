#include "runtime/cloud_material/material_protocol.h"
#include <nlohmann/json.hpp>
#include <array>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

using nlohmann::json;
using namespace xovm::material;

static int base64Value(char character) {
    if (character >= 'A' && character <= 'Z') return character - 'A';
    if (character >= 'a' && character <= 'z') return character - 'a' + 26;
    if (character >= '0' && character <= '9') return character - '0' + 52;
    if (character == '+') return 62;
    if (character == '/') return 63;
    return -1;
}

static std::vector<uint8_t> base64(const std::string &encoded) {
    if (encoded.empty() || encoded.size() % 4) throw std::runtime_error("fixture_base64");
    const size_t padding = encoded.ends_with("==") ? 2 : encoded.ends_with("=") ? 1 : 0;
    const size_t end = encoded.size() - padding;
    std::vector<uint8_t> result(3 * (encoded.size() / 4) - padding);
    uint32_t bits = 0;
    unsigned count = 0;
    size_t output = 0;
    for (size_t index = 0; index < end; ++index) {
        const int value = base64Value(encoded[index]);
        if (value < 0) throw std::runtime_error("fixture_base64");
        bits = (bits << 6) | static_cast<uint32_t>(value);
        count += 6;
        if (count >= 8) {
            count -= 8;
            result[output++] = static_cast<uint8_t>(bits >> count);
        }
    }
    return result;
}

static uint8_t hexDigit(char character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    throw std::runtime_error("fixture_hex");
}

static std::array<uint8_t, 32> hex32(const std::string &encoded) {
    if (encoded.size() != 64) throw std::runtime_error("fixture_hex");
    std::array<uint8_t, 32> result{};
    for (size_t index = 0; index < result.size(); ++index)
        result[index] = static_cast<uint8_t>((hexDigit(encoded[index * 2]) << 4) |
                                             hexDigit(encoded[index * 2 + 1]));
    return result;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    const std::string caseName = argv[1];
    std::string ignored;
    std::getline(std::cin, ignored);
    const std::string input(std::istreambuf_iterator<char>(std::cin), {});
    try {
        const auto fixture = json::parse(input);
        const auto installedValue = fixture.at("installed");
        InstalledTrust installed{
            installedValue.at("software_id").get<std::string>(),
            installedValue.at("root_key_id").get<std::string>(),
            hex32(fixture.at("root_public_key").get<std::string>()),
            std::stoull(installedValue.at("trusted_lower_ms").get<std::string>()),
            std::stoull(installedValue.at("trusted_upper_ms").get<std::string>()),
        };
        auto trust = verifyTrustBundle(base64(fixture.at("trust_bundle").get<std::string>()),
                                       installed);
        if (const auto *error = std::get_if<ProtocolError>(&trust)) {
            std::cout << json{{"ok", true}, {"accepted", false},
                              {"published_generations", 0}, {"code", error->code}}.dump() << '\n';
            return 0;
        }
        const auto expectedValue = fixture.at("expected");
        ExpectedMaterial expected{
            expectedValue.at("software_id").get<std::string>(),
            expectedValue.at("build_id").get<std::string>(),
            expectedValue.at("final_artifact_hash").get<std::string>(),
            expectedValue.at("session_id").get<std::string>(),
            expectedValue.at("counter_epoch").get<std::string>(),
            expectedValue.at("region_id").get<std::string>(),
            expectedValue.at("engine_abi_hash").get<std::string>(),
            expectedValue.at("mode").get<std::string>(),
        };
        PendingRequest pending(base64(fixture.at("request").get<std::string>()),
            hex32(fixture.at("client_private_key").get<std::string>()),
            std::get<VerifiedTrustBundle>(std::move(trust)), std::move(expected),
            std::stoull(fixture.at("sent_boot_ns").get<std::string>()),
            std::stoull(fixture.at("received_boot_ns").get<std::string>()));
        const auto response = base64(fixture.at("response").get<std::string>());
        auto authenticated = authenticateResponse(response, pending);
        if (const auto *error = std::get_if<ProtocolError>(&authenticated)) {
            std::cout << json{{"ok", true}, {"accepted", false},
                              {"published_generations", 0}, {"code", error->code}}.dump() << '\n';
        } else if (caseName == "pending_reuse") {
            auto repeated = authenticateResponse(response, pending);
            if (const auto *error = std::get_if<ProtocolError>(&repeated)) {
                std::cout << json{{"ok", true}, {"accepted", false},
                                  {"first_accepted", true}, {"published_generations", 1},
                                  {"code", error->code}}.dump() << '\n';
            } else {
                std::cout << json{{"ok", true}, {"accepted", true},
                                  {"first_accepted", true}, {"published_generations", 2},
                                  {"code", ""}}.dump() << '\n';
            }
        } else {
            const auto &package = std::get<VerifiedPackage>(authenticated).package();
            std::cout << json{{"ok", true}, {"accepted", true},
                              {"published_generations", 1}, {"code", ""},
                              {"generation", std::to_string(package.binding.generation)}}.dump() << '\n';
        }
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "fixture_failure:" << error.what() << '\n';
        return 3;
    }
}
