#include "config.h"

#include <charconv>
#include <cstdlib>

namespace xovm::cloud_material {
namespace {

BackendError missing(const char *name) {
    return BackendError{std::string("config_missing_") + name};
}

bool parseUnsigned(std::string_view text, std::uint64_t &value) {
    if (text.empty()) return false;
    const auto *begin = text.data();
    const auto *end = begin + text.size();
    const auto result = std::from_chars(begin, end, value);
    return result.ec == std::errc{} && result.ptr == end;
}

std::string required(const BackendConfig::Lookup &lookup, const char *name,
                     BackendError &error) {
    auto value = lookup(name);
    if (value.empty()) error = missing(name);
    return value;
}

} // namespace

std::variant<BackendConfig, BackendError> BackendConfig::fromEnvironment() {
    return fromEnvironment([](std::string_view name) {
        const std::string key(name);
        const char *value = std::getenv(key.c_str());
        return value == nullptr ? std::string{} : std::string(value);
    });
}

std::variant<BackendConfig, BackendError> BackendConfig::fromEnvironment(const Lookup &lookup) {
    if (!lookup) return BackendError{"config_lookup_unavailable"};
    BackendConfig config;
    BackendError error;
    config.sqlite_path = required(lookup, "XOVM_SQLITE_PATH", error);
    config.state_dir = required(lookup, "XOVM_STATE_DIR", error);
    config.relay_token = required(lookup, "XOVM_RELAY_TOKEN", error);
    config.admin_token = required(lookup, "XOVM_ADMIN_TOKEN", error);
    config.trusted_time_provider = required(lookup, "XOVM_TRUSTED_TIME_PROVIDER", error);
    config.signing_key_provider = required(lookup, "XOVM_SIGNING_KEY_PROVIDER", error);
    config.anonymous_policy_provider = required(lookup, "XOVM_ANONYMOUS_POLICY_PROVIDER", error);
    config.trust_root_provider = required(lookup, "XOVM_TRUST_ROOT_PROVIDER", error);
    if (!error.code.empty()) return error;
    if (config.relay_token.size() < 32 || config.admin_token.size() < 32)
        return BackendError{"config_credential_too_short"};
    if (config.relay_token == config.admin_token)
        return BackendError{"config_credentials_must_differ"};
    config.bind_address = lookup("XOVM_BIND_ADDRESS");
    if (config.bind_address.empty()) config.bind_address = "127.0.0.1";
    if (config.bind_address != "127.0.0.1")
        return BackendError{"config_bind_must_be_loopback"};

    std::uint64_t number = 0;
    auto port = lookup("PORT");
    if (!port.empty()) {
        if (!parseUnsigned(port, number) || number == 0 || number > 65535)
            return BackendError{"config_invalid_port"};
        config.port = static_cast<std::uint16_t>(number);
    }
    auto rawPort = lookup("XOVM_RAW_PORT");
    if (!rawPort.empty()) {
        if (!parseUnsigned(rawPort, number) || number > 65535)
            return BackendError{"config_invalid_raw_port"};
        config.raw_port = static_cast<std::uint16_t>(number);
    }
    auto timeout = lookup("REQUEST_TIMEOUT_MS");
    if (!timeout.empty()) {
        if (!parseUnsigned(timeout, number) || number < 100 || number > 120000)
            return BackendError{"config_invalid_request_timeout"};
        config.request_timeout_ms = number;
    }
    auto concurrency = lookup("MAX_CONCURRENT_REQUESTS");
    if (!concurrency.empty()) {
        if (!parseUnsigned(concurrency, number) || number == 0 || number > 10000)
            return BackendError{"config_invalid_concurrency"};
        config.max_concurrent_requests = static_cast<std::uint32_t>(number);
    }
    return config;
}

} // namespace xovm::cloud_material
