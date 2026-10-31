#ifndef XOVM_CLOUD_MATERIAL_BACKEND_CONFIG_H
#define XOVM_CLOUD_MATERIAL_BACKEND_CONFIG_H

#include "canonical_json.h"

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <variant>

namespace xovm::cloud_material {

struct BackendConfig {
    std::string sqlite_path;
    std::string state_dir;
    std::string bind_address = "127.0.0.1";
    std::uint16_t port = 8080;
    std::uint64_t request_timeout_ms = 10000;
    std::uint32_t max_concurrent_requests = 128;
    std::string relay_token;
    std::string admin_token;
    std::string trusted_time_provider;
    std::string signing_key_provider;
    std::string anonymous_policy_provider;
    std::string trust_root_provider;

    using Lookup = std::function<std::string(std::string_view)>;
    static std::variant<BackendConfig, BackendError> fromEnvironment();
    static std::variant<BackendConfig, BackendError> fromEnvironment(const Lookup &lookup);
};

using BackendConfigResult = std::variant<BackendConfig, BackendError>;

} // namespace xovm::cloud_material

#endif
