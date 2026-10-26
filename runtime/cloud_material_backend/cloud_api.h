#ifndef XOVM_CLOUD_MATERIAL_BACKEND_CLOUD_API_H
#define XOVM_CLOUD_MATERIAL_BACKEND_CLOUD_API_H

#include "../cloud_material/dynamic_vm_schema.h"

#include <array>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace xovm::cloud_material {

class AuthenticatedRawContext;

enum class CloudOperation : uint16_t {
    Announcement = 1,
    Update = 2,
    AlgorithmAcquire = 3,
    RemoteVariables = 4,
    LoginAccount = 5,
    LoginCard = 6,
};

struct CloudApiError {
    std::string code;
};

struct AnnouncementResponse {
    std::string announcement_id;
    uint32_t version = 0;
    uint8_t priority = 0;
    uint64_t issued_at_ms = 0;
    uint64_t expires_at_ms = 0;
    std::string content;
    std::vector<uint8_t> signature;
};

struct UpdateResponse {
    std::string version;
    std::array<uint8_t, 32> artifact_hash{};
    uint64_t size = 0;
    uint32_t chunk_count = 0;
    std::vector<uint8_t> signature;
};

struct RemoteVariablesResponse {
    uint32_t version = 0;
    uint64_t expires_at_ms = 0;
    std::vector<uint8_t> canonical_variables;
    std::vector<uint8_t> signature;
};

struct LoginResponse {
    std::array<uint8_t, 16> session_id{};
    uint64_t expires_at_ms = 0;
    uint64_t generation = 0;
    std::vector<std::string> allowed_regions;
};

struct CloudApiProviders {
    std::function<std::variant<AnnouncementResponse, CloudApiError>()> announcement;
    std::function<std::variant<UpdateResponse, CloudApiError>(std::string_view)> update;
    std::function<std::variant<xovm::material::WindowGrant, CloudApiError>(
        const AuthenticatedRawContext &,
        const xovm::material::WindowAcquireRequest &)> algorithm;
    std::function<std::variant<RemoteVariablesResponse, CloudApiError>(std::string_view)> variables;
    std::function<std::variant<LoginResponse, CloudApiError>(
        std::string_view, std::span<const uint8_t>)> account_login;
    std::function<std::variant<LoginResponse, CloudApiError>(
        std::span<const uint8_t>, std::span<const uint8_t>)> card_login;
};

class CloudApi {
public:
    explicit CloudApi(CloudApiProviders providers) : providers_(std::move(providers)) {}

    std::variant<AnnouncementResponse, CloudApiError> announcement() const;
    std::variant<UpdateResponse, CloudApiError> update(std::string_view version) const;
    std::variant<xovm::material::WindowGrant, CloudApiError> algorithm(
        const AuthenticatedRawContext &context,
        const xovm::material::WindowAcquireRequest &request) const;
    std::variant<RemoteVariablesResponse, CloudApiError> variables(std::string_view session) const;
    std::variant<LoginResponse, CloudApiError> accountLogin(
        std::string_view account, std::span<const uint8_t> proof) const;
    std::variant<LoginResponse, CloudApiError> cardLogin(
        std::span<const uint8_t> card, std::span<const uint8_t> binding) const;

private:
    CloudApiProviders providers_;
};

} // namespace xovm::cloud_material

#endif
