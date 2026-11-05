#include "cloud_api.h"

namespace xovm::cloud_material {
namespace {

template<class T, class F>
std::variant<T, CloudApiError> call(const std::function<std::variant<T, CloudApiError>()> &provider,
                                   F fallback) {
    if (!provider) return fallback();
    try {
        return provider();
    } catch (...) {
        return CloudApiError{"provider_unavailable"};
    }
}

} // namespace

std::variant<AnnouncementResponse, CloudApiError> CloudApi::announcement() const {
    return call<AnnouncementResponse>(providers_.announcement,
                                      [] { return std::variant<AnnouncementResponse, CloudApiError>(
                                          CloudApiError{"announcement_unavailable"}); });
}

std::variant<UpdateResponse, CloudApiError> CloudApi::update(std::string_view version) const {
    if (!providers_.update || version.empty() || version.size() > 64)
        return CloudApiError{"update_unavailable"};
    try { return providers_.update(version); }
    catch (...) { return CloudApiError{"provider_unavailable"}; }
}

std::variant<xovm::material::WindowGrant, CloudApiError> CloudApi::algorithm(
    const AuthenticatedRawContext &context,
    const xovm::material::WindowAcquireRequest &request) const {
    if (!providers_.algorithm) return CloudApiError{"algorithm_unavailable"};
    try { return providers_.algorithm(context, request); }
    catch (...) { return CloudApiError{"provider_unavailable"}; }
}

std::variant<RemoteVariablesResponse, CloudApiError> CloudApi::variables(
    std::string_view session) const {
    if (!providers_.variables || session.empty() || session.size() > 64)
        return CloudApiError{"variables_unavailable"};
    try { return providers_.variables(session); }
    catch (...) { return CloudApiError{"provider_unavailable"}; }
}

std::variant<LoginResponse, CloudApiError> CloudApi::accountLogin(
    std::string_view account, std::span<const uint8_t> proof) const {
    if (!providers_.account_login || account.empty() || account.size() > 128 || proof.empty() ||
        proof.size() > 4096)
        return CloudApiError{"login_unavailable"};
    try { return providers_.account_login(account, proof); }
    catch (...) { return CloudApiError{"provider_unavailable"}; }
}

std::variant<LoginResponse, CloudApiError> CloudApi::cardLogin(
    std::span<const uint8_t> card, std::span<const uint8_t> binding) const {
    if (!providers_.card_login || card.empty() || card.size() > 256 || binding.empty() ||
        binding.size() > 256)
        return CloudApiError{"login_unavailable"};
    try { return providers_.card_login(card, binding); }
    catch (...) { return CloudApiError{"provider_unavailable"}; }
}

} // namespace xovm::cloud_material
