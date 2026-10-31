#ifndef XOVM_CLOUD_MATERIAL_BACKEND_RESPONSE_CRYPTO_H
#define XOVM_CLOUD_MATERIAL_BACKEND_RESPONSE_CRYPTO_H

#include "canonical_json.h"

#include <array>
#include <functional>

namespace xovm::cloud_material {

using SignEd25519 = std::function<std::variant<std::array<std::uint8_t, 64>, BackendError>(
    std::span<const std::uint8_t>)>;

struct SigningMetadata {
    std::string key_id;
    std::uint64_t trust_epoch = 0;
    std::uint64_t not_after_ms = 0;
    std::uint64_t bundle_valid_until_ms = 0;
    bool available() const { return !key_id.empty() && trust_epoch != 0; }
};

std::vector<std::uint8_t> frameForTest(std::string_view label,
                                      std::span<const std::uint8_t> part);
std::variant<std::vector<std::byte>, BackendError> sealResponse(
    const nlohmann::json &transcript, std::span<const std::byte> plaintext,
    std::span<const std::uint8_t, 32> clientPublic,
    std::span<const std::uint8_t, 32> serverPrivate,
    const SignEd25519 &sign);

} // namespace xovm::cloud_material

#endif
