#ifndef XOVM_CLOUD_MATERIAL_BACKEND_HTTP_CONTRACT_H
#define XOVM_CLOUD_MATERIAL_BACKEND_HTTP_CONTRACT_H

#include "canonical_json.h"

#include <span>
#include <variant>
#include <vector>

namespace xovm::cloud_material {

inline constexpr size_t kMaxRelayRequestEnvelope = 10967;

struct RelayRequest {
    std::vector<std::byte> request_bytes;
};

using RelayRequestResult = std::variant<RelayRequest, BackendError>;

RelayRequestResult parseRelayEnvelope(std::span<const std::byte> body);

} // namespace xovm::cloud_material

#endif
