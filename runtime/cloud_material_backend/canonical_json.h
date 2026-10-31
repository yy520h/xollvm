#ifndef XOVM_CLOUD_MATERIAL_BACKEND_CANONICAL_JSON_H
#define XOVM_CLOUD_MATERIAL_BACKEND_CANONICAL_JSON_H

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

namespace xovm::cloud_material {

inline constexpr size_t kMaxCanonicalRequest = 8192;
inline constexpr size_t kMaxRawResponse = 16777216;
inline constexpr char kProtocolSuite[] = "X25519-Ed25519-HKDF-SHA256-AES256GCM";

struct BackendError {
    std::string code;
};

struct Request {
    nlohmann::json value;
    std::vector<std::byte> original_bytes;
};

using RequestResult = std::variant<Request, BackendError>;

RequestResult parseCanonicalRequest(std::span<const std::byte> bytes);

} // namespace xovm::cloud_material

#endif
