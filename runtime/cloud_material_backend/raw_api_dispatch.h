#ifndef XOVM_CLOUD_MATERIAL_BACKEND_RAW_API_DISPATCH_H
#define XOVM_CLOUD_MATERIAL_BACKEND_RAW_API_DISPATCH_H

#include "cloud_api.h"
#include "raw_session.h"
#include "../cloud_material/raw_protocol.h"

#include <cstdint>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace xovm::cloud_material {

struct RawApiDispatchError {
    std::string code;
};

class RawApiDispatch {
public:
    explicit RawApiDispatch(CloudApi api) : api_(std::move(api)) {}

    std::variant<std::vector<uint8_t>, RawApiDispatchError> handle(
        const AuthenticatedRawContext &context,
        const xovm::material::RawFrameHeader &header,
        std::span<const uint8_t> payload) const;
    static std::vector<uint8_t> encodeError(const RawApiDispatchError &error);

private:
    CloudApi api_;
};

} // namespace xovm::cloud_material

#endif
