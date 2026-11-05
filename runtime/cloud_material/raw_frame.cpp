#include "raw_frame.h"

namespace xovm::material {

std::vector<uint8_t> encodeRawFrame(const RawFrameHeader &header,
                                    std::span<const uint8_t> payload) {
    if (payload.size() != header.payload_length) return {};
    const auto encoded = encodeRawFrameHeader(header);
    if (encoded.empty()) return {};
    std::vector<uint8_t> frame = encoded;
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

} // namespace xovm::material
