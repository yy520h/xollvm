#ifndef XOVM_RAW_FRAME_H
#define XOVM_RAW_FRAME_H

#include "raw_protocol.h"

namespace xovm::material {

std::vector<uint8_t> encodeRawFrame(const RawFrameHeader &header,
                                    std::span<const uint8_t> payload);

} // namespace xovm::material

#endif
