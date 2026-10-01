#pragma once

#include <cstdint>
#include <string>

namespace xollvm {

std::string deriveDispatchKey(const std::string& signedBlob, uint64_t clientTick);
uint64_t readClientTick();
std::string computeWindowId(uint64_t serverTime, uint64_t windowSeconds);

}  // namespace xollvm
