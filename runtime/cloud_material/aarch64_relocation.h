#ifndef XOVM_AARCH64_RELOCATION_H
#define XOVM_AARCH64_RELOCATION_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace xovm::material {

// AArch64 relocation type descriptors
enum class Aarch64RelocationType : uint8_t {
    AbsoluteAddrLoad,      // Load absolute address
    PCRelative,            // PC-relative offset
    PageOffset,            // Page + offset form
    ImmediateValue,        // Direct immediate value
};

// Relocation record specification
struct Aarch64RelocationRecord {
    uint32_t offset = 0;           // Offset in code/data
    Aarch64RelocationType type = Aarch64RelocationType::ImmediateValue;
    uint32_t target_value = 0;     // Target address or value
    uint8_t width = 0;             // Bit width (16, 32, 64)
    uint8_t shift = 0;             // Shift amount (for aligned targets)
    uint16_t reserved = 0;
};

// Validates relocation is within acceptable bounds and format
bool validateAarch64Relocation(const Aarch64RelocationRecord &relocation,
                                size_t code_size);

// Applies relocation to code buffer at specified offset
// Returns false if relocation cannot be safely applied
bool applyAarch64Relocation(std::span<uint8_t> code,
                             const Aarch64RelocationRecord &relocation);

// Verifies applied relocation by reading back and comparing
bool verifyAarch64Relocation(std::span<const uint8_t> code,
                              const Aarch64RelocationRecord &relocation);

// Generates relocation records for canonical shard patterns
std::optional<std::vector<Aarch64RelocationRecord>>
generateAarch64ShardRelocations(uint32_t shard_base, uint32_t shard_size);

} // namespace xovm::material

#endif
