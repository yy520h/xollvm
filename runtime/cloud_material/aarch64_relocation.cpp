#include "aarch64_relocation.h"

#include <algorithm>
#include <cstring>

namespace xovm::material {
namespace {

// Maximum allowed relocation offset (must be within code buffer)
constexpr uint32_t kMaxRelocationOffset = 64 * 1024;

// Validates offset and width are within acceptable bounds
bool validateRelocationBounds(const Aarch64RelocationRecord &reloc,
                               size_t code_size) {
    if (reloc.offset >= code_size || reloc.offset >= kMaxRelocationOffset)
        return false;
    if (reloc.width != 16 && reloc.width != 32 && reloc.width != 64)
        return false;
    if (reloc.shift > 3)  // Maximum shift for AArch64 (8 bytes)
        return false;
    return reloc.offset + (reloc.width / 8) <= code_size;
}

}  // namespace

bool validateAarch64Relocation(const Aarch64RelocationRecord &relocation,
                                size_t code_size) {
    if (!validateRelocationBounds(relocation, code_size))
        return false;

    // Validate based on relocation type
    switch (relocation.type) {
    case Aarch64RelocationType::AbsoluteAddrLoad:
        // Absolute address must be 64-bit
        if (relocation.width != 64)
            return false;
        break;
    case Aarch64RelocationType::PCRelative:
        // PC-relative must be 32-bit or 64-bit
        if (relocation.width != 32 && relocation.width != 64)
            return false;
        break;
    case Aarch64RelocationType::PageOffset:
        // Page offset uses 12-bit immediate
        if (relocation.width != 16 && relocation.width != 32)
            return false;
        break;
    case Aarch64RelocationType::ImmediateValue:
        // Immediate must fit in width
        if (relocation.width == 16 && relocation.target_value > 0xffff)
            return false;
        if (relocation.width == 32 && relocation.target_value > 0xffffffff)
            return false;
        break;
    }
    return true;
}

bool applyAarch64Relocation(std::span<uint8_t> code,
                             const Aarch64RelocationRecord &relocation) {
    if (!validateAarch64Relocation(relocation, code.size()))
        return false;

    const size_t offset = relocation.offset;
    const uint8_t width_bytes = relocation.width / 8;

    // Apply relocation based on type
    switch (relocation.type) {
    case Aarch64RelocationType::ImmediateValue: {
        // Direct write of immediate value (little-endian)
        uint32_t value = relocation.target_value;
        if (relocation.shift > 0)
            value >>= relocation.shift;

        for (size_t i = 0; i < width_bytes && offset + i < code.size(); ++i) {
            code[offset + i] = static_cast<uint8_t>(value & 0xff);
            value >>= 8;
        }
        break;
    }
    case Aarch64RelocationType::PCRelative: {
        // PC-relative: address - (current_pc + 4)
        // Assuming relocation.target_value contains absolute address
        // and offset is the PC location
        int64_t relative = static_cast<int64_t>(relocation.target_value) -
                          (static_cast<int64_t>(offset) + 4);

        // For AArch64, PC-relative immediates are typically 19-bit or 26-bit
        // Validate the relative offset fits in the required size
        int64_t min_val = -(1LL << (relocation.width - 1));
        int64_t max_val = (1LL << (relocation.width - 1)) - 1;

        if (relative < min_val || relative > max_val)
            return false;  // Out of range

        // Encode relative offset
        uint32_t encoded = static_cast<uint32_t>(relative) &
                          ((1U << relocation.width) - 1);

        if (relocation.shift > 0)
            encoded >>= relocation.shift;

        for (size_t i = 0; i < width_bytes && offset + i < code.size(); ++i) {
            code[offset + i] = static_cast<uint8_t>(encoded & 0xff);
            encoded >>= 8;
        }
        break;
    }
    case Aarch64RelocationType::AbsoluteAddrLoad: {
        // Absolute address (64-bit only)
        uint64_t addr = relocation.target_value;
        for (size_t i = 0; i < width_bytes && offset + i < code.size(); ++i) {
            code[offset + i] = static_cast<uint8_t>(addr & 0xff);
            addr >>= 8;
        }
        break;
    }
    case Aarch64RelocationType::PageOffset: {
        // Page + offset: split address into 12-bit page and offset
        // Page bits [31:12] + offset bits [11:0]
        uint32_t target = relocation.target_value;
        uint32_t page = (target >> 12) & 0xfffff;  // 20-bit page
        uint32_t offset_bits = target & 0xfff;      // 12-bit offset

        // Write page part
        uint32_t page_encoded = (page & 0xfffff) << relocation.shift;
        for (size_t i = 0; i < width_bytes && offset + i < code.size(); ++i) {
            code[offset + i] = static_cast<uint8_t>(page_encoded & 0xff);
            page_encoded >>= 8;
        }

        // Note: offset is typically handled separately in a following MOVK instruction
        break;
    }
    }
    return true;
}

bool verifyAarch64Relocation(std::span<const uint8_t> code,
                              const Aarch64RelocationRecord &relocation) {
    if (!validateAarch64Relocation(relocation, code.size()))
        return false;

    const size_t offset = relocation.offset;
    const uint8_t width_bytes = relocation.width / 8;

    if (offset + width_bytes > code.size())
        return false;

    // Read back the applied value
    uint32_t read_value = 0;
    for (size_t i = 0; i < width_bytes; ++i) {
        read_value |= static_cast<uint32_t>(code[offset + i]) << (i * 8);
    }

    // Verify based on relocation type
    switch (relocation.type) {
    case Aarch64RelocationType::ImmediateValue: {
        uint32_t expected = relocation.target_value;
        if (relocation.shift > 0)
            expected >>= relocation.shift;
        
        // Mask to width
        if (relocation.width == 16)
            expected &= 0xffff;
        else if (relocation.width == 32)
            expected &= 0xffffffff;

        return read_value == expected;
    }
    case Aarch64RelocationType::PCRelative:
    case Aarch64RelocationType::AbsoluteAddrLoad:
    case Aarch64RelocationType::PageOffset:
        // Context-aware types cannot be verified locally
        return false;
    }
    return false;
}

std::optional<std::vector<Aarch64RelocationRecord>>
generateAarch64ShardRelocations(uint32_t shard_base, uint32_t shard_size) {
    // Currently generates no relocations - all relocations must be explicit
    // and declared; this prevents hidden dependencies
    std::vector<Aarch64RelocationRecord> relocations;
    
    // Future: Generate relocations for specific patterns if needed
    // For now, maintain fail-closed: only explicitly declared relocations
    // from artifact are applied
    
    return relocations;
}

}  // namespace xovm::material
