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

// Serialization layout (12 bytes, little-endian):
//   [0..3]  offset          u32 LE
//   [4..7]  target_value    u32 LE
//   [8]     type            u8
//   [9]     width           u8
//   [10]    shift           u8
//   [11]    reserved        u8 (must be 0)
static constexpr size_t kRelocationRecordSize = 12;

std::vector<uint8_t> serializeAarch64Relocation(
    const Aarch64RelocationRecord &reloc) {
    std::vector<uint8_t> out(kRelocationRecordSize, 0);
    out[0] = static_cast<uint8_t>(reloc.offset);
    out[1] = static_cast<uint8_t>(reloc.offset >> 8);
    out[2] = static_cast<uint8_t>(reloc.offset >> 16);
    out[3] = static_cast<uint8_t>(reloc.offset >> 24);
    out[4] = static_cast<uint8_t>(reloc.target_value);
    out[5] = static_cast<uint8_t>(reloc.target_value >> 8);
    out[6] = static_cast<uint8_t>(reloc.target_value >> 16);
    out[7] = static_cast<uint8_t>(reloc.target_value >> 24);
    out[8] = static_cast<uint8_t>(reloc.type);
    out[9] = reloc.width;
    out[10] = reloc.shift;
    out[11] = 0; // reserved
    return out;
}

std::optional<Aarch64RelocationRecord> deserializeAarch64Relocation(
    std::span<const uint8_t> bytes) {
    if (bytes.size() != kRelocationRecordSize)
        return std::nullopt;
    if (bytes[11] != 0) // reserved must be 0
        return std::nullopt;
    Aarch64RelocationRecord reloc;
    reloc.offset = static_cast<uint32_t>(bytes[0]) |
                   (static_cast<uint32_t>(bytes[1]) << 8) |
                   (static_cast<uint32_t>(bytes[2]) << 16) |
                   (static_cast<uint32_t>(bytes[3]) << 24);
    reloc.target_value = static_cast<uint32_t>(bytes[4]) |
                         (static_cast<uint32_t>(bytes[5]) << 8) |
                         (static_cast<uint32_t>(bytes[6]) << 16) |
                         (static_cast<uint32_t>(bytes[7]) << 24);
    reloc.type = static_cast<Aarch64RelocationType>(bytes[8]);
    reloc.width = bytes[9];
    reloc.shift = bytes[10];
    reloc.reserved = 0;
    // Reject unknown type values
    switch (reloc.type) {
    case Aarch64RelocationType::AbsoluteAddrLoad:
    case Aarch64RelocationType::PCRelative:
    case Aarch64RelocationType::PageOffset:
    case Aarch64RelocationType::ImmediateValue:
        break;
    default:
        return std::nullopt;
    }
    return reloc;
}

std::vector<uint8_t> serializeAarch64Relocations(
    const std::vector<Aarch64RelocationRecord> &relocs) {
    std::vector<uint8_t> out;
    out.reserve(relocs.size() * kRelocationRecordSize);
    for (const auto &r : relocs) {
        auto rec = serializeAarch64Relocation(r);
        out.insert(out.end(), rec.begin(), rec.end());
    }
    return out;
}

std::optional<std::vector<Aarch64RelocationRecord>> deserializeAarch64Relocations(
    std::span<const uint8_t> bytes) {
    if (bytes.size() % kRelocationRecordSize != 0)
        return std::nullopt;
    std::vector<Aarch64RelocationRecord> out;
    out.reserve(bytes.size() / kRelocationRecordSize);
    for (size_t i = 0; i < bytes.size(); i += kRelocationRecordSize) {
        auto rec = deserializeAarch64Relocation(bytes.subspan(i, kRelocationRecordSize));
        if (!rec) return std::nullopt;
        out.push_back(*rec);
    }
    return out;
}

bool applyAarch64Relocations(std::span<uint8_t> code,
                              const std::vector<Aarch64RelocationRecord> &relocs) {
    for (const auto &r : relocs) {
        if (!applyAarch64Relocation(code, r))
            return false;
    }
    return true;
}

std::optional<std::vector<Aarch64RelocationRecord>>
generateAarch64ShardRelocations(uint32_t shard_base, uint32_t shard_size) {
    // Current shard templates are fully position-independent: loadPointer/
    // storeRegister use structure-field offsets passed via x0, and putImmediate
    // encodes only VM instruction indices and status constants (0/1/2).
    // No native addresses are embedded at compile time, so no relocation
    // records are needed for the standard templates.
    //
    // When future shard templates embed dispatch-table pointers or other
    // load-time addresses via putImmediate(reg, abs_addr), add scanning logic
    // here: walk 4-byte-aligned instructions, recognise MOVZ/MOVK pairs whose
    // combined value falls in [shard_base, shard_base + shard_size), and emit
    // an ImmediateValue record for each such field.
    (void)shard_base;
    (void)shard_size;
    return std::vector<Aarch64RelocationRecord>{};
}

}  // namespace xovm::material
