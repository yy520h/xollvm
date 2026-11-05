#include "elf_audit_rules.h"

#include <algorithm>

namespace xovm::material {

// ELF section flags (matching ELF standard)
constexpr uint32_t SHF_WRITE = 0x1;
constexpr uint32_t SHF_ALLOC = 0x2;
constexpr uint32_t SHF_EXECINSTR = 0x4;

ElfAuditResult auditWriteXorExecute(
    std::span<const ElfSectionInfo> sections) {
    ElfAuditResult result{true, ElfAuditRuleType::W_XOR_X, 0, nullptr};

    for (const auto &section : sections) {
        bool is_writable = (section.flags & SHF_WRITE) != 0;
        bool is_executable = (section.flags & SHF_EXECINSTR) != 0;

        // W^X violation: section is both writable and executable
        if (is_writable && is_executable) {
            result.passed = false;
            result.violation_count++;
            result.violation_reason = "Section is both writable and executable";
        }
    }

    return result;
}

ElfAuditResult auditNoWritableCode(
    std::span<const ElfSectionInfo> sections) {
    ElfAuditResult result{true, ElfAuditRuleType::NoWritableCode, 0, nullptr};

    for (const auto &section : sections) {
        // Code section is one that is executable and allocated
        bool is_code = (section.flags & SHF_EXECINSTR) != 0 &&
                      (section.flags & SHF_ALLOC) != 0;
        bool is_writable = (section.flags & SHF_WRITE) != 0;

        if (is_code && is_writable) {
            result.passed = false;
            result.violation_count++;
            result.violation_reason = "Code section is writable";
        }
    }

    return result;
}

ElfAuditResult auditNoExecutableData(
    std::span<const ElfSectionInfo> sections) {
    ElfAuditResult result{true, ElfAuditRuleType::NoExecutableData, 0, nullptr};

    for (const auto &section : sections) {
        // Data section is one that is writable and allocated but not code
        bool is_data = (section.flags & SHF_WRITE) != 0 &&
                      (section.flags & SHF_ALLOC) != 0 &&
                      (section.flags & SHF_EXECINSTR) == 0;
        bool is_executable = (section.flags & SHF_EXECINSTR) != 0;

        if (is_data && is_executable) {
            result.passed = false;
            result.violation_count++;
            result.violation_reason = "Data section is executable";
        }
    }

    return result;
}

ElfAuditResult auditDispatchPatterns(
    std::span<const uint8_t> code) {
    ElfAuditResult result{true, ElfAuditRuleType::DispatchOnly, 0, nullptr};

    // Currently allows all patterns as baseline
    // Future: implement specific dispatch pattern validation
    // e.g., only RET, BR, indirect jumps through validated registers
    
    return result;
}

ElfAuditResult auditSymbolNotLeaked(
    std::span<const uint8_t> data) {
    ElfAuditResult result{true, ElfAuditRuleType::SymbolNotLeaked, 0, nullptr};

    // Currently baseline - no symbol leak detection implemented
    // Future: check for symbol addresses embedded in data sections
    // by comparing against symbol table
    
    return result;
}

ElfAuditResult auditRelocationBounds(
    std::span<const RelocationInfo> relocations,
    uint64_t code_base, uint64_t code_size) {
    ElfAuditResult result{true, ElfAuditRuleType::RelocationBounds, 0, nullptr};

    const uint64_t code_end = code_base + code_size;

    for (const auto &reloc : relocations) {
        // Relocation offset must be within code section
        if (reloc.offset < code_base || reloc.offset >= code_end) {
            result.passed = false;
            result.violation_count++;
            result.violation_reason = "Relocation offset out of bounds";
            continue;
        }

        // For certain relocation types, target must also be in valid range
        // (depending on relocation type - some allow external references)
        // Current: permissive - only check offset bounds
    }

    return result;
}

}  // namespace xovm::material
