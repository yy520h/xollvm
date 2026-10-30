#ifndef XOVM_ELF_AUDIT_RULES_H
#define XOVM_ELF_AUDIT_RULES_H

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace xovm::material {

// ELF audit rule types
enum class ElfAuditRuleType : uint8_t {
    W_XOR_X = 0,           // Write XOR Execute - W^X constraint
    NoWritableCode = 1,     // Code sections must not be writable
    NoExecutableData = 2,   // Data sections must not be executable
    DispatchOnly = 3,       // Only allowed dispatch patterns
    SymbolNotLeaked = 4,    // Symbol addresses not leaked
    RelocationBounds = 5,   // Relocation targets within bounds
};

// ELF section information for audit
struct ElfSectionInfo {
    uint32_t section_index = 0;
    uint64_t address = 0;
    uint64_t size = 0;
    uint32_t flags = 0;  // SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR
    const char *name = nullptr;
};

// Audit result
struct ElfAuditResult {
    bool passed = false;
    ElfAuditRuleType rule_type = ElfAuditRuleType::W_XOR_X;
    uint32_t violation_count = 0;
    const char *violation_reason = nullptr;
};

// W^X audit - verify no section is both writable and executable
ElfAuditResult auditWriteXorExecute(
    std::span<const ElfSectionInfo> sections);

// No writable code - verify code sections are not writable
ElfAuditResult auditNoWritableCode(
    std::span<const ElfSectionInfo> sections);

// No executable data - verify data sections are not executable
ElfAuditResult auditNoExecutableData(
    std::span<const ElfSectionInfo> sections);

// Dispatch pattern validation - only certain patterns allowed
ElfAuditResult auditDispatchPatterns(
    std::span<const uint8_t> code);

// Symbol leak detection - symbol addresses not in data/strings
ElfAuditResult auditSymbolNotLeaked(
    std::span<const uint8_t> data);

// Relocation bounds checking
struct RelocationInfo {
    uint64_t offset = 0;
    uint64_t target = 0;
    uint8_t type = 0;
};

ElfAuditResult auditRelocationBounds(
    std::span<const RelocationInfo> relocations,
    uint64_t code_base, uint64_t code_size);

} // namespace xovm::material

#endif
