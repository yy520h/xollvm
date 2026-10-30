#ifndef XOVM_EXCEPTION_HANDLER_H
#define XOVM_EXCEPTION_HANDLER_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "dynamic_vm_schema.h"

namespace xovm::material {

// Exception types that can be raised during handler execution
enum class DynamicVmExceptionType : uint8_t {
    NoException = 0,
    InvalidRegisterAccess = 1,
    InvalidMemoryAccess = 2,
    InvalidOperand = 3,
    ArithmeticError = 4,
    UnknownOpcode = 5,
    ContextCorruption = 6,
};

// Exception record for handler execution
struct DynamicVmException {
    DynamicVmExceptionType type = DynamicVmExceptionType::NoException;
    uint32_t instruction_pointer = 0;
    uint32_t fault_address = 0;
    uint32_t context_hash = 0;
    uint8_t severity = 0;  // 0=recoverable, 1=fatal
};

// Exception handler specification - defines how to handle exceptions
struct ExceptionHandler {
    uint32_t handler_id = 0;
    DynamicVmExceptionType exception_type = DynamicVmExceptionType::NoException;
    uint32_t recovery_node_id = 0;  // Node to execute for recovery
    uint32_t fault_log_offset = 0;  // Where to log exception info
    uint32_t reserved = 0;
};

// Validates exception is within acceptable bounds
bool validateDynamicVmException(const DynamicVmException &exception);

// Handles exception by selecting appropriate recovery path
std::optional<uint32_t> handleDynamicVmException(
    const DynamicVmException &exception,
    std::span<const ExceptionHandler> handlers);

// Records exception for audit trail (fail-closed: doesn't execute recovery)
bool recordExceptionAudit(const DynamicVmException &exception,
                         const char *reason);

} // namespace xovm::material

#endif
