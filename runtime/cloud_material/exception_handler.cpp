#include "exception_handler.h"

#include <algorithm>
#include <cstring>

namespace xovm::material {

bool validateDynamicVmException(const DynamicVmException &exception) {
    // Exception type must be valid
    if (static_cast<uint8_t>(exception.type) > static_cast<uint8_t>(DynamicVmExceptionType::ContextCorruption))
        return false;

    // Instruction pointer must be reasonable
    if (exception.instruction_pointer > 1024 * 1024)  // 1MB limit
        return false;

    // Severity must be 0 or 1
    if (exception.severity > 1)
        return false;

    return true;
}

std::optional<uint32_t> handleDynamicVmException(
    const DynamicVmException &exception,
    std::span<const ExceptionHandler> handlers) {
    // Validate exception first
    if (!validateDynamicVmException(exception))
        return std::nullopt;

    // Find matching handler
    for (const auto &handler : handlers) {
        if (handler.exception_type == exception.type) {
            // Only return recovery node for non-fatal exceptions
            if (exception.severity == 0 && handler.recovery_node_id != 0)
                return handler.recovery_node_id;
        }
    }

    // No handler found - fail-closed
    return std::nullopt;
}

bool recordExceptionAudit(const DynamicVmException &exception,
                         const char *reason) {
    // Validate exception
    if (!validateDynamicVmException(exception))
        return false;

    // Currently just validates - actual logging depends on audit infrastructure
    // In fail-closed mode, exceptions don't trigger recovery automatically
    // They must be explicitly handled by the continuation executor

    return true;
}

}  // namespace xovm::material
