//===-- VMRuntime_CloudMaterial.h - Cloud Material Runtime API -----------===//
//
// Task 5/8: Runtime cloud material window fetching and validation
//
// This header defines the runtime API for cloud material operations.
// These functions are called by the generated VM code at runtime.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_OBFUSCATOR_VMRUNTIME_CLOUDMATERIAL_H
#define LLVM_TRANSFORMS_OBFUSCATOR_VMRUNTIME_CLOUDMATERIAL_H

#include <cstdint>

extern "C" {

/// Fetch a cloud material window from the cloud service
/// @param material_id - Material identifier (format: region__function_name)
/// @param window_index - Index of the window to fetch
/// @param out_buffer - Buffer to write the window data (must be at least window_size bytes)
/// @param window_size - Expected size of the window
/// @param commitment - Expected SHA256 hash for validation (32 bytes)
/// @return 0 on success, non-zero on failure
int __zone_fetch_window(
    const char* material_id,
    uint32_t window_index,
    uint8_t* out_buffer,
    uint32_t window_size,
    const uint8_t* commitment
);

/// Check if a cloud material is available and valid
/// @param material_id - Material identifier
/// @return 0 if valid, non-zero if expired/invalid
int __zone_check_material(const char* material_id);

/// Get dispatch offset for cloud-dispatch mode
/// Used by cloudDispatch feature to redirect execution on invalid/expired material
/// @return 0 if cloud value is valid, non-zero offset if invalid
int __zone_get_dispatch_offset();

} // extern "C"

#endif // LLVM_TRANSFORMS_OBFUSCATOR_VMRUNTIME_CLOUDMATERIAL_H
