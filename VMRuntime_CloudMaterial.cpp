//===-- VMRuntime_CloudMaterial.cpp - Cloud Material Runtime -------------===//
//
// Task 5/8: Runtime cloud material window fetching and validation
// Task 7/8: SHA256 commitment verification
//
// This module provides the runtime interface for fetching and validating
// cloud material windows during VM execution.
//
//===----------------------------------------------------------------------===//

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>

// SHA256 implementation provided by VMRuntime_SHA256.cpp
extern "C" {
    void compute_sha256(const uint8_t* data, size_t len, uint8_t* output);
    int verify_sha256(const uint8_t* data, size_t len, const uint8_t* expected_hash);
}

// Runtime API called by VM engine to fetch cloud material windows
extern "C" {

/// Check if material is valid and available
/// @param material_id - Material identifier (format: region__function_name)
/// @return 0 if valid, non-zero if invalid
int __zone_check_material(const char* material_id) {
    fprintf(stderr, "[CloudMaterial] Checking material: %s\n", material_id);

    // In production, this would query the cloud service
    // For now, we check if the export directory exists
    const char* export_dir = getenv("XOLLVM_CLOUD_EXPORT_DIR");
    if (!export_dir) {
        export_dir = "./cloud_test_export";
    }

    struct stat st;
    if (stat(export_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
        fprintf(stderr, "[CloudMaterial] Material directory found\n");
        return 0; // Success
    }

    fprintf(stderr, "[CloudMaterial] Material not available\n");
    return -1; // Not available
}

/// Fetch a cloud material window from the cloud service
/// @param material_id - Material identifier (format: region__function_name)
/// @param window_index - Index of the window to fetch
/// @param out_buffer - Buffer to write the window data (must be at least window_size bytes)
/// @param window_size - Expected size of the window
/// @param commitment - Expected SHA256 hash for validation (32 bytes), or NULL to skip
/// @return 0 on success, non-zero on failure
int __zone_fetch_window(
    const char* material_id,
    uint32_t window_index,
    uint8_t* out_buffer,
    uint32_t window_size,
    const uint8_t* commitment
) {
    fprintf(stderr, "[CloudMaterial] Fetching window %u for material %s (size=%u)\n",
            window_index, material_id, window_size);

    // In production, this would make an HTTP request to the cloud service
    // For testing, we load from local filesystem
    const char* export_dir = getenv("XOLLVM_CLOUD_EXPORT_DIR");
    if (!export_dir) {
        export_dir = "./cloud_test_export";
    }

    // Construct window filename: {export_dir}/windows/{material_id}_w{idx}_s0.bin
    char window_path[512];
    snprintf(window_path, sizeof(window_path), "%s/windows/%s_w%u_s0.bin",
             export_dir, material_id, window_index);

    // Load window from file
    FILE* f = fopen(window_path, "rb");
    if (!f) {
        fprintf(stderr, "[CloudMaterial] ERROR: Failed to open %s\n", window_path);
        return -1;
    }

    // Read window data
    size_t bytes_read = fread(out_buffer, 1, window_size, f);
    fclose(f);

    if (bytes_read != window_size) {
        fprintf(stderr, "[CloudMaterial] ERROR: Expected %u bytes, got %zu\n",
                window_size, bytes_read);
        return -2;
    }

    fprintf(stderr, "[CloudMaterial] Loaded %zu bytes from %s\n", bytes_read, window_path);

    // Task 7: Verify SHA256 commitment if provided
    if (commitment) {
        fprintf(stderr, "[CloudMaterial] Verifying SHA256 commitment...\n");
        fprintf(stderr, "[CloudMaterial] Expected hash: ");
        for (int i = 0; i < 32; i++) {
            fprintf(stderr, "%02x", commitment[i]);
        }
        fprintf(stderr, "\n");

        // Compute hash of fetched data
        uint8_t computed_hash[32];
        compute_sha256(out_buffer, window_size, computed_hash);

        fprintf(stderr, "[CloudMaterial] Computed hash: ");
        for (int i = 0; i < 32; i++) {
            fprintf(stderr, "%02x", computed_hash[i]);
        }
        fprintf(stderr, "\n");

        // Verify commitment matches
        if (!verify_sha256(out_buffer, window_size, commitment)) {
            fprintf(stderr, "[CloudMaterial] ERROR: SHA256 verification FAILED - data tampered!\n");
            // Zero out buffer to prevent using tampered data
            memset(out_buffer, 0, window_size);
            return -3;
        }

        fprintf(stderr, "[CloudMaterial] SHA256 verification PASSED\n");
    } else {
        fprintf(stderr, "[CloudMaterial] No commitment provided - skipping verification\n");
    }

    return 0; // Success
}

/// Get current dispatch offset (used for cloudDispatch mode)
/// @return Current dispatch offset value
int __zone_get_dispatch_offset() {
    // This is a placeholder - actual offset is stored in function-specific global
    return 0;
}

} // extern "C"
