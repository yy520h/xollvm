//===-- VMRuntime_CloudMaterial.cpp - Cloud Material Runtime -------------===//
//
// Task 5/8: Runtime cloud material window fetching and validation
// Task 7/8: SHA256 commitment verification
//
// This module provides the runtime interface for fetching and validating
// cloud material windows during VM execution. It is packaged as a separate
// static library (xollvm-cloud-material-runtime) that user binaries link
// against; the obfuscator pass plugin only *declares* these symbols in the
// IR it generates and never defines them.
//
// Material location resolution order:
//   1. XOLLVM_CLOUD_EXPORT_DIR env var (testing / explicit override)
//   2. <dir-of-loaded-module>/<module-basename>.material
//      (matches the compile-time auto-export: clang injects
//      -obf-material-export-dir=<output>.material, so the .material dir
//      sits next to the produced .so / executable)
//   3. <cwd>/<module-basename>.material  (fallback)
//
//===----------------------------------------------------------------------===//

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <sys/stat.h>

// dladdr for resolving the host module path (Android API 21+, Linux glibc).
#if defined(__linux__) || defined(__ANDROID__)
  #include <dlfcn.h>
  #define XOVM_HAVE_DLADDR 1
#else
  #define XOVM_HAVE_DLADDR 0
#endif

// SHA256 implementation provided by VMRuntime_SHA256.cpp
extern "C" {
    void compute_sha256(const uint8_t* data, size_t len, uint8_t* output);
    int verify_sha256(const uint8_t* data, size_t len, const uint8_t* expected_hash);
}

namespace {

// Emit debug diagnostics to stderr only when XOLLVM_CLOUD_DEBUG is set, so
// production builds stay quiet. We read the env var directly on each call
// (getenv is cheap) rather than caching it in a function-local static, which
// would require the C++ runtime guard (__cxa_guard_acquire) and force every
// C user to link libc++.
inline bool cloud_debug_enabled() {
    const char* v = getenv("XOLLVM_CLOUD_DEBUG");
    return v && (v[0] == '1' || v[0] == 'y' || v[0] == 'Y');
}

inline void cloud_log(const char* fmt, ...) {
    if (!cloud_debug_enabled()) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

// Resolve the cloud material export directory into `out` (size out_sz).
// Returns true on success. See file header for resolution order.
bool resolve_export_dir(char* out, size_t out_sz) {
    // 1. Explicit env override.
    const char* env = getenv("XOLLVM_CLOUD_EXPORT_DIR");
    if (env && env[0]) {
        snprintf(out, out_sz, "%s", env);
        return true;
    }

#if XOVM_HAVE_DLADDR
    // 2. Sibling of the loaded module: <dir>/<base>.material
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (dladdr(reinterpret_cast<const void*>(&resolve_export_dir), &info) &&
        info.dli_fname && info.dli_fname[0]) {
        const char* path = info.dli_fname;
        const char* slash = strrchr(path, '/');
        const char* base = slash ? slash + 1 : path;
        size_t dir_len = slash ? static_cast<size_t>(slash - path) : 0;
        size_t need = (dir_len ? dir_len + 1 : 0) + strlen(base) + 9; // +"/" +".material" +NUL
        if (need < out_sz) {
            if (dir_len > 0) {
                memcpy(out, path, dir_len);
                out[dir_len] = '/';
                snprintf(out + dir_len + 1, out_sz - dir_len - 1,
                         "%s.material", base);
            } else {
                snprintf(out, out_sz, "%s.material", base);
            }
            return true;
        }
        // path too long — fall through to cwd-based fallback
    }
#endif

    // 3. Fallback relative to the current working directory, using the
    //    module basename derived from dladdr if available, else a generic
    //    name. This keeps a working default when dladdr is unavailable.
    {
#if XOVM_HAVE_DLADDR
        Dl_info info;
        memset(&info, 0, sizeof(info));
        const char* base = "app";
        if (dladdr(reinterpret_cast<const void*>(&resolve_export_dir), &info) &&
            info.dli_fname && info.dli_fname[0]) {
            const char* slash = strrchr(info.dli_fname, '/');
            base = slash ? slash + 1 : info.dli_fname;
        }
#else
        const char* base = "app";
#endif
        snprintf(out, out_sz, "%s.material", base);
        return true;
    }
}

// Stat-check that a directory exists.
bool dir_exists(const char* path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

} // namespace

// Runtime API called by VM engine to fetch cloud material windows
extern "C" {

/// Check if material is valid and available.
/// @param material_id  Material identifier (format: region__function_name)
/// @return 0 if the material directory is present, non-zero otherwise.
int __zone_check_material(const char* material_id) {
    cloud_log("[CloudMaterial] Checking material: %s\n", material_id ? material_id : "(null)");

    char dir[512];
    if (!resolve_export_dir(dir, sizeof(dir))) {
        cloud_log("[CloudMaterial] Could not resolve export dir\n");
        return -1;
    }

    cloud_log("[CloudMaterial] Using material dir: %s\n", dir);

    if (dir_exists(dir)) {
        // Also confirm the windows subdirectory exists for this material.
        char windows_dir[640];
        snprintf(windows_dir, sizeof(windows_dir), "%s/windows", dir);
        if (!dir_exists(windows_dir)) {
            cloud_log("[CloudMaterial] windows/ subdir missing in %s\n", dir);
            return -2;
        }
        return 0; // Success
    }

    cloud_log("[CloudMaterial] Material directory not found\n");
    return -1; // Not available
}

/// Fetch a cloud material window from the material directory.
/// @param material_id   Material identifier (format: region__function_name)
/// @param window_index  Index of the window to fetch
/// @param out_buffer    Buffer to write the window data (>= window_size bytes)
/// @param window_size   Expected size of the window
/// @param commitment     Expected SHA256 hash for validation (32 bytes), or NULL
/// @return 0 on success, non-zero on failure
int __zone_fetch_window(
    const char* material_id,
    uint32_t window_index,
    uint8_t* out_buffer,
    uint32_t window_size,
    const uint8_t* commitment
) {
    cloud_log("[CloudMaterial] Fetching window %u for material %s (size=%u)\n",
              window_index, material_id ? material_id : "(null)", window_size);

    char dir[512];
    if (!resolve_export_dir(dir, sizeof(dir))) {
        cloud_log("[CloudMaterial] Could not resolve export dir\n");
        return -1;
    }

    // Construct window filename: {dir}/windows/{material_id}_w{idx}_s0.bin
    char window_path[768];
    snprintf(window_path, sizeof(window_path), "%s/windows/%s_w%u_s0.bin",
             dir, material_id ? material_id : "", window_index);

    FILE* f = fopen(window_path, "rb");
    if (!f) {
        cloud_log("[CloudMaterial] ERROR: Failed to open %s\n", window_path);
        return -1;
    }

    size_t bytes_read = fread(out_buffer, 1, window_size, f);
    fclose(f);

    if (bytes_read != window_size) {
        cloud_log("[CloudMaterial] ERROR: Expected %u bytes, got %zu\n",
                  window_size, bytes_read);
        return -2;
    }

    cloud_log("[CloudMaterial] Loaded %zu bytes from %s\n", bytes_read, window_path);

    // Task 7: Verify SHA256 commitment if provided
    if (commitment) {
        cloud_log("[CloudMaterial] Verifying SHA256 commitment...\n");

        uint8_t computed_hash[32];
        compute_sha256(out_buffer, window_size, computed_hash);

        if (!verify_sha256(out_buffer, window_size, commitment)) {
            cloud_log("[CloudMaterial] ERROR: SHA256 verification FAILED - data tampered!\n");
            // Zero out buffer to prevent using tampered data
            memset(out_buffer, 0, window_size);
            return -3;
        }

        cloud_log("[CloudMaterial] SHA256 verification PASSED\n");
    } else {
        cloud_log("[CloudMaterial] No commitment provided - skipping verification\n");
    }

    return 0; // Success
}

/// Get current dispatch offset (used for cloudDispatch mode).
/// @return Current dispatch offset value (0 = valid cloud value)
int __zone_get_dispatch_offset() {
    // This is a placeholder - actual offset is stored in function-specific global
    return 0;
}

} // extern "C"
