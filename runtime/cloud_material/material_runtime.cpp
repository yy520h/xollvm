#include "material_store.h"

#include <time.h>

namespace xovm::material {

uint64_t bootTimeNs() {
    timespec value{};
    if (clock_gettime(CLOCK_BOOTTIME, &value) != 0 || value.tv_sec < 0) return 0;
    const auto seconds = static_cast<uint64_t>(value.tv_sec);
    if (seconds > UINT64_MAX / 1000000000ULL) return 0;
    return seconds * 1000000000ULL + static_cast<uint64_t>(value.tv_nsec);
}

} // namespace xovm::material
