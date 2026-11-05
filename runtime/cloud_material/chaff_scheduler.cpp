#include "chaff_scheduler.h"

namespace xovm::material {

ChaffStep ChaffScheduler::next(uint64_t continuation) const {
    uint64_t value = seed_ ^ (continuation + 0x9e3779b97f4a7c15ULL);
    value ^= value >> 30;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31;
    return {static_cast<bool>(value & 1), static_cast<uint32_t>((value >> 1) & 3),
            static_cast<size_t>((value >> 3) & 31) * 8};
}

} // namespace xovm::material
