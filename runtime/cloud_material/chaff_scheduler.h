#ifndef XOVM_CHAFF_SCHEDULER_H
#define XOVM_CHAFF_SCHEDULER_H

#include <cstddef>
#include <cstdint>

namespace xovm::material {

struct ChaffStep {
    bool execute = false;
    uint32_t variant = 0;
    size_t scratch_bytes = 0;
};

class ChaffScheduler {
public:
    explicit ChaffScheduler(uint64_t seed) : seed_(seed) {}
    ChaffStep next(uint64_t continuation) const;

private:
    uint64_t seed_ = 0;
};

} // namespace xovm::material

#endif
