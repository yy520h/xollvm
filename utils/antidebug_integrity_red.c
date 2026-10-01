#include <stdint.h>

__attribute__((annotate("obf: vm(minBlocks=1), antidebug(integrity=1)")))
uint32_t integrity_target(uint32_t x, uint32_t y) {
    if (x == y)
        return x + 1u;
    return x ^ y;
}

__attribute__((annotate("obf: antidebug(tracerPid=1,dynamic=1,interval=100)")))
uint32_t dynamic_target(uint32_t x) {
    return x ^ 7u;
}
