#include <stdint.h>

__attribute__((annotate("obf: antidebug(tracerPid=1)")))
uint32_t antidebug_target(uint32_t x) {
    return x + 1u;
}

__attribute__((annotate("obf: antidebug(ptrace=1,timing=1,maps=1)")))
uint32_t antidebug_all(uint32_t x) {
    return x + 3u;
}

uint32_t plain_target(uint32_t x) {
    return x + 2u;
}
