"""End-to-end cases for explicitly configured target-side anti-debugging."""

from __future__ import annotations

from ._common import Registry, TestCase


def _program(annotation: str) -> str:
    return f'''#include <stdint.h>
#include <stdio.h>
__attribute__((annotate("{annotation}")))
uint32_t obf_target(uint32_t x) {{ return x + 9u; }}
int main(void) {{ printf("%u\\n", obf_target(7)); return 0; }}
'''


def register(reg: Registry, **_opts) -> None:
    reg.add(
        name="antidebug_default_off",
        passes=["vm"],
        gates=["antidebug_default_off"],
        category="vm",
        src_override=_program("obf: vm(minBlocks=1)"),
        correctness=True,
    )
    reg.add(
        name="antidebug_tracer",
        passes=["antidebug"],
        gates=["antidebug_tracer_symbols"],
        category="vm",
        src_override=_program("obf: antidebug(tracerPid=1)"),
        correctness=True,
    )
    reg.add(
        name="antidebug_dynamic",
        passes=["antidebug"],
        gates=["antidebug_dynamic_singleton"],
        category="vm",
        src_override=_program("obf: antidebug(tracerPid=1,dynamic=1,interval=100)"),
        correctness=True,
    )
