"""Focused runtime and IR-structure cases for VM demand pruning."""

from __future__ import annotations

from ._common import (
    Registry, render_vm_demand_add_program, render_vm_demand_fadd_program,
    render_vm_demand_icmp_eq_program, render_vm_demand_incompatible_program,
    render_vm_demand_mul_program,
)
from .vm import VM_DEMAND_STABLE_GATES


_BASE_ANN = "obf: vm(minBlocks=1,obfRegIdx=1,encBytecode=1,randISA=0)"


def register(reg: Registry, **_opts) -> None:
    reg.add(
        name="rt_vm_demand_int_add", passes=["vm"], ann_override=_BASE_ANN,
        category="vm", gates=VM_DEMAND_STABLE_GATES + ["vm_demand_int_add_only"],
        src_override=render_vm_demand_add_program(_BASE_ANN),
    )
    reg.add(
        name="rt_vm_demand_int_mul", passes=["vm"], ann_override=_BASE_ANN,
        category="vm", gates=VM_DEMAND_STABLE_GATES + ["vm_demand_int_mul_no_add"],
        src_override=render_vm_demand_mul_program(_BASE_ANN),
    )
    reg.add(
        name="rt_vm_demand_fadd", passes=["vm"], ann_override=_BASE_ANN,
        category="vm", gates=VM_DEMAND_STABLE_GATES + ["vm_demand_fadd_only"],
        src_override=render_vm_demand_fadd_program(_BASE_ANN),
    )
    reg.add(
        name="rt_vm_demand_icmp_eq", passes=["vm"], ann_override=_BASE_ANN,
        category="vm", gates=VM_DEMAND_STABLE_GATES + ["vm_demand_icmp_eq_only"],
        src_override=render_vm_demand_icmp_eq_program(_BASE_ANN),
    )
    reg.add(
        name="rt_vm_demand_witness", passes=["vm"], ann_override=_BASE_ANN,
        category="vm", witness_required=True,
        src_override=render_vm_demand_add_program(_BASE_ANN),
    )
    for threaded in (0, 1):
        annotation = ("obf: vm(minBlocks=1,hardened=0,handlerVariants=1,"
                      "encDispatch=1,randISA=0,threadedDispatch=" + str(threaded) + ")")
        reg.add(
            name=f"rt_vm_demand_invalid_dispatch_{threaded}", passes=["vm"],
            ann_override=annotation, category="vm",
            gates=["vm_demand_invalid_dispatch"],
            src_override=render_vm_demand_add_program(annotation),
        )
    annotation = "obf: vm(minBlocks=1,hardened=0,handlerVariants=1,randISA=0)"
    reg.add(
        name="rt_vm_demand_invalid_subop", passes=["vm"],
        ann_override=annotation, category="vm", gates=["vm_demand_invalid_subop"],
        src_override=render_vm_demand_mul_program(annotation),
    )

    rand_off = "obf: vm(minBlocks=1,obfRegIdx=1,encBytecode=1,randISA=0)"
    rand_on = "obf: vm(minBlocks=1,obfRegIdx=1,encBytecode=1,randISA=1)"
    reg.add(
        name="rt_vm_demand_incompatible_configs", passes=["vm"],
        ann_override=rand_off, category="vm",
        gates=["vm_demand_incompatible_engines"],
        src_override=render_vm_demand_incompatible_program(rand_off, rand_on),
    )
