"""Structural gates for the opt-in target-side anti-debug pass."""

from __future__ import annotations

import re
from typing import Optional

from . import register


def _declared(ir: str, name: str) -> bool:
    return bool(re.search(rf"(?:declare|define) .*@{re.escape(name)}\b", ir))


@register("antidebug_default_off")
def antidebug_default_off(ir: str) -> Optional[str]:
    forbidden = ("ptrace", "pthread_create", "clock_gettime",
                 "__obf_antidebug", "__obf_ad_", "/proc/self/status", "/proc/self/maps")
    found = [name for name in forbidden if name in ir]
    return f"anti-debug artifacts present by default: {found}" if found else None


@register("antidebug_tracer_symbols")
def antidebug_tracer_symbols(ir: str) -> Optional[str]:
    missing = [name for name in ("fopen", "getline", "fclose", "strtol") if not _declared(ir, name)]
    if missing:
        return f"TracerPid detector missing declarations: {missing}"
    if "/proc/self/status" not in ir:
        return "TracerPid detector path missing"
    if "ptrace" in ir or "clock_gettime" in ir or "pthread_create" in ir:
        return "TracerPid-only configuration emitted unrelated detector symbols"
    return None


@register("antidebug_dynamic_singleton")
def antidebug_dynamic_singleton(ir: str) -> Optional[str]:
    checks = {
        "state": len(re.findall(r"^@__obf_antidebug_monitor_state[^ ]* =", ir, re.M)),
        "monitor": len(re.findall(r"define internal ptr @__obf_antidebug_monitor(?:\.[\d.]+)?\(", ir)),
        "ctor": len(re.findall(r"define internal void @__obf_antidebug_monitor(?:_ctor\.[\d.]+|_ctor|\.[\d.]+_ctor)\(", ir)),
        "dtor": len(re.findall(r"define internal void @__obf_antidebug_monitor(?:_dtor\.[\d.]+|_dtor|\.[\d.]+_dtor)\(", ir)),
        "join": len(re.findall(r"call\b[^\n]*@pthread_join\(", ir)),
        "pthread": ir.count("call i32 @pthread_create"),
    }
    bad = {key: value for key, value in checks.items() if value < 1}
    if bad:
        return f"dynamic monitor artifacts missing: {bad}"
    if any(value != 1 for value in checks.values()):
        return f"dynamic monitor artifacts duplicated: {checks}"
    return None
