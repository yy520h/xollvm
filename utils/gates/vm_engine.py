"""VM pass v7 shared-engine gates (Step 06)."""

from __future__ import annotations

import re
from typing import Optional

from . import register
from ._ir import extract_fn_body


def _engine_bodies(ir: str) -> list[str]:
    bodies = []
    for match in re.finditer(
            r"^define internal void @(?:\"([^\"]+)\"|([\w.$]+))\(",
            ir, re.MULTILINE):
        name = match.group(1) or match.group(2)
        if name.startswith("__vm_engine"):
            body = extract_fn_body(ir, name)
            if body is not None:
                bodies.append(body)
    return bodies


def _vm_labels(engine: str) -> set[str]:
    return set(re.findall(r"^vm\.opc\.([\w]+)(?:\.v\d+)?\d*:",
                          engine, re.MULTILINE))


def _semantic_labels(engine: str, prefix: str) -> set[str]:
    return set(re.findall(r"^" + re.escape(prefix) + r"\.([a-z_]+)\d*\s*:",
                          engine, re.MULTILINE))


def _semantic_ops(engine: str, prefix: str, operations: set[str]) -> set[str]:
    return _semantic_labels(engine, prefix) & operations


_BINOP_OPS = {"add", "sub", "mul", "and", "or", "xor", "shl", "lshr",
              "ashr", "sdiv", "udiv", "srem", "urem"}
_FBINOP_OPS = {"add", "sub", "mul", "div", "rem"}
_ICMP_PREDICATES = {"eq", "ne", "ugt", "uge", "ult", "ule", "sgt", "sge",
                    "slt", "sle"}


def _one_engine(ir: str) -> tuple[str | None, str | None]:
    engines = _engine_bodies(ir)
    if not engines:
        return None, "no internal __vm_engine definition found"
    if len(engines) != 1:
        return None, f"expected one compatible engine, found {len(engines)}"
    return engines[0], None


@register("vm_demand_int_add_only")
def vm_demand_int_add_only(ir: str) -> Optional[str]:
    engine, error = _one_engine(ir)
    if error or engine is None:
        return error or "VM engine body unavailable"
    labels = _vm_labels(engine)
    if "binop" not in labels:
        return "integer-add engine has no OP_BINOP handler"
    if not re.search(r"^vm\.bo\.add(?:\d*)\s*:", engine, re.MULTILINE):
        return "integer-add engine lacks an explicit vm.bo.add semantic branch"
    expected = {"store32", "load32", "binop", "ret_int"}
    forbidden = sorted(labels - expected)
    if forbidden:
        return f"integer-add engine contains handlers outside its demand closure: {forbidden}"
    extra_subops = sorted(_semantic_ops(engine, "vm.bo", _BINOP_OPS) - {"add"})
    if extra_subops:
        return f"integer-add engine contains unused BINOP subops: {extra_subops}"
    if "urem" in _semantic_ops(engine, "vm.bo", _BINOP_OPS):
        return "integer-add engine contains unused integer remainder subop"
    if _semantic_ops(engine, "vm.bof", _FBINOP_OPS):
        return "integer-add engine contains floating BINOP subops"
    return None


@register("vm_demand_int_mul_no_add")
def vm_demand_int_mul_no_add(ir: str) -> Optional[str]:
    engine, error = _one_engine(ir)
    if error or engine is None:
        return error or "VM engine body unavailable"
    labels = _vm_labels(engine)
    expected = {"store32", "load32", "binop", "ret_int"}
    forbidden = sorted(labels - expected)
    if forbidden:
        return f"integer-mul engine contains handlers outside its demand closure: {forbidden}"
    if not re.search(r"^vm\.bo\.mul(?:\d*)\s*:", engine, re.MULTILINE):
        return "integer-mul engine lacks an explicit vm.bo.mul semantic branch"
    extra_subops = sorted(_semantic_ops(engine, "vm.bo", _BINOP_OPS) - {"mul"})
    if extra_subops:
        return f"integer-mul engine contains unused BINOP subops: {extra_subops}"
    if re.search(r"%vm\.add\w*\s*=\s*add i32", engine):
        return "integer-mul engine still contains the default integer-add fallback"
    if re.search(r"^vm\.bo\.def\w*:", engine, re.MULTILINE):
        return "integer-mul engine still has a permissive vm.bo.def fallback block"
    return None


@register("vm_demand_fadd_only")
def vm_demand_fadd_only(ir: str) -> Optional[str]:
    engine, error = _one_engine(ir)
    if error or engine is None:
        return error or "VM engine body unavailable"
    labels = _vm_labels(engine)
    # 实际发射前会扩宽局部 float alloca，并插入精度转换。
    expected = {"store_f", "load_f", "fcast_ff", "binop_f", "ret_f"}
    forbidden = sorted(labels - expected)
    if forbidden:
        return f"float-add engine contains handlers outside its demand closure: {forbidden}"
    if "binop_f" not in labels:
        return "float-add engine has no OP_BINOP_F handler"
    if not re.search(r"^vm\.bof\.add(?:\d*)\s*:", engine, re.MULTILINE):
        return "float-add engine lacks an explicit vm.bof.add semantic branch"
    extra_subops = sorted(_semantic_ops(engine, "vm.bof", _FBINOP_OPS) - {"add"})
    if extra_subops:
        return f"float-add engine contains unused floating BINOP subops: {extra_subops}"
    return None


@register("vm_demand_icmp_eq_only")
def vm_demand_icmp_eq_only(ir: str) -> Optional[str]:
    engine, error = _one_engine(ir)
    if error or engine is None:
        return error or "VM engine body unavailable"
    labels = _vm_labels(engine)
    expected = {"store32", "load32", "icmp", "cast", "ret_int"}
    forbidden = sorted(labels - expected)
    if forbidden:
        return f"icmp-eq engine contains handlers outside its demand closure: {forbidden}"
    if "icmp" not in labels:
        return "icmp-eq engine has no OP_ICMP handler"
    if "icmp64" in labels:
        return "i32 icmp-eq engine contains the unused OP_ICMP64 handler"
    icmp_labels = _semantic_ops(engine, "vm.ic", _ICMP_PREDICATES)
    if "eq" not in icmp_labels:
        return "icmp-eq engine lacks an explicit vm.ic.eq semantic branch"
    extra_predicates = sorted(icmp_labels - {"eq"})
    if extra_predicates:
        return f"icmp-eq engine contains unused ICMP predicates: {extra_predicates}"
    return None


def _engine_blocks(engine: str) -> dict[str, str]:
    labels = list(re.finditer(r"^([\w.$]+):[^\n]*\n", engine, re.MULTILINE))
    return {match.group(1): engine[match.end():labels[i + 1].start()
                                 if i + 1 < len(labels) else len(engine)]
            for i, match in enumerate(labels)}


def _trap_blocks(blocks: dict[str, str]) -> set[str]:
    return {name for name, body in blocks.items()
            if re.search(r"call void @llvm\.trap\(\)", body)
            and re.search(r"^\s*unreachable\b", body, re.MULTILINE)}


@register("vm_demand_invalid_dispatch")
def vm_demand_invalid_dispatch(ir: str) -> Optional[str]:
    engines = _engine_bodies(ir)
    if not engines:
        return "VM engine missing"
    for engine in engines:
        blocks = _engine_blocks(engine)
        traps = _trap_blocks(blocks)
        if not traps:
            return "VM engine lacks an explicit trap/unreachable invalid path"
        # 只检查 opcode/dmap 索引；变体选择及其他宿主取余仍然合法。
        if re.search(r"%(?:vm\.safe|vm\.dm\.slot)\d*\s*=\s*urem\b", engine):
            return "VM dispatch reinterprets an invalid opcode/dmap index using modulo"
        fetches = [body for body in blocks.values()
                   if re.search(r"%vm\.oidx\d*\s*=\s*zext\b", body)]
        if not fetches:
            return "VM engine has no inspectable opcode fetch"
        for body in fetches:
            check = re.search(r"%([\w.$]+)\s*=\s*icmp uge i32 %vm\.oidx\d*, 96\b", body)
            if check is None:
                return "VM fetch lacks an opcode-domain bounds check"
            branch = re.search(r"br i1 %" + re.escape(check.group(1))
                               + r", label %([\w.$]+), label %([\w.$]+)", body)
            if branch is None or branch.group(1) not in traps:
                return "VM opcode bounds failure does not branch to invalid"
            if re.search(r"%(?:vm\.ohsl|vm\.dm\.p)\d*\s*=", body):
                return "VM table lookup occurs before the opcode bounds branch"
            if branch.group(2) not in blocks:
                return "VM valid-opcode continuation is missing"
        for successors in re.findall(r"indirectbr[^\[]*\[([^\]]*)\]", engine):
            if not any(re.search(r"label %" + re.escape(name) + r"(?:,|\s|$)", successors)
                       for name in traps):
                return "VM indirectbr does not declare the invalid destination"
    return None


@register("vm_demand_invalid_subop")
def vm_demand_invalid_subop(ir: str) -> Optional[str]:
    engine, error = _one_engine(ir)
    if error or engine is None:
        return error or "VM engine missing"
    traps = _trap_blocks(_engine_blocks(engine))
    defaults = re.findall(r"switch i32 %vm\.bo(?:64)?\.op(?:\.b)?\d*, label %([\w.$]+)", engine)
    if not defaults:
        return "VM BINOP has no explicit semantic switch"
    if any(default not in traps for default in defaults):
        return "VM BINOP default accepts an invalid subop instead of trapping"
    return None


@register("vm_demand_incompatible_engines")
def vm_demand_incompatible_engines(ir: str) -> Optional[str]:
    engines = _engine_bodies(ir)
    if len(engines) < 2:
        return "incompatible randISA configurations were merged into one VM engine"
    refs = re.findall(r"blockaddress\(@(__vm_engine[\w.$]*),", ir)
    if len(set(refs)) < 2:
        return "incompatible callers do not reference distinct VM engines"
    return None


@register("vm_engine_exists")
def vm_engine_exists(ir: str) -> Optional[str]:
    if not _engine_bodies(ir):
        return "VM engine function not found — shared engine not created"
    return None


@register("vm_engine_singleton")
def vm_engine_singleton(ir: str) -> Optional[str]:
    count = ir.count("define internal void @__vm_engine(")
    if count == 0:
        return "@__vm_engine not found"
    if count != 1:
        return f"expected 1 __vm_engine definition, found {count}"
    return None


@register("vm_wrapper_calls_engine")
def vm_wrapper_calls_engine(ir: str) -> Optional[str]:
    fn = extract_fn_body(ir, "obf_target")
    if fn is None:
        return "obf_target function not found"
    has_direct   = "call void @__vm_engine(" in fn
    has_indirect = bool(re.search(r"call void %[\w.]+\(", fn))
    if not has_direct and not has_indirect:
        return "obf_target does not call __vm_engine (direct or indirect) -- wrapper not generated"
    return None


@register("vm_wrapper_is_thin")
def vm_wrapper_is_thin(ir: str) -> Optional[str]:
    fn = extract_fn_body(ir, "obf_target")
    if fn is None:
        return "obf_target function not found"
    handler_labels = re.findall(r"^vm\.opc\.\w+:", fn, re.MULTILINE)
    if handler_labels:
        return f"obf_target contains handler blocks: {handler_labels[:4]}"
    if "indirectbr" in fn:
        return "obf_target contains indirectbr — should only be in __vm_engine"
    return None


@register("vm_engine_has_handlers")
def vm_engine_has_handlers(ir: str) -> Optional[str]:
    engines = _engine_bodies(ir)
    if not engines:
        return "VM engine function body not found"
    if any(not re.search(r"vm\.opc\.[A-Za-z0-9_.]+\b", engine) for engine in engines):
        return "VM engine has no opcode handler blocks"
    return None


@register("vm_engine_indirectbr")
def vm_engine_indirectbr(ir: str) -> Optional[str]:
    engines = _engine_bodies(ir)
    if not engines:
        return "VM engine function body not found"
    if any("indirectbr" not in engine for engine in engines):
        return "VM engine has no indirectbr — dispatch not indirect"
    return None


@register("vm_engine_dispatch")
def vm_engine_dispatch(ir: str) -> Optional[str]:
    engine = extract_fn_body(ir, "__vm_engine")
    if engine is None:
        return "__vm_engine function body not found"
    if not re.search(r"vm\.dispatch\b", engine):
        return "vm.dispatch not found in __vm_engine"
    return None


@register("vm_multi_fn_shared")
def vm_multi_fn_shared(ir: str) -> Optional[str]:
    handler_globals = re.findall(r"@\w+\.vm\.ophandlers\b", ir)
    engine_refs = ir.count("blockaddress(@__vm_engine,")
    if len(handler_globals) < 2:
        return f"expected 2+ per-function handler tables, found {len(handler_globals)}"
    if engine_refs < 2:
        return f"expected blockaddress(@__vm_engine) in multiple tables, found {engine_refs} refs"
    defcount = ir.count("define internal void @__vm_engine(")
    if defcount != 1:
        return f"expected 1 __vm_engine definition, found {defcount}"
    return None


@register("vm_handlers_permuted")
def vm_handlers_permuted(ir: str) -> Optional[str]:
    tables = re.findall(
        r"@(\w+)\.vm\.ophandlers\s*=[^[]*\[[^\]]*\]\s*\[([^\]]+)\]",
        ir,
    )
    if len(tables) < 2:
        return None
    entries_a = [x.strip() for x in tables[0][1].split(",")]
    entries_b = [x.strip() for x in tables[1][1].split(",")]
    if entries_a == entries_b:
        return f"handler tables for {tables[0][0]} and {tables[1][0]} identical"
    return None
