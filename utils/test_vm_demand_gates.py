"""VM 结构 gate 的正反例，防止裁剪测试误报或漏报。"""

import unittest
import pytest

from gates import run_gate
from vm_hardening_support import annotation, transform


def engine(handlers, semantics=""):
    blocks = "\n".join(f"vm.opc.{name}:\n  unreachable" for name in handlers)
    return f"define internal void @__vm_engine() {{\n{blocks}\n{semantics}\n}}\n"


class DemandGateTests(unittest.TestCase):
    def test_add_allows_only_emitted_memory_and_return_dependencies(self):
        ir = engine(["store32", "load32", "binop", "ret_int"],
                    "vm.bo.add:\n  unreachable\nvm.bo.merge:\n  unreachable")
        self.assertIsNone(run_gate("vm_demand_int_add_only", obf_ir=ir))
        ir = ir.replace("vm.bo.merge:", "vm.bo.mul12623:")
        self.assertIn("unused BINOP", run_gate("vm_demand_int_add_only", obf_ir=ir) or "")

    def test_mul_rejects_implicit_add_fallback(self):
        ir = engine(["store32", "load32", "binop", "ret_int"],
                    "vm.bo.mul:\n  unreachable\nvm.bo.def:\n  unreachable")
        self.assertIn("fallback", run_gate("vm_demand_int_mul_no_add", obf_ir=ir) or "")

    def test_fadd_accepts_dependencies_from_float_alloca_widening(self):
        ir = engine(["store_f", "load_f", "fcast_ff", "binop_f", "ret_f"],
                    "vm.bof.add:\n  unreachable")
        self.assertIsNone(run_gate("vm_demand_fadd_only", obf_ir=ir))

    def test_icmp_requires_explicit_eq_semantics(self):
        ir = engine(["store32", "load32", "icmp", "cast", "ret_int"])
        self.assertIsNotNone(run_gate("vm_demand_icmp_eq_only", obf_ir=ir))
        ir = engine(["store32", "load32", "icmp", "cast", "ret_int"],
                    "vm.ic.eq123:\n  unreachable")
        self.assertIsNone(run_gate("vm_demand_icmp_eq_only", obf_ir=ir))

    def test_dispatch_requires_trap_and_rejects_opcode_modulo(self):
        ir = engine(["ret_int"], """vm.fetch:
  %vm.oidx = zext i8 %raw to i32
  %vm.op.invalid = icmp uge i32 %vm.oidx, 96
  br i1 %vm.op.invalid, label %vm.invalid, label %vm.lookup
vm.lookup:
  %vm.ohsl = getelementptr ptr, ptr %handlers, i32 %vm.oidx
  indirectbr ptr %target, [label %vm.opc.ret_int, label %vm.invalid]
vm.invalid:
  call void @llvm.trap()
  unreachable""")
        self.assertIsNone(run_gate("vm_demand_invalid_dispatch", obf_ir=ir))
        bad = ir.replace("%vm.op.invalid = icmp", "%vm.safe = urem i32 %vm.oidx, 96\n  %vm.op.invalid = icmp")
        self.assertIn("modulo", run_gate("vm_demand_invalid_dispatch", obf_ir=bad) or "")
        bad = ir.replace("call void @llvm.trap()", "; no trap")
        self.assertIsNotNone(run_gate("vm_demand_invalid_dispatch", obf_ir=bad))
        for bound in (56, 97, 256):
            self.assertIsNotNone(run_gate("vm_demand_invalid_dispatch", obf_ir=ir.replace(", 96", f", {bound}")))

    def test_randisa_pruned_predicates_detect_identity(self):
        ir = engine(["icmp"], """vm.ic.check:
  switch i32 %pred, label %vm.invalid [
    i32 39, label %vm.ic.eq
    i32 33, label %vm.ic.ult
  ]
vm.ic.eq:
  unreachable
vm.ic.ult:
  unreachable""")
        self.assertIsNone(run_gate("vm_randisa_icmp_permuted", obf_ir=ir))
        self.assertIsNotNone(run_gate("vm_no_randisa", obf_ir=ir))
        identity = ir.replace("i32 39, label", "i32 32, label").replace("i32 33, label", "i32 36, label")
        self.assertIsNotNone(run_gate("vm_randisa_icmp_permuted", obf_ir=identity))
        self.assertIsNone(run_gate("vm_no_randisa", obf_ir=identity))

    def test_binding_gate_requires_response_to_affect_decode(self):
        ir = """define i32 @obf_target(i32 %salt) {
vm.entry:
  %flag = load atomic i32, ptr @__obf_antidebug_response monotonic, align 4
  %detected = icmp ne i32 %flag, 0
  %vm.ad.bind.poison = select i1 %detected, i32 1234, i32 0
  %vm.ad.bind.salt = xor i32 %salt, %vm.ad.bind.poison
  call void @__vm_engine(ptr null, i32 1, ptr null, ptr null, ptr null, ptr null, ptr null, i32 %vm.ad.bind.salt)
  ret i32 0
}
"""
        self.assertIsNone(run_gate("vm_bindadeb_ctor_present", obf_ir=ir))
        self.assertIsNotNone(run_gate("vm_no_bindadeb_ctor", obf_ir=ir))
        self.assertIsNotNone(run_gate("vm_bindadeb_ctor_present", obf_ir=ir.replace("i32 %vm.ad.bind.salt)", "i32 %salt)")))
        self.assertIsNotNone(run_gate("vm_bindadeb_ctor_present", obf_ir=ir.replace("%flag, 0", "0, 0")))
        self.assertIsNotNone(run_gate("vm_bindadeb_ctor_present", obf_ir=ir.replace("load atomic", "load")))

    def test_binding_rejects_overwritten_store_and_unrelated_callee(self):
        prefix = '''@__obf_antidebug_response = global i32 0
@engine_table = private constant [1 x ptr] [ptr @__vm_engine]
declare void @__vm_engine(ptr, i32, ptr, ptr, ptr, ptr, ptr, i32)
define void @target(i32 %salt, ptr %logger) {
entry:
  %slot = alloca i32
  %flag = load atomic i32, ptr @__obf_antidebug_response monotonic, align 4
  %detected = icmp ne i32 %flag, 0
  %vm.ad.bind.poison = select i1 %detected, i32 1234, i32 0
  %mixed = xor i32 %salt, %vm.ad.bind.poison
  store i32 %mixed, ptr %slot
'''
        call = '  call void @__vm_engine(ptr null, i32 1, ptr null, ptr null, ptr null, ptr null, ptr null, i32 %loaded)\n'
        tail = '  %loaded = load i32, ptr %slot\n' + call + '  ret void\n}\n'
        self.assertIsNone(run_gate('vm_bindadeb_ctor_present', obf_ir=prefix + tail))
        for value in ('%salt', '-1', '0', 'poison', 'undef'):
            self.assertIsNotNone(run_gate('vm_bindadeb_ctor_present', obf_ir=prefix + f'  store i32 {value}, ptr %slot\n' + tail))
            self.assertIsNotNone(run_gate('vm_bindadeb_ctor_present', obf_ir=prefix + f'  br label %next\nnext:\n  store i32 {value}, ptr %slot\n' + tail))
        indirect = prefix + '  %eng = load ptr, ptr @engine_table\n' + tail.replace('@__vm_engine(', '%eng(')
        self.assertIsNone(run_gate('vm_bindadeb_ctor_present', obf_ir=indirect))
        unrelated = prefix + call.replace('@__vm_engine(', '%logger(').replace('%loaded)', '%mixed)') + tail.replace('%loaded)', '%salt)')
        self.assertIsNotNone(run_gate('vm_bindadeb_ctor_present', obf_ir=unrelated))
        self.assertIsNotNone(run_gate('vm_bindadeb_ctor_present', obf_ir=indirect.replace('%eng(', '%logger(')))

    def test_binop_default_must_reach_invalid(self):
        ir = engine(["binop", "ret_int"], """vm.bo.check:
  switch i32 %vm.bo.op.b, label %vm.invalid [
    i32 2, label %vm.bo.mul
  ]
vm.bo.mul:
  unreachable
vm.invalid:
  call void @llvm.trap()
  unreachable""")
        self.assertIsNone(run_gate("vm_demand_invalid_subop", obf_ir=ir))
        bad = ir.replace("label %vm.invalid [", "label %vm.bo.mul [")
        self.assertIsNotNone(run_gate("vm_demand_invalid_subop", obf_ir=bad))

    def test_encoded_handler_table_requires_handler_references(self):
        ir = '@target.vm.targets = private global { ptr } { ptr blockaddress(@__vm_engine.p1, %vm.opc.ret_int) }, section ".obf.vm.targets"\n'
        self.assertIsNone(run_gate("vm_ophandlers_global", obf_ir=ir))
        self.assertIsNotNone(run_gate("vm_ophandlers_global", obf_ir=ir.replace("blockaddress(@__vm_engine.p1, %vm.opc.ret_int)", "null")))

    def test_threaded_gate_checks_every_pool_engine(self):
        ir = engine(["ret_int"], """vm.tail:
  indirectbr ptr %h, [label %vm.opc.ret_int]
vm.tail2:
  indirectbr ptr %h, [label %vm.opc.ret_int]""").replace("@__vm_engine(", "@__vm_engine.p1(")
        self.assertIsNone(run_gate("vm_threaded_no_central_dispatch", obf_ir=ir))
        self.assertIsNotNone(run_gate("vm_threaded_no_central_dispatch", obf_ir=ir + engine(["ret_int"])))

    def test_whitebox_lazy_fetch_requires_a_call(self):
        ir = 'call void @__vm_whitebox_ctr_block(ptr %table, ptr %nonce, i32 %block, ptr %window)'
        self.assertIsNone(run_gate("vm_lazydecrypt_keystream_call", obf_ir=ir))
        self.assertIsNotNone(run_gate("vm_lazydecrypt_keystream_call", obf_ir=ir.replace("call", "declare")))

    def test_engine_gates_inspect_all_pooled_bodies(self):
        ir = engine(["ret_int"], "indirectbr ptr %h, [label %vm.opc.ret_int]").replace("@__vm_engine(", "@__vm_engine.p1(")
        for gate in ("vm_engine_exists", "vm_engine_has_handlers", "vm_engine_indirectbr"):
            self.assertIsNone(run_gate(gate, obf_ir=ir))
            self.assertIsNotNone(run_gate(gate, obf_ir=""))
        self.assertIsNotNone(run_gate("vm_engine_has_handlers", obf_ir=ir + engine([])))
        self.assertIsNotNone(run_gate("vm_engine_indirectbr", obf_ir=ir + engine(["ret_int"])))

    def test_nested_and_perfn_gates_inspect_encoded_descriptors(self):
        ir = engine(["ret_int"]).replace("@__vm_engine(", "@__vm_engine.p1(")
        ir += engine(["binop"]).replace("@__vm_engine(", "@__vm_engine.nest.p1(")
        ir += '@__vm_h_binop_owner.vm.targets = private global { ptr } { ptr blockaddress(@__vm_engine.p1, %vm.opc.ret_int) }, section ".obf.vm.targets"\n'
        ir += '@target.vm.targets = private global { ptr } { ptr blockaddress(@__vm_engine.nest.p1, %vm.opc.binop) }, section ".obf.vm.targets"\n'
        self.assertIsNone(run_gate("vm_nestedvm_helper_virtualized", obf_ir=ir))
        self.assertIsNotNone(run_gate("vm_nestedvm_helper_virtualized", obf_ir=ir.replace("blockaddress(@__vm_engine.p1", "blockaddress(@__vm_engine.nest.p1")))
        self.assertIsNone(run_gate("vm_perfn_engine", obf_ir=ir))
        self.assertIsNotNone(run_gate("vm_perfn_engine", obf_ir=engine(["ret_int"])))
        ir += '@other.vm.targets = private global { ptr } { ptr blockaddress(@__vm_engine.nest.p1, %vm.opc.binop) }, section ".obf.vm.targets"\n'
        ir += '@third.vm.targets = private global { ptr } { ptr blockaddress(@__vm_engine.nest.p1, %vm.opc.binop) }, section ".obf.vm.targets"\n'
        self.assertIsNotNone(run_gate("vm_perfn_engine", obf_ir=ir))


@pytest.mark.parametrize("randisa", [0, 1])
@pytest.mark.parametrize("family,gate", [
    ("icmp", "vm_randisa_icmp_permuted"),
    ("cast", "vm_randisa_cast_permuted"),
    ("fbinop", "vm_randisa_fbinsubop_permuted"),
    ("fcmp", "vm_randisa_fcmp_permuted"),
])
def test_randisa_real_families_reject_identity(tmp_path, randisa, family, gate):
    # 独立列出全部语义，避免裁剪后未用到的 family 被误算为已验证。
    operations = {
        "icmp": [f"%v{i} = icmp {pred} i32 %a, %b\n%r{i} = zext i1 %v{i} to i32"
                 for i, pred in enumerate(("eq", "ne", "ugt", "uge", "ult", "ule", "sgt", "sge", "slt", "sle"))],
        "cast": ["%bit = trunc i32 %a to i1", "%byte = trunc i32 %a to i8", "%half = trunc i32 %a to i16",
                 "%r0 = zext i1 %bit to i32", "%r1 = zext i8 %byte to i32", "%r2 = zext i16 %half to i32",
                 "%r3 = sext i8 %byte to i32", "%r4 = sext i16 %half to i32"],
            "fbinop": [f"%v{i} = {op} double %a, %b\n%r{i} = fptosi double %v{i} to i64"
                   for i, op in enumerate(("fadd", "fsub", "fmul", "fdiv", "frem"))],
        "fcmp": [f"%v{i} = fcmp {pred} double %a, %b\n%r{i} = zext i1 %v{i} to i32"
                 for i, pred in enumerate(("oeq", "ogt", "oge", "olt", "ole", "one", "ord", "uno", "ueq", "ugt", "uge", "ult", "ule", "une"))],
    }
    count = {"icmp": 10, "cast": 5, "fbinop": 5, "fcmp": 14}[family]
    result_type = "i64" if family == "fbinop" else "i32"
    arg_type = "double" if family in ("fbinop", "fcmp") else "i32"
    lines = operations[family]
    previous = "%r0"
    for i in range(1, count):
        lines.append(f"%sum{i} = xor {result_type} {previous}, %r{i}")
        previous = f"%sum{i}"
    body = f"define {result_type} @target({arg_type} %a, {arg_type} %b) {{\n" + "\n".join(lines) + f"\nret {result_type} {previous}\n}}\n"
    ir = transform(tmp_path, body + annotation(["target"],
        f"vm(encBytecode=0,handlerVariants=1,randISA={randisa})"), seed=1).read_text()
    if randisa:
        assert run_gate(gate, obf_ir=ir) is None
        assert run_gate("vm_no_randisa", obf_ir=ir) is not None
    else:
        assert run_gate(gate, obf_ir=ir) is not None
        assert run_gate("vm_no_randisa", obf_ir=ir) is None


def test_randisa_mixed_width_rejects_canonical_icmp64(tmp_path):
    import re
    from gates.vm import _icmp_pred_sequence
    from vm_hardening_support import checked, tools
    predicates = ('eq', 'ne', 'ugt', 'uge', 'ult', 'ule', 'sgt', 'sge', 'slt', 'sle')
    body = ''
    for width in (32, 64):
        lines = []
        for i, pred in enumerate(predicates):
            lines += [f'%c{i} = icmp {pred} i{width} %a, %b', f'%v{i} = zext i1 %c{i} to i32']
        previous = '%v0'
        for i in range(1, 10):
            lines.append(f'%s{i} = xor i32 {previous}, %v{i}')
            previous = f'%s{i}'
        body += f'define i32 @target{width}(i{width} %a, i{width} %b) {{\n' + '\n'.join(lines) + f'\nret i32 {previous}\n}}\n'
    ir = transform(tmp_path, body + annotation(['target32', 'target64'],
        'vm(encBytecode=0,handlerVariants=1,randISA=1)'), seed=1).read_text()
    assert run_gate('vm_randisa_icmp_permuted', obf_ir=ir) is None
    sequence = _icmp_pred_sequence(ir)
    assert sequence is not None and sequence != list(range(32, 42))
    mapping = dict(zip(sequence, range(32, 42)))
    damaged = re.sub(r'(icmp eq i32 %[^,\n]+, )(3[2-9]|4[01])\b',
                     lambda m: m[1] + str(mapping[int(m[2])]), ir)
    path = tmp_path / 'canonical64.ll'
    path.write_text(damaged)
    checked([tools().opt, '-passes=verify', '-disable-output', path])
    assert run_gate('vm_randisa_icmp_permuted', obf_ir=damaged) is not None


if __name__ == "__main__":
    unittest.main()
