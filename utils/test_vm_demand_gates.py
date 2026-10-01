"""VM 结构 gate 的正反例，防止裁剪测试误报或漏报。"""

import unittest

from gates import run_gate


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
  %vm.op.invalid = icmp uge i32 %vm.oidx, 56
  br i1 %vm.op.invalid, label %vm.invalid, label %vm.lookup
vm.lookup:
  %vm.ohsl = getelementptr ptr, ptr %handlers, i32 %vm.oidx
  indirectbr ptr %target, [label %vm.opc.ret_int, label %vm.invalid]
vm.invalid:
  call void @llvm.trap()
  unreachable""")
        self.assertIsNone(run_gate("vm_demand_invalid_dispatch", obf_ir=ir))
        bad = ir.replace("%vm.op.invalid = icmp", "%vm.safe = urem i32 %vm.oidx, 56\n  %vm.op.invalid = icmp")
        self.assertIn("modulo", run_gate("vm_demand_invalid_dispatch", obf_ir=bad) or "")
        bad = ir.replace("call void @llvm.trap()", "; no trap")
        self.assertIsNotNone(run_gate("vm_demand_invalid_dispatch", obf_ir=bad))

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


if __name__ == "__main__":
    unittest.main()
