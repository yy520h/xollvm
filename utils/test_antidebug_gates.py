from gates import run_gate


def test_default_gate_rejects_new_artifacts():
    assert run_gate("antidebug_default_off", obf_ir="define i32 @f() { ret i32 0 }") is None


def test_tracer_gate_requires_only_tracer_dependencies():
    ir = """
declare i32 @open(ptr, i32)
declare i64 @read(i32, ptr, i64)
declare i32 @close(i32)
@path = private constant [18 x i8] c"/proc/self/status\\00"
"""
    assert run_gate("antidebug_tracer_symbols", obf_ir=ir) is None


def test_dynamic_gate_requires_single_thread_creation():
    ir = """
@__obf_antidebug_monitor_state = internal global [4 x i32] zeroinitializer
define internal ptr @__obf_antidebug_monitor(ptr %ctx) { ret ptr null }
define internal void @__obf_antidebug_monitor_ctor() {
  call i32 @pthread_create(ptr null, ptr null, ptr @__obf_antidebug_monitor, ptr null)
  ret void
}
declare i32 @pthread_create(ptr, ptr, ptr, ptr)
"""
    assert run_gate("antidebug_dynamic_singleton", obf_ir=ir) is None
