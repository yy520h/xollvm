from gates import run_gate

import subprocess
from pathlib import Path

import pytest


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


@pytest.mark.parametrize("with_vm", [False, True])
def test_detected_debugger_blocks_business_after_vm_commit(tmp_path, with_vm):
    repo = Path(__file__).resolve().parents[1]
    root = repo.parents[2] if repo.parent.name == ".worktrees" else repo.parent
    opt = root / "build-sensitive/bin/opt"
    clang = root / "build-sensitive/bin/clang"
    ndk = root.parent / "android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64"
    if not opt.exists() or not (ndk / "bin/clang").exists():
        pytest.skip("native Android tools unavailable")
    ann = "obf: antidebug(ptrace=1)"
    if with_vm:
        ann += ", vm(hardened=0,encBytecode=0,lazyDecrypt=0,constInStream=0)"
    data = ann.encode() + b"\0"
    esc = "".join(f"\\{b:02X}" for b in data)
    src = tmp_path / "input.ll"
    src.write_text(
        'target triple = "aarch64-unknown-linux-android26"\n'
        'define i32 @target(i32 %x) { %r = add i32 %x, 7\n ret i32 %r }\n'
        f'@.ann = private constant [{len(data)} x i8] c"{esc}"\n'
        '@llvm.global.annotations = appending global [1 x {ptr,ptr,ptr,i32,ptr}] '
        '[{ptr,ptr,ptr,i32,ptr} {ptr @target,ptr @.ann,ptr @.ann,i32 0,ptr null}]\n')
    obf = tmp_path / "obf.ll"
    subprocess.run([str(opt), "-passes=obfuscation", "-obf-verify", "-S",
                    str(src), "-o", str(obf)], check=True, capture_output=True, text=True)
    lowered = tmp_path / "lowered.ll"
    lowered.write_text("\n".join(line for line in obf.read_text().splitlines()
                                if not line.startswith(("@llvm.global.annotations", "@.ann"))))
    obj = tmp_path / "obf.o"
    subprocess.run([str(clang), "-target", "aarch64-linux-android26", "-c",
                    str(lowered), "-o", str(obj)], check=True, capture_output=True, text=True)
    harness = tmp_path / "harness.c"
    harness.write_text('''
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static int detected;
int __wrap_open(const char *path, int flags, ...) { return 10001; }
ssize_t __wrap_read(int fd, void *out, size_t len) {
    const char *status = detected ? "TracerPid: 23456\\n" : "TracerPid: 0\\n";
    size_t n = strlen(status);
    if (n > len) n = len;
    memcpy(out, status, n);
    return n;
}
int __wrap_close(int fd) { return 0; }
extern int target(int);
int main(int argc, char **argv) {
    detected = argc > 1;
    int result = target(9);
    printf("result=%d\\n", result);
    return result != (detected ? 0 : 16);
}
''')
    exe = tmp_path / "test"
    subprocess.run([str(ndk / "bin/clang"), "--target=aarch64-linux-android26",
                    f"--sysroot={ndk / 'sysroot'}", str(harness), str(obj),
                    "-Wl,--wrap=open", "-Wl,--wrap=read", "-Wl,--wrap=close", "-o", str(exe)],
                   check=True, capture_output=True, text=True)
    for args, expected in (([], "result=16"), (["detected"], "result=0")):
        run = subprocess.run([str(exe), *args], capture_output=True, text=True, timeout=10)
        assert run.returncode == 0, run.stdout + run.stderr
        assert expected in run.stdout
