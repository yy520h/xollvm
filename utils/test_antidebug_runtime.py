"""生成的真实检测器：字段解析、重复调用、SIGINT 和实际调试器附加。"""
import ctypes
import os
import select
import signal
import subprocess
import time
from pathlib import Path

import pytest


@pytest.fixture(scope="module", params=[(vm, detector) for vm in (False, True)
                                       for detector in ("tracerPid", "ptrace")])
def detector_binary(request, tmp_path_factory):
    vm, detector = request.param
    repo = Path(__file__).resolve().parents[1]
    root = repo.parents[2] if repo.parent.name == ".worktrees" else repo.parent
    ndk = root.parent / "android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64"
    tools = root / "build-sensitive/bin"
    if not (tools / "opt").exists() or not (ndk / "bin/clang").exists():
        pytest.skip("native Android tools unavailable")
    work = tmp_path_factory.mktemp(f"ad-{detector}-{vm}")
    ann = f"obf: antidebug({detector}=1)"
    if vm:
        ann += ", vm(hardened=0,encBytecode=0,lazyDecrypt=0,constInStream=0)"
    data = ann.encode() + b"\0"
    esc = "".join(f"\\{b:02X}" for b in data)
    src, obf, obj = (work / name for name in ("input.ll", "obf.ll", "obf.o"))
    src.write_text('target triple = "aarch64-unknown-linux-android26"\n'
                   'define i32 @target(i32 %x) { %r = add i32 %x, 7\n ret i32 %r }\n'
                   f'@.ann = private constant [{len(data)} x i8] c"{esc}"\n'
                   '@llvm.global.annotations = appending global [1 x {ptr,ptr,ptr,i32,ptr}] '
                   '[{ptr,ptr,ptr,i32,ptr} {ptr @target,ptr @.ann,ptr @.ann,i32 0,ptr null}]\n')
    subprocess.run([str(tools / "opt"), "-passes=obfuscation", "-obf-verify", "-S",
                    str(src), "-o", str(obf)], check=True, capture_output=True, text=True)
    lowered = work / "lowered.ll"
    lowered.write_text("\n".join(l for l in obf.read_text().splitlines()
                                if not l.startswith(("@llvm.global.annotations", "@.ann"))))
    subprocess.run([str(tools / "clang"), "-target", "aarch64-linux-android26", "-c",
                    str(lowered), "-o", str(obj)], check=True, capture_output=True, text=True)
    harness = work / "harness.c"
    harness.write_text(r'''
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
static const char *fixture;
static volatile sig_atomic_t interrupted, start;
extern int __real_open(const char *, int, ...);
extern ssize_t __real_read(int, void *, size_t);
extern int __real_close(int);
int __wrap_open(const char *path, int flags, ...) {
    if (fixture && strcmp(path, "/proc/self/status") == 0) return 10001;
    return __real_open(path, flags);
}
ssize_t __wrap_read(int fd, void *out, size_t len) {
    if (fd != 10001) return __real_read(fd, out, len);
    memset(out, '1', len);
    if (strcmp(fixture, "read-error") == 0) return -1;
    size_t n = strlen(fixture);
    if (n > len) n = len;
    memcpy(out, fixture, n);
    return n;
}
int __wrap_close(int fd) { return fd == 10001 ? 0 : __real_close(fd); }
static void on_signal(int sig) {
    if (sig == SIGINT) interrupted = 1;
    if (sig == SIGUSR1) start = 1;
}
extern int target(int);
int main(int argc, char **argv) {
    signal(SIGINT, on_signal);
    signal(SIGUSR1, on_signal);
    setbuf(stdout, NULL);
    if (argc > 1 && strcmp(argv[1], "signal") == 0) {
        int first = target(9), second = target(9);
        printf("ready first=%d second=%d\n", first, second);
        while (!interrupted) usleep(1000);
        puts("SIGINT handled");
        return first != 16 || second != 16;
    }
    if (argc > 1 && strcmp(argv[1], "attach") == 0) {
        puts("ready for attach");
        while (!start) usleep(1000);
    } else if (argc > 1) fixture = argv[1];
    printf("result=%d\n", target(9));
    return 0;
}
''')
    exe = work / "test"
    subprocess.run([str(ndk / "bin/clang"), "--target=aarch64-linux-android26",
                    f"--sysroot={ndk / 'sysroot'}", str(harness), str(obj),
                    "-Wl,--wrap=open", "-Wl,--wrap=read", "-Wl,--wrap=close", "-o", str(exe)],
                   check=True, capture_output=True, text=True)
    return exe


@pytest.mark.parametrize("status,expected", [
    ("Name:\ttest\nTracerPid:\t0\nState:\tR\n", 16),
    ("Name:\ttest\nTracerPid:\t28473\nState:\tR\n", 0),
    ("TracerPid: 2\n", 0),
    ("TracerPid:\t  000987\n", 0),
    ("TracerPid: 0000\n", 16),
    ("TracerPid:\t987", 0),
    ("OtherTracerPid: 123\nTracerPid:\t0\n", 16),
    ("Name: TracerPid: 1\nTracerPid:\t0\n", 16),
    ("Trace", 16), ("", 16), ("read-error", 16),
])
def test_tracer_field_controls_business(detector_binary, status, expected):
    run = subprocess.run([str(detector_binary), status], capture_output=True, text=True, timeout=10)
    assert run.returncode == 0, run.stdout + run.stderr
    assert f"result={expected}" in run.stdout


def test_repeated_calls_leave_sigint_deliverable(detector_binary):
    proc = subprocess.Popen([str(detector_binary), "signal"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    try:
        assert proc.stdout is not None
        assert select.select([proc.stdout], [], [], 5)[0], "target never became ready"
        ready = proc.stdout.readline()
        os.kill(proc.pid, signal.SIGINT)
        try:
            out, err = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            pytest.fail(f"SIGINT did not reach handler (possible ptrace-stop): {ready}")
        assert proc.returncode == 0, ready + out + err
        assert "first=16 second=16" in ready
        assert "SIGINT handled" in out
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=5)


def test_actual_debugger_attach_blocks_business(detector_binary):
    libc = ctypes.CDLL("libc.so", use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    proc = subprocess.Popen([str(detector_binary), "attach"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    try:
        assert proc.stdout is not None
        assert select.select([proc.stdout], [], [], 5)[0]
        assert "ready for attach" in proc.stdout.readline()
        assert libc.ptrace(16, proc.pid, None, None) == 0, f"PTRACE_ATTACH errno={ctypes.get_errno()}"
        deadline = time.monotonic() + 3
        stopped = False
        while time.monotonic() < deadline:
            pid, status = os.waitpid(proc.pid, os.WNOHANG | os.WUNTRACED)
            if pid:
                stopped = os.WIFSTOPPED(status)
                break
            time.sleep(0.01)
        assert stopped, "debugger attach did not stop target"
        assert libc.ptrace(7, proc.pid, None, signal.SIGUSR1) == 0
        out, err = proc.communicate(timeout=5)
        assert proc.returncode == 0, out + err
        assert "result=0" in out, out
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=5)
