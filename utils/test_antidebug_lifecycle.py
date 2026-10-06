"""真实生成代码的配置隔离、锁存、监控创建失败和正常退出回收。"""
import subprocess
import os
from pathlib import Path
import pytest


@pytest.fixture(scope='module', params=[False, True])
def lifecycle_binary(request, tmp_path_factory):
    repo = Path(__file__).resolve().parents[1]
    root = repo.parents[2] if repo.parent.name == '.worktrees' else repo.parent
    tools = root / 'build-sensitive/bin'
    ndk = root.parent / 'android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64'
    work = tmp_path_factory.mktemp('ad-life')
    functions = [('tracer', 'tracerPid=1'), ('maps', 'maps=1'),
                 ('monitor', 'tracerPid=1,dynamic=1,interval=50'),
                 ('monitor_twin', 'tracerPid=1,dynamic=1,interval=50'),
                 ('slow', 'maps=1,dynamic=1,interval=60000')]
    lines = ['target triple = "aarch64-unknown-linux-android26"']
    annotations = []
    for name, cfg in functions:
        ann = 'obf: antidebug(' + cfg + ')'
        if request.param:
            ann += ', vm(hardened=0,encBytecode=0,lazyDecrypt=0,constInStream=0)'
        data = ann.encode() + b'\0'
        encoded = ''.join(f'\\{b:02X}' for b in data)
        lines += [f'define i32 @{name}(i32 %x) {{ %r = add i32 %x, 7\n ret i32 %r }}',
                  f'@ann_{name} = private constant [{len(data)} x i8] c"{encoded}"']
        annotations.append('{ptr,ptr,ptr,i32,ptr} {ptr @' + name + ',ptr @ann_' + name +
                           ',ptr @ann_' + name + ',i32 0,ptr null}')
    lines += [f'@llvm.global.annotations = appending global [{len(functions)} x {{ptr,ptr,ptr,i32,ptr}}] [' +
              ','.join(annotations) + ']']
    src, ir, obj = (work / f for f in ('input.ll', 'obf.ll', 'obf.o'))
    src.write_text('\n'.join(lines))
    build = subprocess.run([os.environ.get('XOLLVM_LIFECYCLE_OPT', str(tools / 'opt')), '-passes=obfuscation', '-obf-verify',
                            '-S', str(src), '-o', str(ir)], capture_output=True, text=True)
    assert build.returncode == 0, build.stderr
    assert ir.read_text().count('call i32 @pthread_create') == 2, 'effective configurations must share one monitor each'
    ir.write_text('\n'.join(line for line in ir.read_text().splitlines()
                            if not line.startswith(('@llvm.global.annotations', '@ann_'))))
    subprocess.run([str(tools / 'clang'), '-target', 'aarch64-linux-android26', '-c',
                    str(ir), '-o', str(obj)], check=True, capture_output=True, text=True)
    harness = work / 'main.c'
    harness.write_text(r'''
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
static atomic_int hit, reads;
FILE *__wrap_fopen(const char* p, const char* mode) {
    const char* s = strstr(p, "status") ? (atomic_load(&hit) ? "TracerPid: 42\n" : "TracerPid: 0\n") :
        "1000-2000 r-xp 0 00:00 0 /data/normal-library.so\n";
    FILE* f = tmpfile(); if (!f) return NULL;
    fputs(s, f); rewind(f); atomic_fetch_add(&reads, 1); return f;
}
int __wrap_open(const char* p, int f, ...) { return strstr(p, "status") ? 10001 : 10002; }
ssize_t __wrap_read(int fd, void* out, size_t n) {
    const char* s = fd == 10001 ? (atomic_load(&hit) ? "TracerPid: 42\n" : "TracerPid: 0\n") : "normal-library\n";
    size_t len = strlen(s); if (len > n) len = n;
    memcpy(out, s, len); atomic_fetch_add(&reads, 1); return len;
}
int __wrap_close(int fd) { return 0; }
int __real_pthread_create(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*);
int __wrap_pthread_create(pthread_t* t, const pthread_attr_t* a, void* (*fn)(void*), void* arg) {
    if (getenv("FAIL_THREAD")) return EAGAIN;
    return __real_pthread_create(t, a, fn, arg);
}
int __real_pthread_join(pthread_t, void**);
int __wrap_pthread_join(pthread_t t, void** r) {
    int rc = __real_pthread_join(t, r);
    if (!rc) write(1, "monitor joined\n", 15);
    return rc;
}
extern int tracer(int), maps(int), monitor(int), monitor_twin(int), slow(int);
int main(int argc, char** argv) {
    if (strcmp(argv[1], "failure") == 0) return monitor(9) != 0;
    if (strcmp(argv[1], "join") == 0) { monitor(9); return 0; }
    if (strcmp(argv[1], "dynamic_latch") == 0) {
        atomic_store(&hit, 1);
        if (monitor(9) != 0) return 4;
        atomic_store(&hit, 0);
        usleep(150000);
        if (monitor_twin(9) != 0) return 5;
        return slow(9) != 16;
    }
    atomic_store(&hit, 1);
    if (tracer(9) != 0) return 3;
    atomic_store(&hit, 0);
    if (strcmp(argv[1], "latch") == 0) return tracer(9) != 0;
    return maps(9) != 16;
}
''')
    exe = work / 'main'
    subprocess.run([str(ndk / 'bin/clang'), '--target=aarch64-linux-android26',
                    f'--sysroot={ndk / "sysroot"}', str(harness), str(obj),
                    *[f'-Wl,--wrap={f}' for f in ('open', 'read', 'close', 'fopen', 'pthread_create', 'pthread_join')],
                    '-pthread', '-o', str(exe)], check=True, capture_output=True, text=True)
    return exe


@pytest.mark.parametrize('case', ['latch', 'isolation', 'dynamic_latch', 'join', 'failure'])
def test_detector_lifecycle(lifecycle_binary, case):
    env = dict(os.environ)
    if case == 'failure': env['FAIL_THREAD'] = '1'
    run = subprocess.run([str(lifecycle_binary), case], env=env,
                         capture_output=True, text=True, timeout=5)
    assert run.returncode == 0, f'{case}: {run.returncode}\n{run.stdout}{run.stderr}'
    if case == 'join': assert run.stdout.count('monitor joined') == 2
