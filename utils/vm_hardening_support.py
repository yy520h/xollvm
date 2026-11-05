"""无凭据 VM 原生测试公共入口，缺工具直接失败。"""
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class VMTools:
    opt: Path
    clang: Path
    clangxx: Path
    sysroot: Path
    hardener: Path


def tools():
    root = Path(os.environ.get('XOLLVM_PROJECT_ROOT', Path(__file__).resolve().parents[2]))
    build = root / 'build-sensitive/bin'
    ndk = root / 'android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64'
    t = VMTools(Path(os.environ.get('XOLLVM_OPT', build / 'opt')),
                ndk / 'bin/clang', ndk / 'bin/clang++', ndk / 'sysroot',
                build / 'xollvm-elf-hardener')
    for path in (t.opt, t.clang, t.clangxx, t.hardener):
        if not path.is_file():
            raise RuntimeError(f'required tool missing: {path}')
    return t


def checked(argv, timeout=120):
    p = subprocess.run([str(a) for a in argv], capture_output=True, text=True, timeout=timeout)
    assert p.returncode == 0, p.stdout + p.stderr
    return p


def annotation(functions, spec):
    data = ('obf: ' + spec).encode() + b'\0'
    encoded = ''.join(f'\\{b:02X}' for b in data)
    ty = '{ptr,ptr,ptr,i32,ptr}'
    rows = ','.join(f'{ty} {{ptr @{f},ptr @ann,ptr @ann,i32 0,ptr null}}' for f in functions)
    return (f'@ann = private constant [{len(data)} x i8] c"{encoded}"\n'
            f'@llvm.global.annotations = appending global [{len(functions)} x {ty}] [{rows}]\n')


def transform(work, source, seed=42, extra=()):
    src, out = work / 'input.ll', work / 'obf.ll'
    src.write_text('target triple = "aarch64-unknown-linux-android26"\n' + source)
    checked([tools().opt, '-passes=obfuscation', '-obf-verify', f'-obf-seed={seed}',
             *extra, '-S', src, '-o', out])
    return out


def build_native(work, ir, harness, finalize_targets=False, backend_opt='-O0'):
    t = tools()
    lowered, src, obj, exe = (work / name for name in ('lowered.ll', 'harness.cpp', 'vm.o', 'native'))
    lowered.write_text('\n'.join(l for l in ir.read_text().splitlines()
                                 if not l.startswith('@llvm.global.annotations')) + '\n')
    src.write_text(harness)
    checked([t.clang, '--target=aarch64-linux-android26', backend_opt, '-c', lowered, '-o', obj])
    checked([t.clangxx, '--target=aarch64-linux-android26', f'--sysroot={t.sysroot}',
             '-std=c++20', '-static-libstdc++', '-Wl,--rosegment', src, obj,
             '-ldl', '-pthread', '-o', exe])
    if finalize_targets:
        checked([t.hardener, 'targets', '--input', exe, '--output', exe])
    return exe


def run_case(exe, args=(), expected='equal\n'):
    p = checked([exe, *args], timeout=30)
    assert p.stdout == expected
