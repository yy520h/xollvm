"""仅构建/运行真实原生桥；项目根必须显式注入，错误不回显包。"""
import json
import os
from pathlib import Path
import subprocess

REPO = Path(__file__).resolve().parents[1]


def build_material_harness(work, *, defines=(), sources=()):
    root = os.environ.get('XOLLVM_PROJECT_ROOT')
    if not root or not Path(root).is_absolute():
        raise RuntimeError('required absolute XOLLVM_PROJECT_ROOT')
    root = Path(root)
    ndk = root.parent / 'android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64'
    zone = root / 'demo/jni/zone_runtime'
    ssl = root / 'demo/obj/openssl/arm64-v8a'
    compiler = ndk / 'bin/clang++'
    for path in (compiler, zone / 'Core/nlohmann/json.hpp', ssl / 'libcrypto.a',
                 ssl / 'include/openssl/configuration.h', zone / 'openssl_core/src/include/openssl/evp.h'):
        if not path.is_file():
            raise RuntimeError(f'required dependency missing: {path}')
    work = Path(work)
    if not work.is_dir():
        raise RuntimeError('required existing build directory')
    exe = work / 'material-harness'
    names = {Path(source).name for source in sources}
    fixture = ('utils/fixtures/cloud_material/lease_harness.cpp'
               if 'material_store.cpp' in names else
               'utils/fixtures/cloud_material/protocol_harness.cpp'
               if 'material_protocol.cpp' in names else
               'utils/fixtures/cloud_material/package_harness.cpp')
    resolved_sources = []
    for source in sources:
        source = Path(source)
        if not source.is_absolute():
            source = REPO / ('runtime/cloud_material' if source.parent == Path('.') else '') / source
        resolved_sources.append(source)
    command = [str(compiler), '--target=aarch64-linux-android26', f'--sysroot={ndk / "sysroot"}',
               '-std=c++20', '-static-libstdc++', '-O2', '-Wall', '-Wextra', '-Werror',
               '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
               '-I', str(REPO), '-I', str(zone / 'Core'), '-I', str(ssl / 'include'),
               '-I', str(zone / 'openssl_core/src/include'),
               *[f'-D{value}' for value in defines],
               str(REPO / fixture),
               str(REPO / 'runtime/cloud_material/material_package.cpp'),
               *[str(source) for source in resolved_sources], str(ssl / 'libcrypto.a'),
               '-ldl', '-pthread', '-o', str(exe)]
    p = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if p.returncode:
        raise RuntimeError(f'harness build failed ({p.returncode})\n{p.stderr}')
    return exe


def run_material_case(exe, name, *, timeout=15, input_bytes=b'', expected_binding=None):
    # 扩展关键字保留计划中的具名调用接口；stdin 第一行是独立期望 binding。
    expected = json.dumps(expected_binding if expected_binding is not None else {},
                          sort_keys=True, separators=(',', ':')).encode()
    try:
        p = subprocess.run([str(exe), name], input=expected + b'\n' + input_bytes,
                           capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        stderr = (error.stderr or b'').decode(errors='replace')
        raise RuntimeError(f'harness timeout; stderr: {stderr}') from None
    if p.returncode:
        raise RuntimeError(f'harness failed ({p.returncode}); stderr: {p.stderr.decode(errors="replace")}')
    try:
        result = json.loads(p.stdout)
        if not isinstance(result, dict) or type(result.get('ok')) is not bool:
            raise ValueError('invalid verdict')
        return result
    except (ValueError, UnicodeError):
        raise RuntimeError(f'invalid harness JSON; stderr: {p.stderr.decode(errors="replace")}') from None
