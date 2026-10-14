"""实际组件安装与原子链接发布，不模拟链接器。"""
import os
import subprocess
from pathlib import Path
import pytest
from vm_hardening_support import tools, checked, annotation, transform, build_native, run_case
from test_vm_target_encoding import SOURCE, HARNESS

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def installed(tmp_path):
    prefix = tmp_path / 'installed tools'
    checked(['cmake', '--install', ROOT / 'build-sensitive', '--component', 'xollvm-link', '--prefix', prefix])
    checked(['cmake', '--install', ROOT / 'build-sensitive', '--component', 'xollvm-elf-hardener', '--prefix', prefix])
    wrapper = prefix / 'bin/xollvm-link'
    assert wrapper.is_file() and os.access(wrapper, os.X_OK)
    return wrapper


def invoke(wrapper, work, output, hardener=None):
    t = tools()
    env = dict(os.environ, XOLLVM_LINK_COMPILER=str(t.clangxx))
    if hardener is not None:
        env['XOLLVM_ELF_HARDENER'] = str(hardener)
    return subprocess.run(['bash', str(wrapper), '--target=aarch64-linux-android26', f'--sysroot={t.sysroot}',
        '-static-libstdc++', '-Wl,--rosegment', str(work / 'harness.cpp'), str(work / 'vm.o'),
        '-ldl', '-pthread', '-o', str(output)], env=env, capture_output=True, text=True, timeout=120)


def prepare(work, spec='vm(encodedTargets=1,hardened=0)'):
    ir = transform(work, SOURCE + annotation(['target'], spec))
    build_native(work, ir, HARNESS)


def test_installed_link_promotes_verified_binary(tmp_path, installed):
    prepare(tmp_path)
    out = tmp_path / 'final app'
    p = invoke(installed, tmp_path, out)
    assert p.returncode == 0, p.stdout+p.stderr
    run_case(out)
    checked([installed.parent / 'xollvm-elf-hardener', 'verify', '--input', out])
    assert not list(tmp_path.glob('.xollvm-link.*'))


def test_installed_link_max(tmp_path, installed):
    prepare(tmp_path, 'vm(preset=max)')
    out = tmp_path / 'final max'
    p = invoke(installed, tmp_path, out)
    assert p.returncode == 0, p.stdout+p.stderr
    run_case(out)
    checked([installed.parent / 'xollvm-elf-hardener', 'verify', '--input', out])


@pytest.mark.parametrize('stage', ['missing', 'targets', 'audit', 'seal', 'verify'])
def test_failed_finalize_preserves_previous_output(tmp_path, installed, stage):
    prepare(tmp_path)
    out = tmp_path / 'previous app'; out.write_bytes(b'previous-output')
    hardener = tmp_path / 'fault hardener'
    if stage != 'missing':
        real = installed.parent / 'xollvm-elf-hardener'
        hardener.write_text(f'#!/data/data/com.termux/files/usr/bin/bash\nif [[ "$1" == "{stage}" ]]; then exit 23; fi\nexec "{real}" "$@"\n')
        hardener.chmod(0o755)
    p = invoke(installed, tmp_path, out, hardener)
    assert p.returncode != 0
    assert out.read_bytes() == b'previous-output'
    assert not list(tmp_path.glob('.xollvm-link.*'))
