"""实际组件安装及 workflow 资源拷贝/缺工具拒绝打包回归。"""
import os
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO.parents[2] if REPO.parent.name == '.worktrees' else REPO.parent


def step(workflow, name):
    text = (REPO / '.github/workflows' / workflow).read_text()
    match = re.search(r'      - name: ' + re.escape(name) + r'\n(?:(?!      - name:)[^\n]*\n)*?        run: \|\n((?:          [^\n]*\n|\n)+)', text)
    assert match, f'missing executable workflow step: {name}'
    return '\n'.join(line[10:] if line.startswith('          ') else line
                     for line in match.group(1).splitlines())


def test_hardener_component_installs_executable(tmp_path):
    build = ROOT / 'build-sensitive'
    run = subprocess.run(['cmake', '--install', str(build), '--component',
                          'xollvm-elf-hardener', '--prefix', str(tmp_path)],
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    tool = tmp_path / 'bin/xollvm-elf-hardener'
    assert tool.is_file() and os.access(tool, os.X_OK), run.stdout
    check = subprocess.run([str(tool), 'verify', '--input',
                            str(ROOT / 'demo/libs/arm64-v8a/zone_demo')],
                           capture_output=True, text=True)
    assert check.returncode == 0, check.stdout + check.stderr


@pytest.mark.parametrize('major', ['22', '23'])
def test_android_resource_copy_uses_built_llvm_version(tmp_path, major):
    paths = {'build/include/llvm/Config/llvm-config.h': f'#define LLVM_VERSION_MAJOR {major}\n',
             'build/runtime/libclang_rt.builtins-aarch64-android.a': 'builtins',
             'build/runtime/libunwind-aarch64.a': 'unwind',
             'llvm-src/libunwind/include/unwind.h': 'header'}
    for path, contents in paths.items():
        file = tmp_path / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(contents)
    resource = tmp_path / f'install/lib/clang/{major}'
    (resource / 'include').mkdir(parents=True)
    script = step('build-android.yml', '兜底：运行时库 + 头文件一并放进安装树')
    script = script.replace('${{ inputs.llvm_major }}', major)
    run = subprocess.run(['bash', '-euc', script], cwd=tmp_path, capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    assert (resource / 'lib/aarch64-unknown-linux-android24/libclang_rt.builtins.a').read_text() == 'builtins'
    assert (resource / 'lib/aarch64-unknown-linux-android24/libunwind.a').read_text() == 'unwind'
    assert (resource / 'include/unwind.h').read_text() == 'header'
    assert not (tmp_path / f'install/lib/clang/{"23" if major == "22" else "22"}').exists()


@pytest.mark.parametrize('workflow', ['build.yml', 'build-android.yml'])
def test_distribution_requires_hardener(workflow):
    text = (REPO / '.github/workflows' / workflow).read_text()
    components = re.findall(r'LLVM_DISTRIBUTION_COMPONENTS="([^"]+)"', text)
    assert components and all('xollvm-elf-hardener' in c.split(';') for c in components)


def test_native_package_rejects_missing_hardener(tmp_path):
    tools = tmp_path / 'install/bin'
    tools.mkdir(parents=True)
    for name in ['clang', 'opt']:
        tool = tools / name
        tool.write_text('#!/bin/sh\nexit 0\n')
        tool.chmod(0o755)
    script = step('build.yml', '验证发布工具完整性')
    run = subprocess.run(['bash', '-euc', script], cwd=tmp_path, capture_output=True, text=True)
    assert run.returncode != 0
    assert 'xollvm-elf-hardener' in run.stdout + run.stderr
