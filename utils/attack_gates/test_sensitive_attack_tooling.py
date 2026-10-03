import subprocess
from pathlib import Path

import pytest

from test_sensitive_attack_baseline import _tool


ROOT = Path(__file__).parents[2]
CMAKE_MODULE = ROOT / 'cmake' / 'SensitiveAttackBaselineTests.cmake'


def _make_executable(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('tool')
    path.chmod(0o755)


def test_tool_resolution_rejects_path_fallback(monkeypatch, tmp_path):
    clang = tmp_path / 'toolchain' / 'clang'
    path_objdump = tmp_path / 'path' / 'llvm-objdump'
    _make_executable(clang)
    _make_executable(path_objdump)
    monkeypatch.setenv('PATH', str(path_objdump.parent))

    with pytest.raises(FileNotFoundError, match='llvm-objdump.*next to XOLLVM_TEST_CLANG'):
        _tool(str(clang), 'llvm-objdump')


def test_cmake_target_depends_on_matching_llvm_tools(tmp_path):
    source = tmp_path / 'source'
    build = tmp_path / 'build'
    source.mkdir()
    (source / 'tool.c').write_text('int main(void) { return 0; }\n')
    (source / 'CMakeLists.txt').write_text(
        f'''cmake_minimum_required(VERSION 3.20)
project(sensitive_attack_tooling C)
add_executable(clang EXCLUDE_FROM_ALL tool.c)
add_executable(llvm-readelf EXCLUDE_FROM_ALL tool.c)
add_executable(llvm-objdump EXCLUDE_FROM_ALL tool.c)
set(Python3_EXECUTABLE "${{CMAKE_COMMAND}}")
include("{CMAKE_MODULE}")
add_sensitive_attack_baseline_tests("{ROOT}")
'''
    )

    subprocess.run(
        ['cmake', '-G', 'Ninja', '-S', str(source), '-B', str(build)],
        check=True,
        capture_output=True,
        text=True,
    )
    query = subprocess.run(
        ['ninja', '-C', str(build), '-t', 'query', 'SensitiveAttackBaselineTests'],
        check=True,
        capture_output=True,
        text=True,
    ).stdout

    assert 'clang' in query
    assert 'llvm-readelf' in query
    assert 'llvm-objdump' in query
