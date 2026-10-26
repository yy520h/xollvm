"""Chaff must be deterministic for a window and side-effect free by contract."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_chaff_scheduler_produces_bounded_scratch_steps(tmp_path):
    source = tmp_path / "chaff_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material/chaff_scheduler.h"\n'
        '#include <cassert>\n'
        'int main() {\n'
        '  using namespace xovm::material;\n'
        '  ChaffScheduler first(7); ChaffScheduler second(7);\n'
        '  for (int i = 0; i < 16; ++i) { auto a = first.next(i); auto b = second.next(i);\n'
        '    assert(a.execute == b.execute && a.variant == b.variant && a.scratch_bytes == b.scratch_bytes); }\n'
        '  assert(first.next(100).scratch_bytes <= 256);\n'
        '  return 0;\n'
        '}\n', encoding="ascii")
    exe = tmp_path / "probe"
    result = subprocess.run(
        ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
         str(source), str(ROOT / "runtime/cloud_material/chaff_scheduler.cpp"),
         "-o", str(exe)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert subprocess.run([str(exe)], capture_output=True, text=True).returncode == 0
