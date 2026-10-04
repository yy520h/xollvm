"""Task 5: post-commit AArch64 codegen gates for sensitive regions.

Lowers an obfuscated sensitive region to an AArch64 object and asserts the
final protected symbol contains no direct call to the external verifier and
does contain an indirect engine call, and that the same seed reproduces
byte-identical IR.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest


def _root() -> Path:
    repo = Path(__file__).resolve().parents[2]
    return repo.parents[2] if repo.parent.name == ".worktrees" else repo.parent


def _tool(name: str) -> Path:
    root = _root()
    for base in (root / "build-sensitive" / "bin", root / "build" / "bin"):
        cand = base / name
        if cand.exists():
            return cand
    return root / "build-sensitive" / "bin" / name


def _annotate(fn: str, ann: str) -> str:
    data = ann.encode() + b"\x00"
    esc = "".join(f"\\{b:02X}" for b in data)
    return (
        f'@.ann.{fn} = private unnamed_addr constant [{len(data)} x i8] c"{esc}"\n'
        f'@llvm.global.annotations = appending global '
        f'[1 x {{ ptr, ptr, ptr, i32, ptr }}] '
        f'[{{ ptr, ptr, ptr, i32, ptr }} {{ ptr @{fn}, ptr @.ann.{fn}, '
        f'ptr @.ann.{fn}, i32 0, ptr null }}]\n'
    )


FIXTURE_BODY = r"""
declare i32 @fixture_verify(ptr, i64)
declare void @fixture_transport(ptr, i64)
define i32 @fixture_decision(ptr %p, i64 %n) {
entry:
  call void @fixture_transport(ptr %p, i64 %n)
  %r = call i32 @fixture_verify(ptr %p, i64 %n)
  %ok = icmp eq i32 %r, 1
  br i1 %ok, label %s, label %f
s:
  ret i32 1
f:
  ret i32 0
}
"""

ANNOTATION = "obf: sensitive(region=fixture-auth,strict=1), vm(encBytecode=0)"


def _run_obf(seed: int, out: Path, tmp_path: Path) -> str:
    opt = _tool("opt")
    if not opt.exists():
        pytest.skip(f"obfuscator opt not found at {opt}")
    src = tmp_path / "fixture.ll"
    src.write_text(FIXTURE_BODY + _annotate("fixture_decision", ANNOTATION))
    proc = subprocess.run(
        [str(opt), "-passes=obfuscation", f"-obf-seed={seed}", "-S",
         str(src), "-o", str(out)],
        capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out.read_text()


def _strip_annotations(text: str) -> str:
    # The frontend-only annotation globals are consumed by the obfuscator and
    # must not be fed back to clang's IR reader.
    keep = []
    for line in text.splitlines():
        if line.startswith("@llvm.global.annotations"):
            continue
        if line.startswith("@.ann."):
            continue
        keep.append(line)
    return "\n".join(keep) + "\n"


def _disasm(obf_ll: Path, tmp_path: Path) -> str:
    clang = _tool("clang")
    obj = tmp_path / "obf.o"
    lowered = tmp_path / "obf.lowered.ll"
    lowered.write_text(_strip_annotations(obf_ll.read_text()))
    subprocess.run(
        [str(clang), "-target", "aarch64-linux-android", "-O0",
         "-Wno-override-module", "-c", str(lowered), "-o", str(obj)],
        check=True, capture_output=True, text=True, timeout=300)
    dump = _tool("llvm-objdump")
    return subprocess.run(
        [str(dump), "-d", "--no-show-raw-insn", str(obj)],
        check=True, capture_output=True, text=True, timeout=120).stdout


def _function_block(disasm: str, name: str) -> str:
    m = re.search(rf"^[0-9a-f]+ <{re.escape(name)}>:\n(.*?)(?=\n[0-9a-f]+ <|\Z)",
                  disasm, re.M | re.S)
    assert m, f"symbol {name} not found in disassembly"
    return m.group(1)


@pytest.mark.parametrize("seed", [1, 20260930, 4294967295])
def test_protected_symbol_has_no_direct_verifier_call(seed, tmp_path):
    obf_ll = tmp_path / f"obf-{seed}.ll"
    _run_obf(seed, obf_ll, tmp_path)
    disasm = _disasm(obf_ll, tmp_path)
    block = _function_block(disasm, "fixture_decision")
    assert not re.search(r"\bbl\s+[0-9a-f]+ <fixture_verify", block), block
    assert not re.search(r"\bbl\s+[0-9a-f]+ <fixture_transport", block), block
    # The VM wrapper reaches the engine indirectly.
    assert re.search(r"\bblr\b", block), block


def test_same_seed_is_byte_identical(tmp_path):
    a = tmp_path / "a.ll"
    b = tmp_path / "b.ll"
    text_a = _run_obf(1234, a, tmp_path)
    text_b = _run_obf(1234, b, tmp_path)
    assert text_a == text_b
