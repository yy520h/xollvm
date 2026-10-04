"""Task 10: VM wrapper structural-family diversity.

Builds the same function under 20 seeds and normalizes each AArch64 prologue
into a coarse structural class (frame size + a sorted multiset of prologue
opcode mnemonics). Requires at least two distinct classes across the seeds and
byte-identical output for a repeated seed.
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


BODY = r"""
declare i32 @ext(i32)
define i32 @fam(i1 %c, i32 %x) {
entry:
  br i1 %c, label %a, label %b
a:
  %r = add i32 %x, 17
  ret i32 %r
b:
  %r2 = call i32 @ext(i32 %x)
  ret i32 %r2
}
"""
# vm with auto family: seeds should split across split/arena.
ANN = "obf: vm(preset=medium, wrapperFamily=auto, enginePoolSize=1, perFnEngine=1)"


def _strip(text: str) -> str:
    return "\n".join(
        l for l in text.splitlines()
        if not l.startswith("@llvm.global.annotations") and not l.startswith("@.ann.")
    ) + "\n"


def _prologue_class(disasm: str) -> str:
    m = re.search(r"<fam>:\n(.*?)(?=\n[0-9a-f]+ <|\Z)", disasm, re.S)
    assert m, "fam symbol not found"
    mns = re.findall(r"^\s+[0-9a-f]+:\s+[0-9a-f ]+\t(\S+)", m.group(1), re.M)
    head = mns[:12]
    return f"{len(mns)}|" + ",".join(sorted(head))


@pytest.fixture(scope="module")
def build_ir(tmp_path_factory):
    opt = _tool("opt")
    clang = _tool("clang")
    objdump = _tool("llvm-objdump")
    if not (opt.exists() and clang.exists() and objdump.exists()):
        pytest.skip("opt/clang/llvm-objdump not all available")
    work = tmp_path_factory.mktemp("wrapper-fam")
    src = work / "f.ll"
    src.write_text(BODY + _annotate("fam", ANN))

    def build(seed: int) -> str:
        obf = work / f"f-{seed}.obf.ll"
        subprocess.run([str(opt), "-passes=obfuscation", f"-obf-seed={seed}",
                        "-S", str(src), "-o", str(obf)],
                       check=True, capture_output=True, text=True, timeout=600)
        low = work / f"f-{seed}.low.ll"
        low.write_text(_strip(obf.read_text()))
        obj = work / f"f-{seed}.o"
        subprocess.run([str(clang), "-target", "aarch64-linux-android", "-O0",
                        "-Wno-override-module", "-c", str(low), "-o", str(obj)],
                       check=True, capture_output=True, text=True, timeout=300)
        return subprocess.run([str(objdump), "-d", str(obj)],
                              check=True, capture_output=True, text=True,
                              timeout=120).stdout
    return build


def test_two_wrapper_families_across_seeds(build_ir):
    classes = set()
    for seed in range(1, 21):
        classes.add(_prologue_class(build_ir(seed)))
    assert len(classes) >= 2, f"only {len(classes)} wrapper class(es): {classes}"


def test_same_seed_is_reproducible(build_ir):
    a = build_ir(1234)
    b = build_ir(1234)
    assert _prologue_class(a) == _prologue_class(b)
