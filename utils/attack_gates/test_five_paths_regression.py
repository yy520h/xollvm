"""Task 10: five-path hardened regression on an obfuscated sensitive region.

Builds a sensitive-decision fixture through the obfuscator, lowers to AArch64,
and asserts the five static-attack paths no longer yield a stable direct
locator chain into the decision:

  1. no direct BL to the verifier (no PLT-mapped callsite into the decision)
  2. no native conditional branch on the verifier result
  3. no direct call to the compare helper followed by a cbz/cbnz failure edge
  4. no direct call to the transport helper in the decision symbol
  5. no unallowlisted PF_X zero run >= 512 in the final link

Everything runs from the worktree; the hardener (path 5) is exercised on an
executable produced by the same AArch64 toolchain.
"""

from __future__ import annotations

import re
import shutil
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
declare i32 @fx_verify(ptr, i64)
declare i32 @fx_compare(ptr, ptr)
declare void @fx_transport(ptr, i64)
define i32 @fx_decision(ptr %p, i64 %n, ptr %a, ptr %b) {
entry:
  call void @fx_transport(ptr %p, i64 %n)
  %r = call i32 @fx_verify(ptr %p, i64 %n)
  %ok = icmp eq i32 %r, 1
  br i1 %ok, label %cmp, label %fail
cmp:
  %c = call i32 @fx_compare(ptr %a, ptr %b)
  %ok2 = icmp eq i32 %c, 0
  br i1 %ok2, label %s, label %fail
s:
  ret i32 1
fail:
  ret i32 0
}
"""
ANN = "obf: sensitive(region=fx-auth,strict=1), vm(encBytecode=0)"


def _strip(text: str) -> str:
    return "\n".join(
        l for l in text.splitlines()
        if not l.startswith("@llvm.global.annotations") and not l.startswith("@.ann.")
    ) + "\n"


@pytest.fixture(scope="module")
def artifacts(tmp_path_factory):
    opt = _tool("opt")
    clang = _tool("clang")
    objdump = _tool("llvm-objdump")
    if not (opt.exists() and clang.exists() and objdump.exists()):
        pytest.skip("opt/clang/llvm-objdump not all available")
    work = tmp_path_factory.mktemp("five-paths")
    src = work / "f.ll"
    src.write_text(BODY + _annotate("fx_decision", ANN))
    obf = work / "f.obf.ll"
    subprocess.run([str(opt), "-passes=obfuscation", "-S", str(src), "-o", str(obf)],
                   check=True, capture_output=True, text=True, timeout=600)
    low = work / "f.low.ll"
    low.write_text(_strip(obf.read_text()))
    exe = work / "f.so"
    subprocess.run([str(clang), "-target", "aarch64-linux-android", "-fuse-ld=lld",
                    "-nostdlib", "-shared", "-Wl,-z,notext", str(low), "-o", str(exe)],
                   check=True, capture_output=True, text=True, timeout=600)
    disasm = subprocess.run([str(objdump), "-d", "--no-show-raw-insn", str(exe)],
                            check=True, capture_output=True, text=True,
                            timeout=120).stdout
    return work, exe, disasm


def _decision_block(disasm: str) -> str:
    m = re.search(r"<fx_decision>:\n(.*?)(?=\n[0-9a-f]+ <|\Z)", disasm, re.S)
    assert m, "fx_decision symbol not found"
    return m.group(1)


def test_path1_no_direct_verifier_call(artifacts):
    _, _, disasm = artifacts
    body = _decision_block(disasm)
    assert not re.search(r"\bbl\s+[0-9a-f]+ <fx_verify", body), body


def test_path2_no_native_result_branch(artifacts):
    _, _, disasm = artifacts
    body = _decision_block(disasm)
    # No cbz/cbnz/tbz/tbnz in the wrapper: all decision branches live in the VM.
    assert not re.search(r"\b(cbz|cbnz|tbz|tbnz)\b", body), body


def test_path3_no_compare_failure_edge(artifacts):
    _, _, disasm = artifacts
    body = _decision_block(disasm)
    assert not re.search(r"\bbl\s+[0-9a-f]+ <fx_compare", body), body


def test_path4_no_transport_call(artifacts):
    _, _, disasm = artifacts
    body = _decision_block(disasm)
    assert not re.search(r"\bbl\s+[0-9a-f]+ <fx_transport", body), body


def test_path5_no_executable_zero_cave(artifacts):
    work, exe, _ = artifacts
    hardener = _tool("xollvm-elf-hardener")
    if not hardener.exists():
        pytest.skip("hardener not built")
    # Seal first so the manifest exists, then audit.
    sealed = work / "f.sealed.so"
    subprocess.run([str(hardener), "seal", "--input", str(exe), "--output", str(sealed)],
                   check=True, capture_output=True, text=True, timeout=120)
    p = subprocess.run([str(hardener), "audit", "--input", str(sealed),
                        "--zero-threshold", "512"],
                       capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
