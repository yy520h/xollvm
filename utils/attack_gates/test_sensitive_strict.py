"""Task 4: strict sensitive-decision enforcement gates.

Runs the in-tree obfuscator (`opt -passes=obfuscation`) over .ll fixtures and
asserts that a `sensitive(strict=1)` region which cannot be proven protected
fails the build with a region-scoped diagnostic, while a valid boundary
compiles and carries the post-commit proof metadata.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


def _opt_path() -> Path:
    env = os.environ.get("XOLLVM_OPT")
    if env:
        return Path(env)
    repo = Path(__file__).resolve().parents[2]
    root = repo.parents[2] if repo.parent.name == ".worktrees" else repo.parent
    for cand in (root / "build-sensitive" / "bin" / "opt",
                 root / "build" / "bin" / "opt"):
        if cand.exists():
            return cand
    return root / "build-sensitive" / "bin" / "opt"


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


def _compile(tmp_path: Path, body: str, ann: str) -> subprocess.CompletedProcess:
    opt = _opt_path()
    if not opt.exists():
        pytest.skip(f"obfuscator opt not found at {opt}")
    src = tmp_path / "fixture.ll"
    src.write_text(body + _annotate("auth", ann))
    return subprocess.run(
        [str(opt), "-passes=obfuscation", "-S", str(src), "-o", os.devnull],
        capture_output=True, text=True, timeout=180)


SENSITIVE_VM = "obf: sensitive(region=auth,strict=1), vm(encBytecode=0)"
SENSITIVE_NOVM = "obf: sensitive(region=auth,strict=1)"


def _expect_fatal(tmp_path, body, ann, needle):
    proc = _compile(tmp_path, body, ann)
    assert proc.returncode != 0, proc.stdout + proc.stderr
    combined = proc.stdout + proc.stderr
    assert "obfuscator: sensitive region 'auth'" in combined, combined
    assert needle in combined, combined


def test_invoke_region_fails_strict(tmp_path):
    _expect_fatal(tmp_path, r"""
declare i32 @verify(i32)
declare i32 @__gxx_personality_v0(...)
define i32 @auth(i32 %x) personality ptr @__gxx_personality_v0 {
entry:
  %r = invoke i32 @verify(i32 %x) to label %ok unwind label %lpad
ok:
  %okv = icmp eq i32 %r, 1
  br i1 %okv, label %success, label %fail
success:
  ret i32 1
fail:
  ret i32 0
lpad:
  %lp = landingpad { ptr, i32 } cleanup
  ret i32 0
}
""", SENSITIVE_VM, "EH/invoke")


def test_indirectbr_region_fails_strict(tmp_path):
    _expect_fatal(tmp_path, r"""
declare i32 @verify(i32)
define i32 @auth(i32 %x) {
entry:
  %r = call i32 @verify(i32 %x)
  %ok = icmp eq i32 %r, 1
  br i1 %ok, label %success, label %fail
success:
  %d = select i1 %ok, ptr blockaddress(@auth, %a), ptr blockaddress(@auth, %b)
  indirectbr ptr %d, [label %a, label %b]
a:
  ret i32 1
b:
  ret i32 0
fail:
  ret i32 0
}
""", SENSITIVE_VM, "indirectbr")


def test_oversized_region_fails_strict(tmp_path):
    _expect_fatal(tmp_path, r"""
declare i32 @verify(i32)
define i32 @auth(i32 %x) {
entry:
  %r = call i32 @verify(i32 %x)
  %c1 = icmp eq i32 %r, 1
  br i1 %c1, label %a, label %b
a:
  br label %c
b:
  br label %c
c:
  %c2 = icmp eq i32 %r, 2
  br i1 %c2, label %success, label %fail
success:
  ret i32 1
fail:
  ret i32 0
}
""", "obf: sensitive(region=auth,strict=1), vm(encBytecode=0,maxBlocks=2)",
        "too many blocks")


def test_missing_vm_fails_strict(tmp_path):
    _expect_fatal(tmp_path, r"""
declare i32 @verify(i32)
define i32 @auth(i32 %x) {
entry:
  %r = call i32 @verify(i32 %x)
  %ok = icmp eq i32 %r, 1
  br i1 %ok, label %success, label %fail
success:
  ret i32 1
fail:
  ret i32 0
}
""", SENSITIVE_NOVM, "vm pass")


def test_raw_tainted_return_fails_strict(tmp_path):
    _expect_fatal(tmp_path, r"""
declare i32 @verify(i32)
define i32 @auth(i32 %x) {
entry:
  %r = call i32 @verify(i32 %x)
  %ok = icmp eq i32 %r, 1
  br i1 %ok, label %success, label %fail
success:
  ret i32 1
fail:
  ret i32 %r
}
""", SENSITIVE_VM, "escapes through return")


def test_valid_literal_return_commits(tmp_path):
    proc = _compile(tmp_path, r"""
declare i32 @verify(i32)
define i32 @auth(i32 %x) {
entry:
  %r = call i32 @verify(i32 %x)
  %ok = icmp eq i32 %r, 1
  br i1 %ok, label %success, label %fail
success:
  ret i32 1
fail:
  ret i32 0
}
""", SENSITIVE_VM)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = tmp_path / "out.ll"
    # Re-run capturing output to inspect metadata.
    opt = _opt_path()
    src = tmp_path / "fixture.ll"
    subprocess.run([str(opt), "-passes=obfuscation", "-S", str(src), "-o", str(out)],
                   check=True, capture_output=True, text=True, timeout=180)
    text = out.read_text()
    assert "obf.sensitive.validated" in text
    assert "obf.sensitive.committed" in text


def test_valid_multi_return_commits(tmp_path):
    proc = _compile(tmp_path, r"""
declare i32 @verify(i32)
define i32 @auth(i1 %c, i32 %x) {
entry:
  br i1 %c, label %a, label %b
a:
  %r = call i32 @verify(i32 %x)
  %ok = icmp eq i32 %r, 1
  br i1 %ok, label %s1, label %f1
s1:
  ret i32 1
f1:
  ret i32 0
b:
  %r2 = call i32 @verify(i32 %x)
  %ok2 = icmp eq i32 %r2, 2
  br i1 %ok2, label %s2, label %f2
s2:
  ret i32 1
f2:
  ret i32 0
}
""", SENSITIVE_VM)
    assert proc.returncode == 0, proc.stdout + proc.stderr
