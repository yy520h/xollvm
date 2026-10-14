"""Task 6: Zone capability sensitive-boundary structural gate.

The full demo cannot be built in this environment (OpenSSL/curl/zlib are
source-only). Instead this gate compiles the demo's capability_client.cpp to
LLVM IR, runs the obfuscator over it, and asserts:

  * the single `sensitive(region=zone-capability, strict=1)` region validates
    and commits (compilation succeeds),
  * the protected decision symbol retains no direct call to the verifier API,
  * the protected decision symbol reaches the engine indirectly.

It is skipped when the demo source or the obfuscator opt is unavailable.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


def _root() -> Path:
    repo = Path(__file__).resolve().parents[2]
    return repo.parents[2] if repo.parent.name == ".worktrees" else repo.parent


def _demo_client() -> Path:
    return Path("/data/user/0/com.termux/files/home/xollvm-android/demo/jni/"
                "zone_runtime/capability_client.cpp")


def _tool(name: str) -> Path:
    root = _root()
    for base in (root / "build-sensitive" / "bin", root / "build" / "bin"):
        cand = base / name
        if cand.exists():
            return cand
    return root / "build-sensitive" / "bin" / name


def _strip_annotations(text: str) -> str:
    keep = [l for l in text.splitlines()
            if not l.startswith("@llvm.global.annotations") and not l.startswith("@.ann.")]
    return "\n".join(keep) + "\n"


@pytest.fixture(scope="module")
def obf_ir(tmp_path_factory):
    client = _demo_client()
    if not client.exists():
        pytest.skip("demo capability_client.cpp not available")
    host_clang = shutil.which("clang++") or shutil.which("clang")
    opt = _tool("opt")
    if not host_clang or not opt.exists():
        pytest.skip("clang++ or obfuscator opt not available")

    work = tmp_path_factory.mktemp("zone-boundary")
    ir = work / "cap.ll"
    subprocess.run(
        [host_clang, "-std=c++17", "-DXOLLVM_ZONE_OBFUSCATE=1",
         "-I", str(client.parent), "-S", "-emit-llvm", str(client), "-o", str(ir)],
        check=True, capture_output=True, text=True, timeout=300)
    assert "sensitive(region=zone-capability" in ir.read_text()
    return ir, work


def test_zone_region_validates_and_commits(obf_ir):
    ir, work = obf_ir
    opt = _tool("opt")
    out = work / "cap.obf.ll"
    proc = subprocess.run(
        [str(opt), "-passes=obfuscation", "-S", str(ir), "-o", str(out)],
        capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    text = out.read_text()
    assert "obf.sensitive.validated" in text
    assert "obf.sensitive.committed" in text


def test_sensitive_decision_uses_encrypted_lazy_bytecode(obf_ir):
    ir, work = obf_ir
    out = work / "cap.obf.ll"
    if not out.exists():
        subprocess.run([str(_tool("opt")), "-passes=obfuscation", "-S", str(ir),
                        "-o", str(out)], check=True, capture_output=True,
                       text=True, timeout=600)
    text = out.read_text()
    decision = re.search(
        r"define[^\n]*@([^\s(]*22acceptVerifiedResponse[^\s(]*)\([^\n]*\{(.*?)\n\}",
        text, re.S)
    assert decision, "sensitive decision wrapper missing"
    symbol, body = decision.groups()
    assert f"@{symbol}.vm.aes.rk" in body, "decision bytecode lacks AES key setup"
    assert "vm.lazy.ctx" in body, "decision eagerly exposes decrypted bytecode"
    assert "vm.regkeys" in body, "hardened decision lacks encrypted register state"
    assert re.search(r"\bcall\b[^\n]*@__obf_aes_ctr_keystream_block\s*\(", text), \
        "lazy instruction decoder missing"


def test_protected_symbol_has_no_direct_verifier_and_uses_indirect_engine(obf_ir):
    ir, work = obf_ir
    opt = _tool("opt")
    clang = _tool("clang")
    objdump = _tool("llvm-objdump")
    if not clang.exists() or not objdump.exists():
        pytest.skip("AArch64 clang/objdump not available")

    obf = work / "cap.obf.ll"
    if not obf.exists():
        subprocess.run([str(opt), "-passes=obfuscation", "-S", str(ir), "-o", str(obf)],
                       check=True, capture_output=True, text=True, timeout=600)
    lowered = work / "cap.lowered.ll"
    lowered.write_text(_strip_annotations(obf.read_text()))
    obj = work / "cap.o"
    subprocess.run(
        [str(clang), "-target", "aarch64-linux-android", "-O0",
         "-Wno-override-module", "-c", str(lowered), "-o", str(obj)],
        check=True, capture_output=True, text=True, timeout=300)
    disasm = subprocess.run(
        [str(objdump), "-d", str(obj)],
        check=True, capture_output=True, text=True, timeout=120).stdout

    m = re.search(r"<([^>]*22acceptVerifiedResponse[^>]*)>:\n(.*?)(?=\n[0-9a-f]+ <|\Z)",
                  disasm, re.S)
    assert m, "acceptVerifiedResponse symbol not found in disassembly"
    body = m.group(2)
    assert "EVP_DigestVerify" not in body
    assert re.search(r"\bblr\b", body), body
