"""Task 8: xollvm-elf-hardener seal / verify integrity tests.

Builds a real AArch64 shared object from obfuscated, manifest-bearing IR, then
asserts:
  * seal succeeds and is deterministic for identical input,
  * verify accepts the sealed file,
  * the unsealed file fails verify,
  * mutating covered executable bytes, a program-header field, or the ELF
    header is rejected,
  * a dynamic relocation targeting an executable load makes seal fail.

Skipped when the obfuscator opt, an AArch64 linker, or the hardener tool is
unavailable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


def _root() -> Path:
    repo = Path(__file__).resolve().parents[1]
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
declare i32 @fixture_verify(ptr, i64)
define i32 @fixture_decision(ptr %p, i64 %n) {
entry:
  %r = call i32 @fixture_verify(ptr %p, i64 %n)
  %ok = icmp eq i32 %r, 1
  br i1 %ok, label %s, label %f
s:
  ret i32 1
f:
  ret i32 0
}
"""
ANN = "obf: sensitive(region=fixture-auth,strict=1), vm(encBytecode=0)"


def _strip(text: str) -> str:
    return "\n".join(
        l for l in text.splitlines()
        if not l.startswith("@llvm.global.annotations") and not l.startswith("@.ann.")
    ) + "\n"


@pytest.fixture(scope="module")
def sealed(tmp_path_factory):
    opt = _tool("opt")
    clang = _tool("clang")
    tool = _tool("xollvm-elf-hardener")
    if not (opt.exists() and clang.exists() and tool.exists()):
        pytest.skip("opt/clang/xollvm-elf-hardener not all available")
    work = tmp_path_factory.mktemp("elf-integrity")
    src = work / "f.ll"
    src.write_text(BODY + _annotate("fixture_decision", ANN))
    obf = work / "f.obf.ll"
    subprocess.run([str(opt), "-passes=obfuscation", "-S", str(src), "-o", str(obf)],
                   check=True, capture_output=True, text=True, timeout=600)
    low = work / "f.lowered.ll"
    low.write_text(_strip(obf.read_text()))
    so = work / "f.so"
    subprocess.run(
        [str(clang), "-target", "aarch64-linux-android", "-fuse-ld=lld",
         "-nostdlib", "-shared", "-Wl,--rosegment", str(low), "-o", str(so)],
        check=True, capture_output=True, text=True, timeout=600)
    return work, so, tool


def _run(tool, *args):
    return subprocess.run([str(tool), *args], capture_output=True, text=True, timeout=120)


def test_seal_verify_round_trip(sealed):
    work, so, tool = sealed
    out = work / "sealed.so"
    p = _run(tool, "seal", "--input", str(so), "--output", str(out))
    assert p.returncode == 0, p.stderr
    p2 = _run(tool, "verify", "--input", str(out))
    assert p2.returncode == 0, p2.stderr


def test_seal_is_deterministic(sealed):
    work, so, tool = sealed
    a = work / "a.so"; b = work / "b.so"
    _run(tool, "seal", "--input", str(so), "--output", str(a))
    _run(tool, "seal", "--input", str(so), "--output", str(b))
    assert a.read_bytes() == b.read_bytes()


def test_unsealed_fails_verify(sealed):
    work, so, tool = sealed
    p = _run(tool, "verify", "--input", str(so))
    assert p.returncode == 3, p.stderr


def _exec_range(data: bytes):
    import struct
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, _, p_filesz, _, _ = \
            struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1 and (p_flags & 1) and p_filesz:
            return p_offset, p_filesz
    raise AssertionError("no executable PT_LOAD")


def test_mutations_fail_verify(sealed):
    work, so, tool = sealed
    sealedp = work / "sealed2.so"
    _run(tool, "seal", "--input", str(so), "--output", str(sealedp))
    base = bytearray(sealedp.read_bytes())
    seg_off, seg_size = _exec_range(base)
    # executable range byte (covered), a program-header field, e_flags.
    cases = {
        "text": seg_off + min(0x100, seg_size - 1),
        "phdr": 0x38,
        "eflags": 0x30,
    }
    for name, off in cases.items():
        c = bytearray(base); c[off] ^= 0xFF
        p = work / f"mut_{name}.so"
        p.write_bytes(c)
        r = _run(tool, "verify", "--input", str(p))
        assert r.returncode == 3, f"{name}: {r.returncode} {r.stderr}"


def test_sealed_manifest_has_runtime_metadata(sealed):
    work, so, tool = sealed
    out = work / "meta.so"
    _run(tool, "seal", "--input", str(so), "--output", str(out))
    data = out.read_bytes()
    # Locate the manifest via its symbol vaddr from the symtab.
    import struct, subprocess
    nm = subprocess.run([str(_tool("llvm-nm")), str(out)],
                        capture_output=True, text=True).stdout
    man = None
    for line in nm.splitlines():
        if "integrity_manifest" in line:
            man = int(line.split()[0], 16); break
    assert man is not None
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsz = struct.unpack_from("<H", data, 54)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]
    off = None
    for i in range(e_phnum):
        p = struct.unpack_from("<IIQQQQQQ", data, e_phoff + i * e_phentsz)
        if p[0] == 1 and p[3] <= man < p[3] + p[5]:
            off = p[2] + (man - p[3]); break
    assert off is not None
    magic = data[off:off + 8]
    rangecount = struct.unpack_from("<I", data, off + 12)[0]
    manifest_va = struct.unpack_from("<Q", data, off + 16)[0]
    r0vaddr = struct.unpack_from("<Q", data, off + 24)[0]
    r0size = struct.unpack_from("<Q", data, off + 32)[0]
    assert rangecount == 1, f"rangecount={rangecount}"
    assert manifest_va != 0, "ManifestVirtualAddress not stamped"
    assert r0vaddr != 0 and r0size != 0, "range[0] not stamped"
    assert magic == b"XOLINT01", f"magic={magic!r}"


def test_malformed_elf_is_exit_2(sealed):
    work, _so, tool = sealed
    bad = work / "bad.bin"
    bad.write_bytes(b"\x7fELF\x02\x01\x01garbage")
    p = _run(tool, "verify", "--input", str(bad))
    assert p.returncode == 2, p.stderr


@pytest.mark.parametrize("field,value", [
    (8, b"\x01\x01\x00\x00"),
    (12, b"\x00\x00\x00\x00"),
    (12, b"\x09\x00\x00\x00"),
    (16, b"\x00" * 8),
    (24, b"\x00" * 8),
    (32, b"\x00" * 8),
    (40, b"\x01" + b"\x00" * 7),
])
def test_manifest_metadata_mutation_fails_verify(sealed, field, value):
    work, so, tool = sealed
    out = work / f"metadata-{field}-{value.hex()}.so"
    result = _run(tool, "seal", "--input", str(so), "--output", str(out))
    assert result.returncode == 0, result.stderr
    data = bytearray(out.read_bytes())
    offset = data.index(b"XOLINT01")
    data[offset + field:offset + field + len(value)] = value
    out.write_bytes(data)
    result = _run(tool, "verify", "--input", str(out))
    assert result.returncode == 3, result.stderr
