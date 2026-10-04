"""Task 7: xollvm-elf-hardener executable-cave auditor tests.

Synthesizes minimal ELF64LE/AArch64 fixtures with precise zero-run sizes and
segment permissions, then asserts the auditor's exit codes and diagnostics.

Policy under test:
  * executability is PT_LOAD.p_flags & PF_X (never section SHF_EXECINSTR)
  * a non-allowlisted executable zero run >= threshold (512, inclusive) fails
  * section ownership is diagnostic/allowlist only, and survives stripped
    section headers
"""

from __future__ import annotations

import struct
import subprocess
from pathlib import Path

import pytest


def _tool() -> Path:
    repo = Path(__file__).resolve().parents[1]
    root = repo.parents[2] if repo.parent.name == ".worktrees" else repo.parent
    for cand in (root / "build-sensitive" / "bin" / "xollvm-elf-hardener",
                 root / "build" / "bin" / "xollvm-elf-hardener"):
        if cand.exists():
            return cand
    return root / "build-sensitive" / "bin" / "xollvm-elf-hardener"


def build_elf(segments, sections=(), machine=183, elf_class=2, elf_data=1):
    """segments: list of dict(flags, data, vaddr); sections: list of
    dict(name, offset, size, type=1)."""
    EH, PH, SH = 64, 56, 64
    phoff = EH
    phnum = len(segments)
    data_off = phoff + PH * phnum
    seg_off = []
    cur = data_off
    for s in segments:
        seg_off.append(cur)
        cur += len(s["data"])

    shstr = b"\x00"
    no = {}
    for sec in sections:
        no[sec["name"]] = len(shstr)
        shstr += sec["name"].encode() + b"\x00"
    no[".shstrtab"] = len(shstr)
    shstr += b".shstrtab\x00"

    shstr_off = cur
    cur += len(shstr)
    if cur % 8:
        cur += 8 - (cur % 8)
    shoff = cur
    shnum = 1 + len(sections) + 1
    buf = bytearray(shoff + SH * shnum)

    ident = b"\x7fELF" + bytes([elf_class, elf_data, 1]) + bytes(9)
    struct.pack_into("<16sHHIQQQIHHHHHH", buf, 0, ident, 2, machine, 1, 0,
                     phoff, shoff, 0, EH, PH, phnum, SH, shnum, shnum - 1)
    for i, s in enumerate(segments):
        struct.pack_into("<IIQQQQQQ", buf, phoff + i * PH, 1, s["flags"],
                         seg_off[i], s["vaddr"], s["vaddr"], len(s["data"]),
                         len(s["data"]), 0x1000)
    for i, s in enumerate(segments):
        buf[seg_off[i]:seg_off[i] + len(s["data"])] = s["data"]
    buf[shstr_off:shstr_off + len(shstr)] = shstr
    for j, sec in enumerate(sections):
        struct.pack_into("<IIQQQQIIQQ", buf, shoff + (1 + j) * SH,
                         no[sec["name"]], sec.get("type", 1), 0, 0,
                         sec["offset"], sec["size"], 0, 0, 0, 0)
    struct.pack_into("<IIQQQQIIQQ", buf, shoff + (shnum - 1) * SH,
                     no[".shstrtab"], 3, 0, 0, shstr_off, len(shstr),
                     0, 0, 0, 0)
    return bytes(buf)


def seg(flags, prefix, zerolen, trailer=b"\x02" * 16):
    return {"flags": flags, "data": prefix + b"\x00" * zerolen + trailer,
            "vaddr": 0x400000}


DATA_OFF = 64 + 56  # ehdr + one phdr


def run(tmp_path, data, *extra):
    elf = tmp_path / "fixture.elf"
    elf.write_bytes(data)
    return subprocess.run(
        [str(_tool()), "audit", "--input", str(elf), "--zero-threshold", "512",
         *extra],
        capture_output=True, text=True, timeout=60)


def test_511_byte_run_is_below_threshold(tmp_path):
    p = run(tmp_path, build_elf([seg(5, b"\x01" * 16, 511)]))
    assert p.returncode == 0, p.stderr


def test_512_byte_run_in_pf_x_fails(tmp_path):
    p = run(tmp_path, build_elf([seg(5, b"\x01" * 16, 512)]))
    assert p.returncode == 3, p.stderr
    assert "permissions r-x" in p.stderr
    assert "size 512" in p.stderr


def test_513_byte_run_in_pf_x_fails(tmp_path):
    p = run(tmp_path, build_elf([seg(5, b"\x01" * 16, 513)]))
    assert p.returncode == 3, p.stderr
    assert "size 513" in p.stderr


def test_rw_zero_run_is_reported_but_allowed(tmp_path):
    p = run(tmp_path, build_elf([seg(6, b"\x01" * 16, 512)]))
    assert p.returncode == 0, p.stderr
    assert "permissions rw-" in p.stderr


def test_rodata_owner_reported_and_allowlisted(tmp_path):
    ro = {"name": ".rodata", "offset": DATA_OFF + 16, "size": 512}
    data = build_elf([seg(5, b"\x01" * 16, 512)], sections=[ro])
    p = run(tmp_path, data)
    assert p.returncode == 3, p.stderr
    assert "section .rodata" in p.stderr

    p2 = run(tmp_path, data, "--allow-section", ".rodata")
    assert p2.returncode == 0, p2.stderr


def test_stripped_section_headers_still_audits(tmp_path):
    # Same PF_X 512-byte run, but with e_shoff/e_shnum zeroed.
    data = bytearray(build_elf([seg(5, b"\x01" * 16, 512)]))
    struct.pack_into("<Q", data, 40, 0)   # e_shoff
    struct.pack_into("<H", data, 60, 0)   # e_shnum
    struct.pack_into("<H", data, 62, 0)   # e_shstrndx
    p = run(tmp_path, bytes(data))
    assert p.returncode == 3, p.stderr
    assert "section <none>" in p.stderr


def test_malformed_short_file_is_exit_2(tmp_path):
    p = run(tmp_path, b"\x7fELF\x02\x01\x01")
    assert p.returncode == 2, p.stderr


def test_non_aarch64_is_exit_2(tmp_path):
    p = run(tmp_path, build_elf([seg(5, b"\x01" * 16, 512)], machine=62))
    assert p.returncode == 2, p.stderr


def test_elf32_is_exit_2(tmp_path):
    p = run(tmp_path, build_elf([seg(5, b"\x01" * 16, 512)], elf_class=1))
    assert p.returncode == 2, p.stderr
