"""Task 9: final-link wrapper integration tests.

The wrapper is a bash script shipped in the demo tree (outside this repo).
This test drives a copy of the wrapper logic against a stub "real clang" so
the output-discovery, audit, seal, atomic-promotion and failure paths are
verified without an NDK or a real demo build.

It copy-invokes the wrapper from the demo path when present, else skips.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

WRAPPER = Path("/data/user/0/com.termux/files/home/xollvm-android/demo/jni/"
               "ndk-linker-wrapper/clang++")


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


@pytest.fixture()
def env(tmp_path):
    if not WRAPPER.exists():
        pytest.skip("demo wrapper not available")
    hardener = _tool("xollvm-elf-hardener")
    if not hardener.exists():
        pytest.skip("xollvm-elf-hardener not built")

    # Stub "real clang": copies a canned ELF to the -o argument.
    real = tmp_path / "real-clang"
    canned = tmp_path / "canned.so"
    # Produce a canned ELF using the obfuscator pipeline is heavy; instead make
    # the stub touch an ELF header the hardener will reject as needed.
    real.write_text(
        "#!/data/data/com.termux/files/usr/bin/bash\n"
        "out=''; prev=''\n"
        "for a in \"$@\"; do\n"
        "  if [ \"$prev\" = -o ]; then out=\"$a\"; prev=''; continue; fi\n"
        "  case \"$a\" in -o) prev=-o;; -o*) out=\"${a#-o}\";; esac\n"
        "done\n"
        "cp \"$STUB_ELF\" \"$out\"\n"
    )
    real.chmod(real.stat().st_mode | stat.S_IEXEC)

    envd = dict(os.environ)
    envd["XOLLVM_REAL_CLANG"] = str(real)
    envd["XOLLVM_OBFUSCATOR_CLANG"] = str(real)
    envd["XOLLVM_ELF_HARDENER"] = str(hardener)
    envd["STUB_ELF"] = str(canned)
    return envd, canned, real, tmp_path


def _write_canned_elf(path: Path, seg_flags=5, zerolen=512):
    # Minimal ELF64LE/AArch64 with one PT_LOAD; mirrors elf_hardener_test.
    import struct
    EH, PH = 64, 56
    data = b"\x01" * 16 + b"\x00" * zerolen + b"\x02" * 16
    data_off = EH + PH
    buf = bytearray(data_off + len(data))
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    struct.pack_into("<16sHHIQQQIHHHHHH", buf, 0, ident, 2, 183, 1, 0,
                     EH, 0, 0, EH, PH, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", buf, EH, 1, seg_flags, data_off, 0x400000,
                     0x400000, len(data), len(data), 0x1000)
    buf[data_off:data_off + len(data)] = data
    path.write_bytes(bytes(buf))


def test_compile_only_does_not_invoke_hardener(env):
    envd, _canned, _real, tmp = env
    envd["XOLLVM_ELF_HARDENER"] = "/nonexistent/hardener"
    p = subprocess.run(["bash", str(WRAPPER), "-c", "x.c", "-o", "x.o"],
                       capture_output=True, text=True, env=envd, timeout=60)
    # Stub real-clang ignores -c and copies STUB_ELF; the point is the wrapper
    # must not fail on the missing hardener for compile-only.
    assert "hardener not executable" not in p.stderr


def test_link_runs_audit_and_cleans_temp_when_seal_fails(env):
    # A canned ELF with no manifest: audit passes (RW zero run is allowed) but
    # seal must fail, and the wrapper must not emit the requested output nor
    # leave the temporary file behind.
    envd, canned, _real, tmp = env
    _write_canned_elf(canned, seg_flags=6, zerolen=512)
    out = tmp / "out.so"
    p = subprocess.run(["bash", str(WRAPPER), "-o", str(out)],
                       capture_output=True, text=True, env=envd, timeout=120)
    assert p.returncode != 0
    assert "audit" in p.stderr
    assert "seal failed" in p.stderr
    assert not out.exists()
    assert not (tmp / "out.so.xollvm-unsealed").exists()


def test_link_fails_on_executable_cave(env):
    envd, canned, _real, tmp = env
    _write_canned_elf(canned, seg_flags=5, zerolen=512)  # PF_X zero run -> audit fail
    out = tmp / "out.so"
    p = subprocess.run(["bash", str(WRAPPER), "-o", str(out)],
                       capture_output=True, text=True, env=envd, timeout=120)
    assert p.returncode != 0
    assert not out.exists()
    assert not (tmp / "out.so.xollvm-unsealed").exists()


def test_existing_output_preserved_on_failure(env):
    envd, canned, _real, tmp = env
    _write_canned_elf(canned, seg_flags=5, zerolen=512)
    out = tmp / "out.so"
    out.write_bytes(b"PRECIOUS")
    p = subprocess.run(["bash", str(WRAPPER), "-o", str(out)],
                       capture_output=True, text=True, env=envd, timeout=120)
    assert p.returncode != 0
    assert out.read_bytes() == b"PRECIOUS"
