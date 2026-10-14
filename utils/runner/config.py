"""Tool detection: locate clang and opt inside the LLVM build directory."""

from __future__ import annotations

import platform
import os
from dataclasses import dataclass
from pathlib import Path

from .util import die


_TERMUX_CLANG = Path("/data/data/com.termux/files/usr/bin/clang")


@dataclass(frozen=True)
class Tools:
    clang: Path
    opt: Path
    llc: Path | None = None  # optional — only required for cross-arch builds
    host_clang: Path | None = None
    android_clangxx: Path | None = None


def detect_tools(build_dir: Path, config: str) -> Tools:
    exe = ".exe" if platform.system() == "Windows" else ""
    search = [build_dir / "bin", build_dir / config / "bin"]
    bin_dir: Path | None = None
    for d in search:
        if (d / f"opt{exe}").exists():
            bin_dir = d
            break
    if not bin_dir:
        die(f"Cannot find opt in: {', '.join(str(d) for d in search)}")
    assert bin_dir is not None

    clang = bin_dir / f"clang{exe}"
    if not clang.exists():
        clang = bin_dir / f"clang-cl{exe}"
    if not clang.exists():
        die(f"clang not found in: {bin_dir}")

    llc_path = bin_dir / f"llc{exe}"
    llc = llc_path if llc_path.exists() else None
    host_clang = _TERMUX_CLANG if platform.system() == "Android" and _TERMUX_CLANG.exists() else None
    android_clangxx = None
    if host_clang is not None:
        ndk = Path(os.environ.get("XOLLVM_NDK", Path.home() / "android-ndk-r30-ollvm-r23-beta3"))
        candidate = ndk / "toolchains/llvm/prebuilt/linux-arm64/bin/clang++"
        if candidate.is_file():
            android_clangxx = candidate

    return Tools(clang=clang, opt=bin_dir / f"opt{exe}", llc=llc,
                  host_clang=host_clang, android_clangxx=android_clangxx)
