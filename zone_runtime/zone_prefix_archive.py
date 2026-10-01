#!/usr/bin/env python3
"""Create a selectively symbol-prefixed copy of a static archive.

The mapping is applied to both definitions and references in every member.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import shutil
import subprocess
import tempfile

SYSTEM = re.compile(
    r"^(?:malloc|calloc|realloc|free|mem|str|wcs|printf|puts|abort|exit|"
    r"close|read|write|open|socket|connect|select|poll|fcntl|pthread_|dl|"
    r"__|_Unwind|stdin|stdout|stderr|errno|android_|__cxa_|_Z)"
)


def nm_symbols(path: pathlib.Path) -> set[str]:
    result = subprocess.run(["nm", "-g", str(path)], text=True,
                            capture_output=True, check=True)
    symbols = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if fields and fields[-1] != "U":
            name = fields[-1]
            if name not in {"U", "w"} and not SYSTEM.match(name):
                symbols.add(name)
    return symbols


def prefix_archive(source: pathlib.Path, output: pathlib.Path, prefix: str) -> None:
    ar = shutil.which("ar")
    objcopy = shutil.which("objcopy") or shutil.which("llvm-objcopy")
    if not ar or not objcopy:
        raise RuntimeError("ar and objcopy are required to prefix Zone archives")
    source = source.resolve()
    output = output.resolve()
    with tempfile.TemporaryDirectory(prefix="xollvm-zone-prefix-") as temp:
        root = pathlib.Path(temp)
        subprocess.run([ar, "x", str(source)], cwd=root, check=True)
        objects = sorted(root.iterdir())
        names = set()
        for obj in objects:
            names.update(nm_symbols(obj))
        mapping = root / "symbols.map"
        mapping.write_text("\n".join(f"{name} {prefix}{name}" for name in sorted(names)) + "\n")
        for obj in objects:
            subprocess.run([objcopy, "--redefine-syms", str(mapping), str(obj)], check=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            output.unlink()
        subprocess.run([ar, "rcs", str(output), *(str(obj) for obj in objects)], check=True)


def prefix_archives(sources: list[pathlib.Path], output: pathlib.Path,
                    prefixes: list[tuple[str, str]],
                    runtime_sources: set[pathlib.Path] | None = None) -> None:
    ar = shutil.which("ar")
    objcopy = shutil.which("objcopy") or shutil.which("llvm-objcopy")
    if not ar or not objcopy:
        raise RuntimeError("ar and objcopy are required to prefix Zone archives")
    sources = [source.resolve() for source in sources]
    output = output.resolve()
    with tempfile.TemporaryDirectory(prefix="xollvm-zone-prefix-") as temp:
        root = pathlib.Path(temp)
        objects = []
        for index, source in enumerate(sources):
            member_dir = root / str(index)
            member_dir.mkdir()
            subprocess.run([ar, "x", str(source)], cwd=member_dir, check=True)
            objects.extend(sorted(member_dir.iterdir()))
        names = set()
        for obj in objects:
            result = subprocess.run(["nm", "-g", str(obj)], text=True,
                                    capture_output=True, check=True)
            for line in result.stdout.splitlines():
                fields = line.split()
                if fields:
                    name = fields[-1]
                    if name not in {"U", "w"} and not SYSTEM.match(name):
                        names.add(name)
                    elif name not in {"U", "w"} and not SYSTEM.match(name):
                        names.add(name)
        mapping = root / "symbols.map"
        rows = []
        for name in sorted(names):
            for prefix, stem in prefixes:
                if name.startswith(stem) and not name.startswith(prefix):
                    rows.append(f"{name} {prefix}{name}")
                    break
        mapping.write_text("\n".join(rows) + "\n")
        for obj in objects:
            subprocess.run([objcopy, "--redefine-syms", str(mapping), str(obj)], check=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            output.unlink()
        subprocess.run([ar, "rcs", str(output), *(str(obj) for obj in objects)], check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", action="append", required=True)
    parser.add_argument("--runtime-source", action="append", default=[],
                        type=pathlib.Path)
    parser.add_argument("sources", nargs="+", type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    prefixes = []
    for value in args.prefix:
        prefix, stem = value.split("=", 1)
        prefixes.append((prefix, stem))
    prefix_archives(args.sources, args.output, prefixes,
                    {path.resolve() for path in args.runtime_source})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
