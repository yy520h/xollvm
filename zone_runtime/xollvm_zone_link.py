#!/usr/bin/env python3
"""Resolve XOLLVM Zone link requirements from object/IR marker inputs."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
import subprocess
from dataclasses import dataclass

try:
    from .zone_dependency_manifest import DEPENDENCIES
except ImportError:
    from zone_dependency_manifest import DEPENDENCIES

MARKER = b"xollvm-zone-v1;"
MODES = {"bundled", "external"}


@dataclass(frozen=True)
class LibraryInspection:
    path: pathlib.Path
    compatible: bool
    reason: str = ""


@dataclass(frozen=True)
class DependencyDecision:
    status: str
    path: pathlib.Path | None = None
    reason: str = ""


def _symbols(path: pathlib.Path) -> set[str]:
    tool = os.environ.get("XOLLVM_NM", "nm")
    result = subprocess.run([tool, "-g", str(path)], text=True,
                            capture_output=True, check=True)
    symbols = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3:
            symbols.add(fields[-1])
    return symbols


def inspect_library(path: pathlib.Path, spec, target_triple: str) -> LibraryInspection:
    try:
        symbols = _symbols(path)
    except (OSError, subprocess.CalledProcessError) as exc:
        return LibraryInspection(path, False, f"cannot inspect {spec.name}: {exc}")
    missing = [symbol for symbol in spec.required_symbols if symbol not in symbols]
    if missing:
        return LibraryInspection(path, False,
                                 f"missing required symbol {missing[0]}")
    return LibraryInspection(path, True)


def _candidate_paths(args: list[str], spec, search_dirs: list[pathlib.Path]):
    candidates = []
    for index, arg in enumerate(args):
        if arg in (f"-l{name}" for name in spec.link_names):
            candidates.extend(search_dirs)
        elif arg == "-l" and index + 1 < len(args) and args[index + 1] in spec.link_names:
            candidates.extend(search_dirs)
        elif arg.endswith((".a", ".so")) and pathlib.Path(arg).name in {
            f"lib{name}.a" for name in spec.link_names
        } | {f"lib{name}.so" for name in spec.link_names}:
            candidates.append(pathlib.Path(arg).parent)
    paths = []
    for directory in candidates:
        for name in spec.link_names:
            for suffix in (".a", ".so"):
                path = directory / f"lib{name}{suffix}"
                if path.is_file() and path not in paths:
                    paths.append(path)
    return paths


def _requested(args: list[str], spec) -> bool:
    names = {f"-l{name}" for name in spec.link_names}
    for index, arg in enumerate(args):
        if arg in names:
            return True
        if arg == "-l" and index + 1 < len(args) and args[index + 1] in spec.link_names:
            return True
        if arg.endswith((".a", ".so")) and pathlib.Path(arg).name in {
            f"lib{name}.a" for name in spec.link_names
        } | {f"lib{name}.so" for name in spec.link_names}:
            return True
    return False


def resolve_dependencies(args: list[str], target_triple: str, mode: str,
                         sdk_root: pathlib.Path):
    search_dirs = []
    for index, arg in enumerate(args):
        if arg == "-L" and index + 1 < len(args):
            search_dirs.append(pathlib.Path(args[index + 1]))
        elif arg.startswith("-L") and len(arg) > 2:
            search_dirs.append(pathlib.Path(arg[2:]))
    decisions = {}
    for name, spec in DEPENDENCIES.items():
        candidates = _candidate_paths(args, spec, search_dirs)
        if not candidates:
            decisions[name] = DependencyDecision(
                "add-private" if _requested(args, spec) else "absent",
                reason=("requested but not found for ABI inspection"
                        if _requested(args, spec) else "not in link arguments"),
            )
            continue
        inspection = inspect_library(candidates[0], spec, target_triple)
        decisions[name] = DependencyDecision(
            "reuse" if inspection.compatible else "add-private",
            candidates[0] if inspection.compatible else None,
            inspection.reason,
        )
    return decisions


def read_marker(path: pathlib.Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"cannot read input {path}: {exc}") from exc
    if MARKER not in data:
        return None
    start = data.index(MARKER)
    end = data.find(b"\0", start)
    if end < 0:
        end = min(len(data), start + 256)
    return data[start:end].decode("ascii", errors="strict")


def collect_markers(inputs: list[pathlib.Path]) -> tuple[str | None, set[str]]:
    mode = None
    triples: set[str] = set()
    for path in inputs:
        marker = read_marker(path)
        if marker is None:
            continue
        match = re.fullmatch(r"xollvm-zone-v1;mode=(bundled|external);triple=([^;]*)", marker)
        if not match:
            raise RuntimeError(f"invalid Zone link marker in {path}")
        found_mode, triple = match.groups()
        if mode is not None and mode != found_mode:
            raise RuntimeError("conflicting Zone link modes in input files")
        mode = found_mode
        if triple:
            triples.add(triple)
    return mode, triples


def write_response(output: pathlib.Path, mode: str | None, sdk_root: pathlib.Path) -> None:
    lines: list[str] = []
    if mode == "bundled":
        configured = os.environ.get("XOLLVM_ZONE_BUNDLED_ARCHIVE", "")
        if configured:
            archive = pathlib.Path(configured)
        else:
            candidates = (
                sdk_root / "lib" / "libxollvm_zone_sdk.a",
                sdk_root / "private" / "libxollvm_zone_sdk_private.a",
                sdk_root / "zone_runtime" / "private" / "libxollvm_zone_sdk_private.a",
                sdk_root / "zone_runtime" / "libxollvm_zone_sdk.a",
            )
            archive = next((path for path in candidates if path.is_file()), candidates[0])
        if not archive.is_file():
            raise RuntimeError(
                "bundled Zone archive is not configured; set "
                "XOLLVM_ZONE_BUNDLED_ARCHIVE")
        lines.append(str(archive))
    elif mode == "external":
        archive = pathlib.Path(os.environ.get("XOLLVM_ZONE_EXTERNAL_ARCHIVE", ""))
        if not archive.is_file():
            raise RuntimeError(
                "external Zone archive is not configured; set "
                "XOLLVM_ZONE_EXTERNAL_ARCHIVE")
        lines.append(str(archive))
    output.write_text("\n".join(lines) + ("\n" if lines else ""))


def write_dependency_response(output: pathlib.Path, mode: str | None,
                              sdk_root: pathlib.Path, link_args: list[str],
                              target_triple: str) -> None:
    if mode != "external":
        write_response(output, mode, sdk_root)
        return
    decisions = resolve_dependencies(link_args, target_triple, mode, sdk_root)
    lines = []
    for name, decision in decisions.items():
        variable = f"XOLLVM_ZONE_EXTERNAL_{name.upper()}"
        configured = os.environ.get(variable, "")
        if not configured:
            raise RuntimeError(f"external Zone {name} archive is not configured; set {variable}")
        archive = pathlib.Path(configured)
        if not archive.is_file():
            raise RuntimeError(f"external Zone {name} archive does not exist: {archive}")
        inspection = inspect_library(archive, DEPENDENCIES[name], target_triple)
        if not inspection.compatible and archive.stat().st_size:
            raise RuntimeError(f"external Zone {name} archive is incompatible: {inspection.reason}")
        lines.append(str(archive))
    output.write_text("\n".join(dict.fromkeys(lines)) + ("\n" if lines else ""))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("auto", "bundled", "external"), default="auto")
    parser.add_argument("--target-triple", default="")
    parser.add_argument("--sdk-root", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--link-arg", action="append", default=[])
    parser.add_argument("inputs", nargs="+", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        detected, triples = collect_markers(args.inputs)
        if args.target_triple and triples and args.target_triple not in triples:
            raise RuntimeError("Zone link marker target triple does not match link target")
        if args.mode != "auto" and detected not in (None, args.mode):
            raise RuntimeError("requested Zone link mode conflicts with marker")
        selected = detected if args.mode == "auto" else detected or args.mode
        write_dependency_response(args.output, selected, args.sdk_root,
                                  args.link_arg, args.target_triple)
    except RuntimeError as exc:
        print(f"xollvm-zone-link: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
