"""Multiple-return differential test using the newly linked VM unit-test driver."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess


HARNESS = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern bool ret_i1(bool, int32_t);
extern int32_t ret_i32(bool, int32_t);
extern uint64_t ret_i64(bool, uint64_t);
extern void *ret_ptr(bool, void *, void *);
extern float ret_float(bool, float);
extern double ret_double(bool, double);
extern void ret_void(bool, int32_t *);
int main(void) {
    const int32_t xs[] = {-100, -3, -1, 0, 7, 42, 100000};
    int p[2] = {17, 29};
    for (int c = 0; c != 2; ++c) {
        for (unsigned i = 0; i != sizeof(xs) / sizeof(xs[0]); ++i) {
            int32_t x = xs[i], out = 0;
            uint64_t wide = ((uint64_t)(uint32_t)x << 32) | (uint32_t)(x + 113);
            float f = ret_float(c, (float)x / 8.0f);
            double d = ret_double(c, (double)x / 8.0);
            uint32_t fb;
            uint64_t db;
            memcpy(&fb, &f, sizeof(fb));
            memcpy(&db, &d, sizeof(db));
            void *pv = ret_ptr(c, &p[0], &p[1]);
            int pi = pv == &p[0] ? 0 : pv == &p[1] ? 1 : -1;
            ret_void(c, &out);
            printf("%d %d %u %08x %016llx %d %08x %016llx %d\n",
                   c, x, (unsigned)ret_i1(c, x), (uint32_t)ret_i32(c, x),
                   (unsigned long long)ret_i64(c, wide), pi, fb,
                   (unsigned long long)db, out);
        }
    }
    return 0;
}
"""


def main() -> int:
    # 默认工具目录同时支持普通 checkout 与 .worktrees 下的隔离 checkout。
    repo = Path(__file__).resolve().parents[2]
    root = repo.parents[2] if repo.parent.name == ".worktrees" else repo.parent
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--case", choices=["vm-multiple-returns"], required=True)
    ap.add_argument("--build-dir", type=Path, default=root / "build-sensitive")
    ap.add_argument("--clang", type=Path, default=root / "build" / "bin" / "clang")
    ap.add_argument("--host-clang", type=Path, default=shutil.which("clang"))
    ap.add_argument("--work", type=Path,
                    default=root / "build-sensitive" / "task-2-runtime")
    args = ap.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    work = args.work.resolve()
    driver = args.build_dir.resolve() / "tools/Obfuscator/VMRequirementsTests"

    def run(cmd: list[str], *, source: str | None = None, env=None) -> str:
        print("+ " + shlex.join(map(str, cmd)), flush=True)
        p = subprocess.run(cmd, input=source, text=True, capture_output=True,
                           timeout=20, env=env)
        if p.returncode:
            raise RuntimeError(f"exit {p.returncode}\n{p.stdout}\n{p.stderr}")
        return p.stdout

    try:
        output = run([str(driver), "--gtest_filter=VMReturnABI.MultipleReturnRuntimeModule"],
                     env={**os.environ, "OBF_VM_RETURN_IR_DIR": str(work)})
        print(output, end="")
        if "[  PASSED  ] 1 test." not in output:
            raise RuntimeError("IR driver did not execute the required test")
        kinds = {"i1": 1, "i32": 1, "i64": 2, "ptr": 3,
                 "float": 4, "double": 4, "void": 0}
        for mode in range(4):
            ir = (work / f"mode-{mode}.ll").read_text()
            engines = re.findall(r"^define internal void @__vm_engine\(", ir, re.M)
            if len(engines) != 1:
                raise RuntimeError(f"mode {mode}: expected one shared engine")
            for kind, abi in kinds.items():
                body = re.search(rf"^define [^\n]*@ret_{kind}\([^\n]*\).*?^}}",
                                 ir, re.M | re.S)
                if not body or not re.search(
                        rf"call void %[^\n]*ptr %vm\.ret\.storage, i32 {abi}[,)]",
                        body[0]):
                    raise RuntimeError(f"mode {mode}: ret_{kind} missing committed VM call/ABI")
            print(f"mode {mode}: 7 committed wrappers, one shared engine, ABI kinds verified")
        for opt in ("-O0", "-O2"):
            expected = None
            for name in ("reference", "mode-0", "mode-1", "mode-2", "mode-3"):
                exe = work / f"{name}{opt}"
                obj = exe.with_suffix(".o")
                run([str(args.clang.resolve()), opt, "-Wno-override-module",
                     "-fPIC", "-c", str(work / f"{name}.ll"), "-o", str(obj)])
                run([str(args.host_clang.resolve()), opt, "-x", "c", "-",
                     "-x", "none", str(obj), "-lm", "-o", str(exe)], source=HARNESS)
                actual = run([str(exe)])
                if len(actual.splitlines()) != 14:
                    raise RuntimeError(f"{name}{opt}: expected 14 branch/input rows")
                if expected is None:
                    expected = actual
                    (work / f"reference{opt}.txt").write_text(actual)
                elif actual != expected:
                    raise RuntimeError(f"{name}{opt}: differential mismatch\n"
                                       f"expected:\n{expected}actual:\n{actual}")
                else:
                    print(f"PASS {name}{opt}: 6 value kinds + void, both branches, 7 inputs")
        print("PASS vm-multiple-returns: 8 native comparisons, 672 value results + 112 void effects")
        return 0
    except (RuntimeError, subprocess.TimeoutExpired) as e:
        print(f"FAIL vm-multiple-returns: {e}")
        return 1
