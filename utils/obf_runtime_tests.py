#!/usr/bin/env python3
"""Thin entrypoint for the LLVM obfuscator runtime test suite.

The implementation lives under the runner/ package (framework helpers) and
cases/ package (test catalog). This shim only resolves the sibling packages
and dispatches to runner.cli.main().
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runner.cli import main  # noqa: E402

if __name__ == "__main__":
    if "--case" in sys.argv:
        from cases.vm_returns import main as return_main
        raise SystemExit(return_main())
    raise SystemExit(main())
