"""Attack module registry + shared result type.

Each attack module (mba_smt, cfg_recovery, string_extract) exposes a single
`run(case, tools, work, seed, *, verbose=False, progress=None) -> AttackResult`
function and is registered here under the name used by `--attacks`/
BenchCase.attack.

`progress`, when given, is a `Callable[[str], None]` the attack calls at
each major phase boundary (compile, lift, solve, ...) so a caller running in
--nerd mode can print live checkpoints instead of a single result at the end
of a potentially multi-minute angr/Z3 call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import signal
import subprocess
import time
from typing import Callable, Dict, Optional


@dataclass
class AttackResult:
    """Outcome of running one attack against one (case, seed).

    status:
      PASS  — attack engine ran to completion and produced `resilience`.
              A low/zero resilience is a valid, useful result (obfuscation
              was broken) — it is NOT a bench failure.
      SKIP  — required tool unavailable (e.g. z3-solver/angr not importable).
      FAIL  — bench infra error (compile crash, engine exception, timeout).
    resilience: 0.0 (fully broken) .. 1.0 (fully held). None unless PASS.
    tool: the concrete deobfuscation tool driving the attack (e.g. "z3",
      "angr+capstone") — what the user would install/name if reproducing it.
    technique: one-line description of the attack technique used, so the
      report reads as "X was attacked with Y via Z" rather than just a score.
    extra: nerd-mode diagnostics (solver stats, raw block/edge counts, hex
      dumps, ...) — only shown with --nerd, kept out of the default table.
    """
    case: str
    attack: str
    seed: int
    status: str            # "PASS" | "SKIP" | "FAIL"
    resilience: Optional[float]
    detail: str
    tool: str
    technique: str
    elapsed: float = 0.0
    extra: Dict[str, str] = field(default_factory=dict)


AttackFn = Callable[..., AttackResult]

_REGISTRY: Dict[str, AttackFn] = {}

ELF_STATUSES = {'RECOVERED', 'NOT_RECOVERED_WITHIN_BUDGET', 'TIMEOUT', 'UNSUPPORTED', 'TOOL_ERROR'}


def run_attack_process(case, attack, seed, argv, *, timeout, tool, technique, cwd=None, env=None):
    """超时会终止并回收攻击子进程，错误不产生安全分数。"""
    start = time.monotonic()
    status, detail, extra = 'TOOL_ERROR', '', {}
    try:
        with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, cwd=cwd, env=env, start_new_session=True) as p:
            try:
                stdout, stderr = p.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                # objdump 等后代也必须停止，不能只杀最外层 Python。
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                p.communicate()
                raise
        if p.returncode:
            detail = f'attack exit={p.returncode}: {stderr[-2000:]}'
        else:
            data = json.loads(stdout)
            status = data['status']
            if status not in ELF_STATUSES:
                raise ValueError(f'unknown status {status}')
            detail, extra = data.get('detail', ''), data.get('extra', {})
    except subprocess.TimeoutExpired:
        status, detail = 'TIMEOUT', f'attack exceeded {timeout}s; subprocess terminated'
    except (OSError, ValueError, KeyError, TypeError) as e:
        status, detail = 'TOOL_ERROR', str(e)
    resilience = 0.0 if status == 'RECOVERED' else None
    return AttackResult(case, attack, seed, status, resilience, detail, tool, technique,
                        time.monotonic() - start, extra)


def register(name: str) -> Callable[[AttackFn], AttackFn]:
    def deco(fn: AttackFn) -> AttackFn:
        _REGISTRY[name] = fn
        return fn
    return deco


def get(name: str) -> AttackFn:
    return _REGISTRY[name]


def names() -> list[str]:
    return sorted(_REGISTRY)


def load_all() -> None:
    """Import every attack module so its @register(...) runs.

    Import errors inside an attack module (e.g. `import angr` failing) must
    NOT prevent other attacks from registering — each module guards its own
    optional dependency and reports SKIP at run() time instead.
    """
    from . import mba_smt   # noqa: F401
    from . import simba  # noqa: F401
    from . import cfg_recovery  # noqa: F401
    from . import string_extract  # noqa: F401
    from . import opt_survival  # noqa: F401
    from . import decompile_quality  # noqa: F401
    from . import call_target_recovery  # noqa: F401
    from . import vm_bytecode  # noqa: F401
    from . import opaque_predicate  # noqa: F401
    from . import latopq_opaque  # noqa: F401
    from . import dse_coverage  # noqa: F401
    from . import handler_sig  # noqa: F401
