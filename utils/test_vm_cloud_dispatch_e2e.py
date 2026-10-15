"""Demo 端到端集成：受保护函数消费云值 dispatch。

锁定：
- demo 的 VM 注解启用 cloudDispatch（云值缺省/过期时 dispatch 越界自然崩溃）。
- demo 源码里没有任何本地授权布尔分支（零校验）。
"""

from pathlib import Path
import json
import re
import signal
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parents[2] if ROOT.parent.name == ".worktrees" else ROOT.parent
DEMO = PROJECT / "demo/jni/main.cpp"


def _demo_src():
    return DEMO.read_text()


def test_demo_vm_function_requests_cloud_dispatch():
    src = _demo_src()
    assert "cloudDispatch=1" in src, "demo 的 VM 注解未启用 cloudDispatch=1"


def test_demo_has_no_local_auth_branch():
    src = _demo_src()
    for token in ["verifySignature", "windowExpired", "dispatchValid"]:
        assert token not in src, f"demo 出现本地校验分支: {token}"


@pytest.mark.parametrize('backend_opt', ['-O0', '-O2'])
def test_demo_cloud_vm_survives_production_budget_and_expires(tmp_path, backend_opt):
    """生产预算不能让云保护退化为普通算术；失效 offset 必须拒绝执行。"""
    from vm_hardening_support import tools, checked, build_native
    t = tools()
    function = re.search(r'OBF_FN\("vm\(preset=max[^\n]+\n'
                         r'int demo_protected_operation\(int value\) \{.*?\n\}',
                         _demo_src(), re.S)
    assert function
    source, ir, report = (tmp_path / name for name in ('demo.cpp', 'demo.ll', 'report.json'))
    source.write_text('#include "obf_annotations.h"\n' + function.group() + '\n')
    checked([t.opt.with_name('clang'), '--target=aarch64-linux-android26',
             f'--sysroot={t.sysroot}', f'-I{DEMO.parent}', '-O2', '-emit-llvm', '-S', source,
             '-mllvm', '-enable-obfuscation', '-mllvm', '-obf-seed=20260930',
             '-mllvm', '-obf-verify', '-mllvm', '-obf-max-function-insts=500',
             '-mllvm', '-obf-max-function-blocks=80',
             '-mllvm', '-obf-ir-budget-multiplier=12',
             '-mllvm', '-obf-ir-budget-max=12000', '-mllvm', '-obf-shield-auto',
             '-mllvm', f'-obf-report-json={report}', '-o', ir])
    fn = next(f for f in json.loads(report.read_text())['functions']
              if f['name'] == '_Z24demo_protected_operationi')
    vm = next(p for p in fn['passes'] if p['id'] == 'vm')
    assert vm['status'] == 'ran', vm
    assert fn['vm']['phase'] == 'committed'
    assert fn['vm']['effective']['cloudDispatch'] is True
    assert '@__zone_get_dispatch_offset' in ir.read_text()
    exe = build_native(tmp_path, ir, '''#include <cstdint>
static uint64_t offset;
extern "C" uint64_t __zone_get_dispatch_offset() { return offset; }
int demo_protected_operation(int);
int main(int argc, char**) {
    offset = argc > 1 ? 4095 : 0;
    return demo_protected_operation(703) == 11299 ? 0 : 1;
}
''', finalize_targets=True, backend_opt=backend_opt)
    valid = subprocess.run([str(exe)], capture_output=True, text=True, timeout=30)
    assert valid.returncode == 0, valid.stderr
    expired = subprocess.run([str(exe), 'expired'], capture_output=True, text=True, timeout=30)
    assert expired.returncode in (-signal.SIGSEGV, -signal.SIGTRAP,
                                  -signal.SIGILL, -signal.SIGABRT), expired
