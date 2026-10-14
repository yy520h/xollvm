"""验证后置变换和预算作用于最终 VM wrapper，而非即将丢弃的原函数体。"""
import re
import os
import json
import subprocess
from pathlib import Path

import pytest


def obfuscate(tmp_path, spec, extra=()):
    repo = Path(__file__).resolve().parents[1]
    root = repo.parents[2] if repo.parent.name == '.worktrees' else repo.parent
    opt = Path(os.environ.get('XOLLVM_LIFECYCLE_OPT', root / 'build-sensitive/bin/opt'))
    if not opt.exists():
        pytest.skip('native opt unavailable')
    ann = ('obf: ' + spec).encode() + b'\0'
    encoded = ''.join(f'\\{b:02X}' for b in ann)
    source = tmp_path / 'input.ll'
    source.write_text(
        'target triple = "aarch64-unknown-linux-android26"\n'
        'define i32 @target(i32 %x) { %r = add i32 %x, 7\n ret i32 %r }\n'
        f'@ann = private constant [{len(ann)} x i8] c"{encoded}"\n'
        '@llvm.global.annotations = appending global [1 x {ptr,ptr,ptr,i32,ptr}] '
        '[{ptr,ptr,ptr,i32,ptr} {ptr @target,ptr @ann,ptr @ann,i32 0,ptr null}]\n')
    result = subprocess.run([str(opt), '-passes=obfuscation', '-obf-seed=42',
                             '-obf-pipeline-ordering=vm,split',
                             '-obf-verify', *extra, '-S', str(source), '-o', '-'],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    body = re.search(r'define [^\n]*i32 @target\([^\n]*\).*?\n}', result.stdout, re.S)
    assert body, result.stdout[:1000]
    return body.group(), result


VM = 'vm(hardened=0,encBytecode=0,lazyDecrypt=0,constInStream=0,handlerVariants=1)'


def test_post_vm_split_survives_commit(tmp_path):
    body, _ = obfuscate(tmp_path, 'vm(hardened=1,encBytecode=1,lazyDecrypt=0,constInStream=0,antiDebug=0,budgetMultiplier=10000), split(num=3)')
    assert re.search(r'^[-\w.]+\.split[^\n]*:', body, re.M), 'split transformed the discarded original body'


def test_encrypted_vm_modules_link_without_duplicate_crypto_helpers(tmp_path):
    ndk = Path('/data/user/0/com.termux/files/home/android-ndk-r30-ollvm-r23-beta3'
               '/toolchains/llvm/prebuilt/linux-arm64')
    clang = ndk / 'bin/clang'
    if not clang.exists():
        pytest.skip('NDK clang unavailable')
    _, result = obfuscate(tmp_path, 'vm(encBytecode=1,lazyDecrypt=1,constInStream=1,hardened=1)')
    objects = []
    for index in range(2):
        ir = tmp_path / f'module{index}.ll'
        lowered = '\n'.join(line for line in result.stdout.splitlines()
                            if not line.startswith('@llvm.global.annotations'))
        ir.write_text(lowered.replace('@target', f'@target_{index}') + '\n')
        obj = tmp_path / f'module{index}.o'
        proc = subprocess.run([str(clang), '--target=aarch64-linux-android26',
                               '-O0', '-c', str(ir), '-o', str(obj)],
                              capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, proc.stderr
        objects.append(str(obj))
    linked = subprocess.run([str(clang), '--target=aarch64-linux-android26',
                             '-nostdlib', '-r', *objects, '-o', str(tmp_path / 'linked.o')],
                            capture_output=True, text=True, timeout=60)
    assert linked.returncode == 0, linked.stderr


def test_vm_wrapper_honors_hard_budget(tmp_path):
    body, _ = obfuscate(tmp_path, VM[:-1] + ',budgetMultiplier=100,budgetMax=10)')
    assert '!obf.vm.caller' not in body, 'oversized wrapper escaped budget rollback'
    assert 'add i32 %x, 7' in body


@pytest.mark.parametrize('rollback', [False, True])
def test_report_records_final_vm_outcome(tmp_path, rollback):
    report = tmp_path / 'report.json'
    spec = VM[:-1] + (',budgetMultiplier=100,budgetMax=10)' if rollback else ')')
    body, _ = obfuscate(tmp_path, spec, [f'-obf-report-json={report}'])
    functions = [f for f in json.loads(report.read_text())['functions'] if f['name'] == 'target']
    assert len(functions) == 1
    vm = next(p for p in functions[0]['passes'] if p['id'] == 'vm')
    assert vm['status'] == ('skipped' if rollback else 'ran')
    if rollback:
        assert vm['skip_reason'] == 'budget_rollback'
        assert vm['insts_after'] == vm['insts_before']
    else:
        assert vm['insts_after'] > vm['insts_before']
