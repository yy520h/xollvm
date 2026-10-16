"""正式验收入口必须拒绝虚假通过，普通 pytest 不访问真实服务。"""
import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).with_name('production_acceptance.py')


def acceptance():
    assert SCRIPT.is_file(), '正式验收入口尚未实现'
    spec = importlib.util.spec_from_file_location('production_acceptance', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_report_rejects_skipped_or_missing_vm():
    m = acceptance()
    for status, phase in [('skipped', 'failed'), ('ran', 'failed'), ('skipped', 'committed')]:
        report = {'functions': [{'name': 'protected', 'passes': [
            {'id': 'vm', 'status': status, 'skip_reason': 'budget_rollback'}],
            'vm': {'phase': phase, 'effective': {'cloudDispatch': True}}}]}
        with pytest.raises(m.AcceptanceError):
            m.require_vm(report, ['protected'], cloud=True)
    with pytest.raises(m.AcceptanceError):
        m.require_vm({'functions': []}, ['protected'], cloud=True)


def test_report_requires_cloud_knob_for_committed_vm():
    m = acceptance()
    report = {'functions': [{'name': 'protected', 'passes': [{'id': 'vm', 'status': 'ran'}],
                            'vm': {'phase': 'committed', 'effective': {'cloudDispatch': False}}}]}
    with pytest.raises(m.AcceptanceError):
        m.require_vm(report, ['protected'], cloud=True)
    report['functions'][0]['vm']['effective']['cloudDispatch'] = True
    m.require_vm(report, ['protected'], cloud=True)


def test_report_accepts_resumed_pipeline_records_but_rejects_any_vm_skip():
    m = acceptance()
    passes = [{'id': 'vm', 'status': 'ran'}, {'id': 'vm', 'status': 'ran'}]
    report = {'functions': [{'name': 'protected', 'passes': passes,
                            'vm': {'phase': 'committed', 'effective': {'cloudDispatch': True}}}]}
    m.require_vm(report, ['protected'], cloud=True)
    passes[1]['status'] = 'skipped'
    with pytest.raises(m.AcceptanceError):
        m.require_vm(report, ['protected'], cloud=True)


def test_real_budget_rollback_report_is_rejected(tmp_path):
    from vm_hardening_support import annotation, transform
    m = acceptance()
    report = tmp_path / 'report.json'
    transform(tmp_path, 'define i32 @protected(i32 %x) { %r = add i32 %x,7\n ret i32 %r }\n' +
              annotation(['protected'], 'vm(cloudDispatch=1,budgetMultiplier=100,budgetMax=10,'
                         'hardened=0,encBytecode=0,lazyDecrypt=0,constInStream=0)'),
              extra=[f'-obf-report-json={report}'])
    data = json.loads(report.read_text())
    fn = next(f for f in data['functions'] if f['name'] == 'protected')
    vm = next(p for p in fn['passes'] if p['id'] == 'vm')
    assert vm['status'] == 'skipped' and vm['skip_reason'] == 'budget_rollback'
    with pytest.raises(m.AcceptanceError, match='VM not run'):
        m.require_vm(data, ['protected'], cloud=True)


def test_online_requires_every_call_and_two_window_boundaries():
    m = acceptance()
    good = '\n'.join(f'call={i} window={100+i//50} value=11299' for i in range(126))
    good += '\nacceptance complete\n'
    m.check_cloud('online', 0, good)
    for damaged in (good.replace('value=11299', 'value=0', 1),
                    good.replace('call=61 ', 'call=60 '),
                    good.replace('window=102', 'window=101'),
                    good.replace('acceptance complete', ''),
                    good.replace('call=0 window=100 value=11299\n', '')):
        with pytest.raises(m.AcceptanceError):
            m.check_cloud('online', 0, damaged)


OFFLINE = ('call=0 window=100 value=11299\n'
           'offline start closed=0 window=100\n'
           'offline expired window=101 offset=1363 refresh=0 denied=40\n')


def test_expiry_requires_reached_vm_and_signal_not_just_a_crash():
    m = acceptance()
    output = OFFLINE + 'calling expired VM; abnormal termination expected\n'
    with pytest.raises(m.AcceptanceError, match='fault evidence'):
        m.check_cloud('offline-expiry', -signal.SIGTRAP, output)
    for code, damaged in [(9, output), (-signal.SIGKILL, output),
                          (-signal.SIGTRAP, 'crashed before login'),
                          (-signal.SIGTRAP, output + 'call=1 window=101 value=11299\n'),
                          (-signal.SIGTRAP, output.replace('offset=1363', 'offset=0')),
                          (-signal.SIGTRAP, output.replace('denied=40', 'denied=0')),
                          (-signal.SIGTRAP, output.replace('window=101', 'window=100'))]:
        with pytest.raises(m.AcceptanceError):
            m.check_cloud('offline-expiry', code, damaged)


def test_expiry_rejects_unrelated_crash_after_reaching_expired_call():
    m = acceptance()
    output = OFFLINE + 'calling expired VM; abnormal termination expected\n'
    # 即使前置云证据完整，raise/abort/空指针等无现场的崩溃也不能通过。
    for sig in (signal.SIGTRAP, signal.SIGILL, signal.SIGSEGV, signal.SIGABRT):
        with pytest.raises(m.AcceptanceError, match='fault evidence'):
            m.check_cloud('offline-expiry', -sig, output)


def test_expiry_rejects_fault_from_different_offset_or_signal():
    m = acceptance()
    output = OFFLINE + 'calling expired VM; abnormal termination expected\n'
    evidence = {'offset': 1363, 'signal': int(signal.SIGTRAP)}
    result = m.check_cloud('offline-expiry', -signal.SIGTRAP, output, fault=evidence)
    assert result['fault'] == evidence
    for damaged in ({'offset': 42, 'signal': int(signal.SIGTRAP)},
                    {'offset': 1363, 'signal': int(signal.SIGSEGV)}):
        with pytest.raises(m.AcceptanceError, match='disagrees'):
            m.check_cloud('offline-expiry', -signal.SIGTRAP, output, fault=damaged)


def test_fault_replay_requires_cloud_offset_to_cause_descriptor_oob():
    m = acceptance()
    # 手工构造的 AArch64 分发边界检查；真实运行另验最终 ELF。
    instructions = {
        0x100: 'add\tw8, w26, w0', 0x104: 'ldr\tw9, [x28, #0xc]',
        0x108: 'ldr w10, [x28, #0x10]', 0x10c: 'cmp w9, #0x1',
        0x110: 'b.ne 0x128', 0x114: 'cmp w8, w10',
        0x118: 'b.hs 0x128', 0x11c: 'mov w8, w8',
        0x120: 'lsl x8, x8, #5', 0x124: 'ret', 0x128: 'brk #0x1',
    }
    regs = [0] * 31
    regs[0], regs[26], regs[28] = 1363, 7, 0x1000
    memory = {0x100c: 1, 0x1010: 100}
    def read(address, size):
        assert size == 4
        return memory[address]
    result = m.replay_dispatch(instructions, 0x100, 0x128, regs, read, 1363)
    assert result['baseSlot'] == 7 and result['expiredSlot'] == 1370
    assert result['count'] == 100 and result['descriptor'] == 0x1000
    for damage in ('zero-still-oob', 'pending', 'wrong-trap', 'no-offset-use', 'unknown-op'):
        broken = dict(instructions)
        memory[0x100c] = 0 if damage == 'pending' else 1
        regs[26] = 101 if damage == 'zero-still-oob' else 7
        if damage == 'no-offset-use':
            broken[0x100] = 'mov w8, #1370'
        if damage == 'unknown-op':
            broken[0x100] = 'mystery w8, w26, w0'
        with pytest.raises(m.AcceptanceError):
            m.replay_dispatch(broken, 0x100, 0x124 if damage == 'wrong-trap' else 0x128,
                              regs, read, 1363)


def test_fault_replay_rejects_register_context_mismatch():
    m = acceptance()
    instructions = {
        0x100: 'add w8, w26, w0', 0x104: 'ldr w9, [x28, #0xc]',
        0x108: 'ldr w10, [x28, #0x10]', 0x10c: 'cmp w8, w10',
        0x110: 'b.hs 0x11c', 0x114: 'mov w8, w8',
        0x118: 'lsl x8, x8, #5', 0x11c: 'brk #0x1',
    }
    regs = [0] * 31
    regs[0], regs[26], regs[28] = 1363, 7, 0x1000
    context = list(regs)
    context[8], context[9], context[10] = 1370, 1, 100
    read = lambda address, size: {0x100c: 1, 0x1010: 100}[address]
    m.replay_dispatch(instructions, 0x100, 0x11c, regs, read, 1363, fault_registers=context)
    context[8] = 7
    with pytest.raises(m.AcceptanceError, match='kernel fault context'):
        m.replay_dispatch(instructions, 0x100, 0x11c, regs, read, 1363, fault_registers=context)


def test_recovery_requires_fresh_offset_and_correct_protected_result():
    m = acceptance()
    output = (OFFLINE + 'call=1 window=101 value=11299\n'
              'network restored offset=0\nacceptance complete\n')
    m.check_cloud('recovery', 0, output)
    for damaged in (output.replace('restored offset=0', 'restored offset=17'),
                    output.replace('call=1 window=101 value=11299', 'call=1 window=101 value=0'),
                    output.replace('refresh=0', 'refresh=1')):
        with pytest.raises(m.AcceptanceError):
            m.check_cloud('recovery', 0, damaged)


def test_child_output_and_timeout_report_are_redacted(tmp_path):
    m = acceptance()
    card = 'acceptance-secret-card'
    run = m.Runner(tmp_path, secrets=[card])
    row = run.run('output', [sys.executable, '-c',
                           'import os; print(os.environ["XOLLVM_ZONE_CARD"])'],
                  env={'XOLLVM_ZONE_CARD': card})
    assert row['status'] == 'OK'
    assert card not in json.dumps(row)
    assert card not in (tmp_path / 'output.log').read_text()
    timed = run.run('timeout', [sys.executable, '-u', '-c',
                               'import time; print("started"); time.sleep(10)'], timeout=0.2)
    assert timed['status'] == 'TIMEOUT'
    assert 'started' in (tmp_path / 'timeout.log').read_text()


def test_cloud_without_card_fails_with_structured_report(tmp_path, monkeypatch):
    acceptance()
    monkeypatch.delenv('XOLLVM_ZONE_CARD', raising=False)
    out = tmp_path / 'run'
    p = subprocess.run([sys.executable, str(SCRIPT), 'cloud', '--output', str(out)],
                       capture_output=True, text=True, timeout=10)
    assert p.returncode != 0
    report = json.loads((out / 'report.json').read_text())
    assert report['status'] == 'FAIL'
    assert 'XOLLVM_ZONE_CARD' in report['error']
    assert report['steps'] == []
