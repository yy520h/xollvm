"""真实 max 生效报告、显式覆盖和错误配置拒绝。"""
import json
import subprocess
import pytest
from vm_hardening_support import annotation, transform, tools
from gates import run_gate


def transform_report(tmp_path, spec):
    report = tmp_path / 'report.json'
    ir = transform(tmp_path, 'define i64 @target(i64 %a,i64 %b) { %r = add i64 %a,%b\n ret i64 %r }\n' +
        annotation(['target'], spec), extra=[f'-obf-report-json={report}'])
    fn = next(f for f in json.loads(report.read_text())['functions'] if f['name'] == 'target')
    return fn['vm'], ir


def test_max_effective_and_real_witness(tmp_path):
    vm, ir = transform_report(tmp_path, 'vm(preset=max)')
    for knob in ('whiteboxAES', 'encodedTargets', 'extendedISA', 'operandLayout', 'nestedVMHardened'):
        assert vm['effective'][knob] is True
    assert vm['requested']['bindAntiDebug'] is True
    assert vm['effective']['bindAntiDebug'] is False
    assert vm['disabled_reasons']['bindAntiDebug'] == 'no_detection_source'
    assert vm['wrapper_family'] in ('split', 'arena')
    assert vm['post_link'] == 'pending'
    assert vm['handler_variants'] == 4
    assert vm['requirements']['opcodes']
    assert vm['real_handlers']
    assert vm['caller_requirements']['opcodes']
    assert vm['whitebox_instances'] >= 1
    assert vm['nested_helpers'] >= 1
    assert 'section ".obf.vm.targets"' in ir.read_text()


def test_explicit_disable_overrides_max(tmp_path):
    vm, _ = transform_report(tmp_path, 'vm(preset=max,whiteboxAES=0,encodedTargets=0,nestedVM=0,wrapperFamily=split)')
    assert vm['effective']['whiteboxAES'] is False
    assert vm['effective']['encodedTargets'] is False
    assert vm['effective']['extendedISA'] is True
    assert vm['wrapper_family'] == 'split'
    assert vm['post_link'] == 'not_required'
    assert vm['nested_helpers'] == 0


@pytest.mark.parametrize('spec', ['vm(preset=light)', 'vm(preset=typo)', 'vm(whiteboxAES=garbage)',
    'vm(handlerVariants=notanumber)', 'vm(wrapperFamily=typo)', 'vm(whiteboxAES=1,encBytecode=0)'])
def test_bad_config_rejected(tmp_path, spec):
    src = tmp_path / 'bad.ll'
    src.write_text('target triple = "aarch64-unknown-linux-android26"\ndefine i32 @target(i32 %x) { ret i32 %x }\n' + annotation(['target'], spec))
    p = subprocess.run([str(tools().opt), '-passes=obfuscation', '-disable-output', str(src)], capture_output=True, text=True, timeout=30)
    assert p.returncode != 0
    assert 'vm' in p.stderr.lower() or 'whiteboxAES' in p.stderr


@pytest.mark.parametrize('detector,enabled,reason', [('tracerPid=1', True, None),
    ('integrity=1', False, 'no_detection_source'), ('debuggerProcess=1', False, 'no_detection_source')])
def test_binding_uses_effective_detection_source(tmp_path, detector, enabled, reason):
    vm, ir = transform_report(tmp_path, f'vm(hardened=1,whiteboxAES=1,bindAntiDebug=1), antidebug({detector})')
    assert vm['effective']['bindAntiDebug'] is enabled
    if enabled:
        assert run_gate('vm_bindadeb_ctor_present', obf_ir=ir.read_text()) is None
    else:
        assert run_gate('vm_no_bindadeb_ctor', obf_ir=ir.read_text()) is None
    if reason:
        assert vm['disabled_reasons']['bindAntiDebug'] == reason


def test_real_extended_opcode_in_report(tmp_path):
    report = tmp_path / 'report.json'
    transform(tmp_path, 'define i32 @target(i32 %a) { %r = add i32 %a,7\n ret i32 %r }\n' +
        annotation(['target'], 'vm(extendedISA=1)'), extra=[f'-obf-report-json={report}'])
    vm = next(f['vm'] for f in json.loads(report.read_text())['functions'] if f['name'] == 'target')
    assert 'addi32' in vm['caller_requirements']['opcode_names']
    assert 'addi32' in vm['requirements']['opcode_names']


def test_requested_dependencies_are_not_normalized_away(tmp_path):
    vm, _ = transform_report(tmp_path, 'vm(encBytecode=0,lazyDecrypt=1,hardened=1,constInStream=1,metamorphicEngines=1)')
    for knob in ('lazyDecrypt', 'hardened', 'constInStream', 'metamorphicEngines'):
        assert vm['requested'][knob] is True
        assert vm['effective'][knob] is False
        assert vm['disabled_reasons'][knob]


def test_whitebox_count_has_caller_scope(tmp_path):
    report = tmp_path / 'report.json'
    body = 'define i32 @a(i32 %x) { ret i32 %x }\ndefine i32 @b(i32 %x) { ret i32 %x }\n'
    body += annotation(['a'], 'vm(whiteboxAES=1)')
    # annotation() 使用固定 ann 名；为第二组生成独立全局。
    other = annotation(['b'], 'vm(whiteboxAES=0)').replace('@ann', '@ann2').replace('@llvm.global.annotations', '@unused.annotations')
    body = body.replace('[1 x {ptr,ptr,ptr,i32,ptr}]', '[2 x {ptr,ptr,ptr,i32,ptr}]').replace(
        'ptr @ann,i32 0,ptr null}]', 'ptr @ann,i32 0,ptr null},{ptr,ptr,ptr,i32,ptr} {ptr @b,ptr @ann2,ptr @ann2,i32 0,ptr null}]')
    body += other.split('@unused.annotations')[0]
    transform(tmp_path, body, extra=[f'-obf-report-json={report}'])
    vms = {f['name']: f['vm'] for f in json.loads(report.read_text())['functions'] if f['name'] in ('a', 'b')}
    assert vms['a']['whitebox_instances'] == 1
    assert vms['b']['whitebox_instances'] == 0
    assert vms['b']['module_whitebox_instances'] == 1
