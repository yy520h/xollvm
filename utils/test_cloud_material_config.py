"""配置、严格失败及分阶段发射边界；不把旧静态 VM 当作材料实现。"""
import json
import os
from pathlib import Path
import subprocess

import pytest
from vm_hardening_support import annotation


SIMPLE = 'define i32 @f(i32 %x) { %r = add i32 %x, 7\n ret i32 %r }\n'
MODE = 'cloudMaterial=lease,materialRegion=auth'
STAGED = 'cloud material emission not implemented'


def request(tmp_path, spec, *, body=SIMPLE, triple='aarch64-linux-android26',
            extra=(), export=True, functions=('f',)):
    opt = Path(os.environ['XOLLVM_OPT'])
    assert opt.is_file()
    source, output = tmp_path / 'request.ll', tmp_path / 'output.ll'
    source.write_text(f'target triple = "{triple}"\n' + body + annotation(functions, spec))
    args = [str(opt), '-passes=obfuscation', '-obf-seed=42']
    if export:
        directory = tmp_path / 'private'
        directory.mkdir(exist_ok=True)
        args.append(f'-obf-material-export-dir={directory}')
    p = subprocess.run([*args, *extra, '-S', str(source), '-o', str(output)],
                       capture_output=True, text=True, timeout=45)
    return p, output


@pytest.mark.parametrize('options,diagnostic', [
    ('cloudMaterial=lease', 'materialRegion'),
    (MODE + ',cloudDispatch=1', 'cloudDispatch'),
    ('cloudMaterial=operation,materialRegion=pay', 'operation material not implemented'),
    ('cloudMaterial=typo,materialRegion=auth', 'cloudMaterial'),
    (MODE + ',preset=max', 'preset=max'),
    (MODE + ',preset=max,whiteboxAES=0,nestedVM=0', 'preset=max'),
    *[(MODE + ',' + knob + '=1', knob) for knob in
      ('whiteboxAES', 'lazyDecrypt', 'encDispatch', 'keyedDispatch',
       'encBytecode', 'strongBytecode', 'nestedVM', 'nestedVMHardened', 'nativeJIT', 'bindAntiDebug')],
    (MODE + ',constInStream=0', 'constInStream'),
    (MODE + ',materialExportDir=/private', 'obf-material-export-dir'),
    ('cloudMaterial=lease,materialRegion=bad@name', 'materialRegion'),
    ('cloudMaterial=lease,materialRegion=naïve', 'materialRegion'),
    (MODE + ',minBlocks=0', 'minBlocks'),
    (MODE + ',minBlocks=4,maxBlocks=2', 'maxBlocks'),
    (MODE + ',nativeJit=1', 'unknown cloudMaterial option'),
])
def test_rejects_invalid_request_before_emission(tmp_path, options, diagnostic):
    # 不传新 CLI，以便旧二进制的 RED 是配置漏检而非未知选项。
    p, _ = request(tmp_path, f'vm({options})', export=False)
    assert p.returncode != 0
    assert diagnostic in p.stderr
    assert STAGED not in p.stderr


@pytest.mark.parametrize('triple', ['armv7-linux-androideabi26', 'x86_64-linux-gnu',
                                    'aarch64-linux-gnu'])
def test_target_rejected_before_emission(tmp_path, triple):
    p, _ = request(tmp_path, f'vm({MODE})', triple=triple, export=False)
    assert p.returncode != 0
    assert 'requires Android AArch64 little-endian' in p.stderr


@pytest.mark.parametrize('body,options,extra,diagnostic', [
    (SIMPLE, ',minBlocks=2', (), 'too few blocks'),
    ('define void @f() { fence seq_cst\n ret void }\n', '', (), 'unsupported'),
    (SIMPLE, '', ('-obf-max-function-insts=1',), 'cap_max_function_insts'),
    ('define i32 @f(i32 %x) { br label %b\nb: ret i32 %x }\n', '',
     ('-obf-max-function-blocks=1',), 'cap_max_function_blocks'),
    (SIMPLE, '', ('-obf-ir-budget-max=1',), 'budget exhausted'),
])
def test_strict_failure_without_sensitive(tmp_path, body, options, extra, diagnostic):
    p, _ = request(tmp_path, f'vm({MODE}{options})', body=body, extra=extra, export=False)
    assert p.returncode != 0
    assert diagnostic in p.stderr
    assert STAGED not in p.stderr


def test_budget_rollback_is_fatal_before_vm(tmp_path):
    body = ('define i32 @f(i32 %x) { %c = icmp eq i32 %x, 1\n'
            'br i1 %c, label %a, label %b\na: ret i32 1\nb: ret i32 0 }\n')
    p, _ = request(tmp_path, f'flattening(minBlocks=2,fakeCases=4), vm({MODE})', body=body,
                   extra=('-obf-pipeline-ordering=flattening,vm', '-obf-ir-budget-max=8'), export=False)
    assert p.returncode != 0
    assert 'budget rollback' in p.stderr
    assert STAGED not in p.stderr


@pytest.mark.parametrize('kind', ['missing', 'not_directory', 'unwritable', 'unsearchable'])
def test_export_preflight_failure(tmp_path, kind):
    extra = []
    target = tmp_path / 'unused'
    if kind == 'not_directory':
        target = tmp_path / 'file'
        target.write_text('fixture')
        extra = [f'-obf-material-export-dir={target}']
    elif kind in ('unwritable', 'unsearchable'):
        target = tmp_path / 'locked'
        target.mkdir(mode=0o500 if kind == 'unwritable' else 0o600)
        extra = [f'-obf-material-export-dir={target}']
    try:
        p, _ = request(tmp_path, f'vm({MODE})', export=False, extra=extra,
                       triple='aarch64-unknown-linux-android26')
        assert p.returncode != 0
        assert 'material export' in p.stderr
        assert STAGED not in p.stderr
    finally:
        if kind in ('unwritable', 'unsearchable'):
            target.chmod(0o700)


@pytest.mark.parametrize('mode', ['session', 'lease'])
@pytest.mark.parametrize('knobs', ['', ',hardened=1,encBytecode=0', ',preset=high'])
def test_valid_preflight_reports_truth_and_never_emits_fallback(tmp_path, mode, knobs):
    report = tmp_path / 'report.json'
    p, output = request(tmp_path, f'vm(cloudMaterial={mode},materialRegion=Auth_1{knobs})',
                        extra=[f'-obf-report-json={report}'])
    assert p.returncode != 0
    assert STAGED in p.stderr
    assert not output.exists() or not output.read_text().strip()
    vm = next(f['vm'] for f in json.loads(report.read_text())['functions'] if f['name'] == 'f')
    assert vm['phase'] == 'preflight_only'
    assert vm['bytecodeSource'] == 'cloud_material'
    assert vm['material_dependency_emitted'] is False
    assert vm['native_fallback_removed'] is False
    assert vm['effective']['cloudMaterial'] == mode
    assert vm['effective']['materialRegion'] == 'Auth_1'
    assert vm['effective']['constInStream'] is True
    assert vm['requested']['constInStream'] is False
    assert vm['effective']['hardened'] is bool(knobs)
    if knobs:
        assert vm['effective']['regEncrypt'] is True
    for key in ('encBytecode', 'strongBytecode', 'encDispatch', 'keyedDispatch',
                'whiteboxAES', 'lazyDecrypt'):
        assert vm['effective'][key] is False
        assert vm['disabled_reasons'][key] == 'replaced_by_cloud_material'
    assert vm['whitebox_instances'] == 0
    assert vm['real_handlers'] == []
    assert vm['caller_requirements']['opcodes']
    assert list((tmp_path / 'private').iterdir()) == []


def test_fmerge_cannot_drop_material_requests(tmp_path):
    body = SIMPLE.replace('define ', 'define internal ') + 'define internal i32 @g(i32 %x) { ret i32 %x }\n'
    # 两个函数均为 eligible fmerge 成员，旧行为会剪掉原注解。
    p, _ = request(tmp_path, f'fmerge(group=both), vm({MODE})', body=body, export=False,
                   functions=('f', 'g'), triple='aarch64-unknown-linux-android26')
    assert p.returncode != 0
    assert 'fmerge not supported with cloudMaterial' in p.stderr
    assert STAGED not in p.stderr


def test_nonlocal_exit_is_rejected_before_staging(tmp_path):
    body = ('declare void @longjmp(ptr, i32) noreturn\n'
            'define void @f(ptr %p) { call void @longjmp(ptr %p, i32 1)\n unreachable }\n')
    p, _ = request(tmp_path, f'vm({MODE})', body=body, triple='aarch64-unknown-linux-android26')
    assert p.returncode != 0
    assert 'non-local exit' in p.stderr
    assert STAGED not in p.stderr


def test_canonical_android_triple_and_explicit_disables(tmp_path):
    p, _ = request(tmp_path, f'vm({MODE},whiteboxAES=0,lazyDecrypt=0,encDispatch=0,'
                   'keyedDispatch=0,nestedVM=0,nativeJIT=0)',
                   triple='aarch64-unknown-linux-android26')
    assert p.returncode != 0
    assert STAGED in p.stderr


def test_preflight_report_write_failure_is_not_success(tmp_path):
    p, _ = request(tmp_path, f'vm({MODE})', extra=['-obf-report-json=/dev/full'])
    assert p.returncode != 0
    assert 'material preflight report failed' in p.stderr
    assert STAGED not in p.stderr


def test_preflight_report_does_not_label_vm_as_ran(tmp_path):
    report = tmp_path / 'report.json'
    p, _ = request(tmp_path, f'vm({MODE})', extra=[f'-obf-report-json={report}'])
    assert STAGED in p.stderr
    fn = next(f for f in json.loads(report.read_text())['functions'] if f['name'] == 'f')
    vm_pass = next(p for p in fn['passes'] if p['id'] == 'vm')
    assert vm_pass['status'] == 'skipped'
    assert vm_pass['skip_reason'] == 'cloud_material_emission_not_implemented'
    assert vm_pass['insts_after'] == vm_pass['insts_before'] == 2


@pytest.mark.parametrize('body,options,diagnostic', [
    ('declare i32 @callee(i32)\ndefine i32 @f(i32 %x) { '
     '%r = musttail call i32 @callee(i32 %x)\n ret i32 %r }\n', '', 'musttail'),
    ('declare i32 @callee(i32)\ndeclare i32 @__gxx_personality_v0(...)\n'
     'define i32 @f(i32 %x) personality ptr @__gxx_personality_v0 { '
     '%r = invoke i32 @callee(i32 %x) to label %ok unwind label %lp\n'
     'ok: ret i32 %r\nlp: %e = landingpad {ptr,i32} cleanup\n ret i32 0 }\n', '', 'EH/invoke'),
    ('define i32 @f(i32 %x) { br label %b\nb: ret i32 %x }\n', ',maxBlocks=1', 'too many blocks'),
])
def test_ir_boundaries_precede_staging(tmp_path, body, options, diagnostic):
    p, _ = request(tmp_path, f'vm({MODE}{options})', body=body)
    assert p.returncode != 0
    assert diagnostic in p.stderr
    assert STAGED not in p.stderr


def test_off_keeps_legacy_transform(tmp_path):
    report = tmp_path / 'report.json'
    p, output = request(tmp_path, 'vm(cloudMaterial=off)', export=False,
                        extra=[f'-obf-report-json={report}'])
    assert p.returncode == 0, p.stderr
    assert '__vm_engine' in output.read_text()
    vm = next(f['vm'] for f in json.loads(report.read_text())['functions'] if f['name'] == 'f')
    assert vm['effective']['cloudMaterial'] == 'off'
    assert vm['effective']['encBytecode'] is True
    assert vm['bytecodeSource'] == 'legacy'


@pytest.mark.parametrize('region', ['1auth', 'auth/payment', 'auth:payment',
                                    '9A._:/-z', 'a', 'a' * 128])
def test_protocol_name_valid_reaches_staging(tmp_path, region):
    report = tmp_path / 'report.json'
    p, _ = request(tmp_path, f'vm(cloudMaterial=lease,materialRegion={region})',
                   extra=[f'-obf-report-json={report}'])
    assert p.returncode != 0
    assert STAGED in p.stderr
    vm = next(f['vm'] for f in json.loads(report.read_text())['functions'] if f['name'] == 'f')
    assert vm['effective']['materialRegion'] == region


@pytest.mark.parametrize('region', ['_auth', '/auth', ':auth', '-auth', '.auth',
                                    'a' * 129, 'naïve', '""', '"auth payment"'])
def test_protocol_name_invalid_fails_before_staging(tmp_path, region):
    p, _ = request(tmp_path, f'vm(cloudMaterial=lease,materialRegion={region})')
    assert p.returncode != 0
    assert 'materialRegion' in p.stderr
    assert STAGED not in p.stderr


@pytest.mark.parametrize('key', ['budget', 'budgetMax', 'budgetMultiplier'])
@pytest.mark.parametrize('value', ['oops', '2junk', '-1', '+1', '4294967296',
                                   '18446744073709551616', '""', '"2 junk"', '2 junk', ''])
@pytest.mark.parametrize('owner', ['vm', 'shield'])
def test_material_budget_invalid_value(tmp_path, key, value, owner):
    # 同一函数的其他 pass 参数也会改变函数预算，不能绕过材料边界。
    spec = (f'vm({MODE},{key}={value})' if owner == 'vm' else
            f'vm({MODE}), shield({key}={value})')
    p, _ = request(tmp_path, spec)
    assert p.returncode != 0
    assert f'invalid unsigned value for {key}' in p.stderr
    assert STAGED not in p.stderr


@pytest.mark.parametrize('key', ['budget', 'budgetMax', 'budgetMultiplier'])
def test_declaration_cross_pass_budget_error_precedes_missing_body(tmp_path, key):
    p, _ = request(tmp_path, f'vm({MODE}), shield({key}=2junk)',
                   body='declare i32 @f(i32)\n')
    assert p.returncode != 0
    assert f'invalid unsigned value for {key}' in p.stderr
    assert 'cloudMaterial requires a function body' not in p.stderr
    assert STAGED not in p.stderr


@pytest.mark.parametrize('options,limit', [
    ('budget=0', 1000), ('budgetMultiplier=0', 1000), ('budgetMax=0', 1000),
    ('budget=200', 400), ('budgetMultiplier=200', 400), ('budgetMax=300', 300),
    ('budget=4294967295', 4294967295), ('budgetMultiplier=4294967295', 4294967295),
    ('budgetMax=4294967295', 1000), ('budget=200,budgetMultiplier=300', 600),
])
def test_material_budget_valid_values_preserve_effective_limit(tmp_path, options, limit):
    report = tmp_path / 'report.json'
    p, _ = request(tmp_path, f'vm({MODE},{options})',
                   extra=['-obf-ir-budget-multiplier=500', f'-obf-report-json={report}'])
    assert STAGED in p.stderr
    fn = next(f for f in json.loads(report.read_text())['functions'] if f['name'] == 'f')
    assert fn['budget']['limit'] == limit


@pytest.mark.parametrize('mixed', [False, True])
@pytest.mark.parametrize('mode,diagnostic', [
    ('lease', 'cloudMaterial requires a function body'),
    ('session', 'cloudMaterial requires a function body'),
    ('typo', 'unknown cloudMaterial mode'),
    ('operation', 'operation material not implemented'),
])
def test_declaration_material_request_is_fatal(tmp_path, mixed, mode, diagnostic):
    body = 'declare i32 @f(i32)\n'
    if mixed:
        body += 'define i32 @g(i32 %x) { ret i32 %x }\n'
    p, _ = request(tmp_path, f'vm(cloudMaterial={mode},materialRegion=auth)', body=body)
    assert p.returncode != 0
    assert diagnostic in p.stderr
    assert STAGED not in p.stderr


def test_declaration_request_with_populated_definition_cache(tmp_path):
    body = 'declare i32 @f(i32)\ndefine i32 @g(i32 %x) { ret i32 %x }\n'
    p, _ = request(tmp_path, f'vm({MODE})', body=body, functions=('f', 'g'))
    assert p.returncode != 0
    assert 'cloudMaterial requires a function body' in p.stderr
    assert STAGED not in p.stderr


@pytest.mark.parametrize('spec', ['vm', 'vm(cloudMaterial=off)', 'vm(cloudDispatch=1)',
                                  'vm(preset=legacy_unknown)'])
def test_ordinary_declaration_remains_ignored(tmp_path, spec):
    p, output = request(tmp_path, spec, body='declare i32 @f(i32)\n', export=False)
    assert p.returncode == 0, p.stderr
    assert 'declare i32 @f(i32)' in output.read_text()
