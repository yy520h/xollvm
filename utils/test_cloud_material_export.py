"""Task 3 export remains private and cannot promote a failed compiler run."""
import os
from pathlib import Path
import subprocess

from vm_hardening_support import annotation


MODE = 'vm(cloudMaterial=lease,materialRegion=auth)'


def run_request(tmp_path, spec=MODE, *, extra=(), body=None):
    root = Path(os.environ.get('XOLLVM_PROJECT_ROOT', Path(__file__).resolve().parents[2]))
    opt = Path(os.environ.get('XOLLVM_OPT', root / 'build-sensitive/bin/opt'))
    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    source = tmp_path / 'input.ll'
    source.write_text('target triple = "aarch64-linux-android26"\n' +
                      (body or 'define i32 @f(i32 %x) { %r = add i32 %x, 7\n ret i32 %r }\n') +
                      annotation(['f'], spec))
    result = subprocess.run([str(opt), '-passes=obfuscation',
                             f'-obf-material-export-dir={private}', *extra,
                             '-disable-output', str(source)],
                            capture_output=True, text=True, timeout=45)
    return result, private


def published_regions(private):
    return list(private.rglob('*.region.json'))


def test_budget_failure_does_not_publish_material(tmp_path):
    result, private = run_request(
        tmp_path, 'vm(cloudMaterial=lease,materialRegion=auth,budgetMax=1)')
    assert result.returncode != 0
    assert not published_regions(private)


def test_valid_config_exports_runtime_lookup_id_without_rewriting(tmp_path):
    result, private = run_request(
        tmp_path, body='define i32 @f() { ret i32 7 }\n')
    assert result.returncode == 0, result.stderr
    assert 'auth__f' in result.stdout
    assert not list(private.rglob('*auth_pay*'))
    assert list(private.rglob('*auth__f*'))


def test_material_region_id_uses_one_path_safe_spelling(tmp_path):
    result, private = run_request(
        tmp_path, 'vm(cloudMaterial=lease,materialRegion=auth.pay)',
        body='define i32 @f() { ret i32 7 }\n')
    assert result.returncode != 0
    assert 'path-safe ID' in result.stderr
    assert list(private.iterdir()) == []


def test_real_cpp_exporter_fixture(tmp_path):
    project = Path(os.environ.get(
        'XOLLVM_PROJECT_ROOT', '/data/user/0/com.termux/files/home/xollvm-android'))
    binary = Path(os.environ.get(
        'XOVM_MATERIAL_TEST', project / 'build-sensitive/tools/Obfuscator/VMRequirementsTests'))
    assert binary.is_file()
    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    env = {**os.environ, 'XOVM_TEST_EXPORT_ROOT': str(private)}
    result = subprocess.run(
        [str(binary), '--gtest_filter=VMMaterial.ExportFixtureForAggregator'],
        env=env, capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
    regions = published_regions(private)
    assert len(regions) == 2
    assert all(region.stat().st_mode & 0o777 == 0o600 for region in regions)


def test_unsupported_and_report_failure_do_not_publish_material(tmp_path):
    result, private = run_request(
        tmp_path, body='define void @f() { fence seq_cst\n ret void }\n')
    assert result.returncode != 0
    assert not published_regions(private)
    assert list(private.iterdir()) == []

    other = tmp_path / 'report-failure'
    other.mkdir()
    result, private = run_request(
        other, extra=('-obf-report-json=/dev/full',),
        body='define i32 @f() { ret i32 7 }\n')
    assert result.returncode != 0
    assert 'material preflight report failed' in result.stderr
    assert not published_regions(private)
    assert list(private.iterdir()) == []
