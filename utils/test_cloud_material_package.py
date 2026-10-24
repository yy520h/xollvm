"""同一原始字节跨语言验证；期望包和摘要由独立 Python 实现产生。"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from cloud_material_support import build_material_harness, run_material_case

REPO = Path(__file__).resolve().parents[1]
MAX_BC = 8388608
MAX_P = 11250348


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def seal(package):
    core = copy.deepcopy(package)
    core['binding'].pop('package_hash', None)
    data = canonical(core)
    digest = hashlib.sha256(b'XOVM2/package\0' + len(data).to_bytes(4, 'big') + data).hexdigest()
    package['binding']['package_hash'] = digest
    return canonical(package)


def fixture(size=3, mode='session', generation='1', lease=0) -> dict:
    bc = bytes((i % 256 for i in range(size)))
    p = dict(format_version=1, bytecode_size=size, encoded_bc=base64.b64encode(bc).decode(),
             binding=dict(build_id='11' * 32, region_id='22' * 32, session_id='33' * 32,
                          request_hash='44' * 32, engine_abi_hash='55' * 32,
                          generation=generation, mode=mode, lease_ms=lease),
             decode_map=list(range(256)),
             static_decode_descriptor=dict(decode_salt=4294967295, isa_version=1,
                                           layout_hash='66' * 32, operand_encoding_hash='77' * 32))
    seal(p)
    return p


@pytest.fixture(scope='session')
def exe(tmp_path_factory):
    return build_material_harness(tmp_path_factory.mktemp('material-native'))


def compare(exe, data, expected, ok, case='package', code=None, forbidden_codes=()):
    native = run_material_case(exe, case, input_bytes=data, expected_binding=expected, timeout=30)
    p = subprocess.run(['node', REPO / 'cloud/material_v2/test/codec.test.mjs', '--case', case],
                       input=canonical(expected) + b'\n' + data, capture_output=True, timeout=30)
    assert p.returncode == 0, p.stderr.decode(errors='replace')
    node = json.loads(p.stdout)
    assert native['ok'] is ok, native
    assert node['ok'] is ok, node
    if ok:
        assert native == node
    if code:
        assert native['code'] == node['code'] == code
    if not ok:
        assert native['code'] not in forbidden_codes
        assert node['code'] not in forbidden_codes
    return native


@pytest.mark.parametrize('size,mode,generation,lease', [
    (1, 'session', '1', 0), (3, 'lease', '18446744073709551615', 120000),
    (2, 'lease', '9007199254740993', 1), (256, 'lease', '2', 45000),
    (MAX_BC, 'session', '1', 0),
])
def test_valid_boundaries(exe, size, mode, generation, lease):
    p = fixture(size, mode, generation, lease)
    result = compare(exe, seal(p), p['binding'], True)
    assert result['bytecode_size'] == size
    assert result['bytecode_hash'] == hashlib.sha256(base64.b64decode(p['encoded_bc'])).hexdigest()
    assert result['package_hash'] == p['binding']['package_hash']


def mutations():
    yield 'zero-size', ('bytecode_size',), 0
    yield 'large-size', ('bytecode_size',), MAX_BC + 1
    yield 'size-mismatch', ('bytecode_size',), 2
    yield 'version', ('format_version',), 2
    yield 'version-bool', ('format_version',), True
    yield 'empty-bc', ('encoded_bc',), ''
    for value in ['AA', 'AB==', 'AAB=', 'AA==\n', 'AA-_', 'A===', '====', 'AA==AAAA']:
        yield 'base64-' + repr(value), ('encoded_bc',), value
    for field, value in [('generation', 9007199254740993), ('generation', '0'),
                         ('generation', '01'), ('generation', '18446744073709551616'),
                         ('generation', '1' * 21), ('generation', '-1'),
                         ('lease_ms', 1), ('mode', 'operation'), ('mode', 'unknown'),
                         ('session_id', '00' * 32), ('build_id', 'AA' * 32),
                         ('engine_abi_hash', 'f' * 63), ('unknown', 1)]:
        yield 'binding-' + field + '-' + str(value), ('binding', field), value
    for field, value in [('isa_version', 2), ('decode_salt', -1), ('decode_salt', True),
                         ('decode_salt', 4294967296), ('layout_hash', 'z' * 64),
                         ('operand_encoding_hash', None), ('extra', 0)]:
        yield 'descriptor-' + field + '-' + str(value), ('static_decode_descriptor', field), value
    for value in [[0] * 256, [65535] * 256, list(range(255)), list(range(256)) + [65535],
                  [256] + list(range(1, 256)), [-1] + list(range(1, 256)),
                  [65536] + list(range(1, 256)), [True] + list(range(1, 256))]:
        yield 'map-' + str(value[:2]) + '-' + str(len(value)), ('decode_map',), value
    yield 'unknown-root', ('extra',), 1


@pytest.mark.parametrize('name,path,value', list(mutations()))
def test_adversarial_schema(exe, name, path, value):
    p = fixture()
    expected = copy.deepcopy(p['binding'])
    target = p
    for field in path[:-1]:
        target = target[field]
    target[path[-1]] = value
    data = seal(p)
    # 更新期望摘要，使 schema 拒绝不能仅依赖旧摘要或 binding 不相等。
    expected['package_hash'] = p['binding']['package_hash']
    compare(exe, data, expected, False, forbidden_codes=('binding_mismatch', 'package_hash_mismatch'))


@pytest.mark.parametrize('section', ['', 'binding', 'static_decode_descriptor'])
def test_every_required_member(exe, section):
    base = fixture()
    for key in (base[section] if section else base):
        p = copy.deepcopy(base)
        del (p[section] if section else p)[key]
        compare(exe, canonical(p), base['binding'], False)


@pytest.mark.parametrize('field', list(fixture()['binding']))
def test_full_expected_binding(exe, field):
    p = fixture(mode='lease', lease=45000)
    expected = copy.deepcopy(p['binding'])
    expected[field] = {'generation': '2', 'lease_ms': 1, 'mode': 'session'}.get(field, 'aa' * 32)
    if field == 'mode':
        expected['lease_ms'] = 0
    compare(exe, seal(p), expected, False, code='binding_mismatch')


def test_expected_binding_closed_schema(exe):
    p = fixture()
    for value in [{**p['binding'], 'extra': 0}, {k: v for k, v in p['binding'].items() if k != 'engine_abi_hash'}]:
        compare(exe, seal(p), value, False)


def test_hash_integrity_and_sparse_map(exe):
    p = fixture()
    p['decode_map'] = [65535] * 256
    p['decode_map'][0] = 255
    data = seal(p)
    compare(exe, data, p['binding'], True)
    for path in [('encoded_bc',), ('decode_map',), ('static_decode_descriptor', 'decode_salt'),
                 ('binding', 'package_hash')]:
        q = copy.deepcopy(p)
        t = q
        for key in path[:-1]:
            t = t[key]
        t[path[-1]] = {'encoded_bc': 'AAIE', 'decode_map': list(range(256)),
                      'decode_salt': 0, 'package_hash': 'aa' * 32}[path[-1]]
        compare(exe, canonical(q), q['binding'], False, code='package_hash_mismatch')


@pytest.mark.parametrize('data,code', [
    (b'[' * 9, 'depth_limit'), (b'{"a":"' + b'x' * 257, 'string_limit'),
    (b'{"a":' + b'1' * 11, 'number_limit'),
    (b'[' + b'0,' * 256 + b'0]', 'array_limit'),
    (canonical({f'k{i:02}': 0 for i in range(41)}), 'object_limit'),
    (b'x' * (MAX_P + 1), 'size_limit'),
    (b'{"encoded_bc":"' + b'A' * 11184813, 'string_limit'),
], ids=['depth', 'string', 'number', 'array', 'object', 'body', 'base64-token'])
def test_pre_dom_resource_limits(exe, data, code):
    compare(exe, data, {}, False, case='canonical', code=code)
    compare(exe, data, {}, False, case='canonical-noalloc', code=code)


@pytest.mark.parametrize('data', [b'{"a":1,"a":2}', b'{"a":{"x":0,"x":1}}',
    b'{"b":0,"a":0}', b'{"a":-0}', b'{"a":1e0}', b'{"a":1.0}', b'{"a":01}',
    b'{"a":"\\u0031"}', b'{"a":"\\/"}', b'{"a":null}', b'{"a": 0}', b'{}\n', b'{}{}',
    b'\xef\xbb\xbf{}', b'{"a":"\xc0\xaf"}', b'{"a":"\xff"}', b'{"a":"\x7f"}',
    b'{"a":"\xc3\xa9"}', b'{"A":0}', b'{"a":4294967296}', b'{"a":true,}', b'[0,]'])
def test_raw_canonical_rejections(exe, data):
    compare(exe, data, {}, False, case='canonical')


@pytest.mark.parametrize('value', [True, False, 4294967295, {'a': 'x' * 256},
    {'a': '/"\\'}, [[[[[[[[]]]]]]]], list(range(256)), {f'k{i:02}': 0 for i in range(40)}])
def test_canonical_inclusive_limits(exe, value):
    compare(exe, canonical(value), {}, True, case='canonical')


def test_truncation_trailing_and_lease_bounds(exe):
    p = fixture()
    data = seal(p)
    for value in [data[:-1], data + b'\n', data + b'{}', b'']:
        compare(exe, value, p['binding'], False)
    for lease in [0, 120001]:
        p = fixture(mode='lease', lease=lease)
        compare(exe, seal(p), p['binding'], False)


def test_harness_real_failure_and_root_override(exe, monkeypatch, tmp_path):
    with pytest.raises(RuntimeError, match='fixture_failure'):
        run_material_case(exe, 'fail')
    with pytest.raises(RuntimeError, match='timeout'):
        run_material_case(exe, 'wait', timeout=0.1)
    monkeypatch.setenv('XOLLVM_PROJECT_ROOT', str(tmp_path))
    with pytest.raises(RuntimeError, match='required'):
        build_material_harness(tmp_path)


def test_static_runtime_and_c_abi(exe):
    result = run_material_case(exe, 'abi')
    assert result == {'ok': True, 'descriptor_size': 104, 'record_size': 120, 'view_size': 40}
    root = Path(os.environ['XOLLVM_PROJECT_ROOT'])
    readelf = root.parent / 'android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64/bin/llvm-readelf'
    p = subprocess.run([readelf, '-d', exe], capture_output=True, text=True, check=True)
    assert 'libc++_shared.so' not in p.stdout
    assert 'libcrypto.so' not in p.stdout
    compiler = readelf.parent / 'clang'
    p = subprocess.run([compiler, '--target=aarch64-linux-android26', '-x', 'c', '-std=c11',
                        '-Werror', '-fsyntax-only', '-include',
                        REPO / 'runtime/cloud_material/material_abi.h', '-'], input=b'', capture_output=True)
    assert p.returncode == 0, p.stderr.decode()
    p = subprocess.run([exe, 'abi'], capture_output=True, check=True,
                       env={'PATH': '/system/bin', 'LD_LIBRARY_PATH': '/system/lib64'})
    assert json.loads(p.stdout) == result


def test_binding_changes_are_in_hash_preimage(exe):
    p = fixture(mode='lease', lease=45000)
    for key in p['binding']:
        q = copy.deepcopy(p)
        q['binding'][key] = {'generation': '2', 'lease_ms': 1, 'mode': 'session'}.get(key, 'aa' * 32)
        if key == 'mode':
            q['binding']['lease_ms'] = 0
        compare(exe, canonical(q), q['binding'], False, code='package_hash_mismatch')
    for key, value in [('layout_hash', 'aa' * 32), ('operand_encoding_hash', 'bb' * 32)]:
        q = copy.deepcopy(p)
        q['static_decode_descriptor'][key] = value
        compare(exe, canonical(q), q['binding'], False, code='package_hash_mismatch')


def overhead_fixture(overhead, bc_length=0):
    p = {'a': ['x' * 256] * 252 + [''], 'encoded_bc': 'A' * bc_length}
    remaining = overhead - (len(canonical(p)) - bc_length)
    assert 0 <= remaining <= 256
    p['a'][-1] = 'x' * remaining
    data = canonical(p)
    assert len(data) - bc_length == overhead
    return data


def test_plaintext_and_overhead_inclusive_limits(exe):
    compare(exe, overhead_fixture(65536), {}, True, case='canonical')
    data = overhead_fixture(65536, 11184812)
    assert len(data) == MAX_P
    compare(exe, data, {}, True, case='canonical')
    data = overhead_fixture(65537)
    compare(exe, data, {}, False, case='canonical', code='overhead_limit')
    compare(exe, data, {}, False, case='canonical-noalloc', code='overhead_limit')
    # 正常 DOM 解析在禁用分配时失败，证明故障注入确实生效。
    assert run_material_case(exe, 'canonical-noalloc', input_bytes=b'{}') == {
        'ok': False, 'code': 'allocation_failed'}


def test_actual_bytecode_one_over_limit(exe):
    p = fixture(MAX_BC + 1)
    compare(exe, seal(p), p['binding'], False)
    p['bytecode_size'] = MAX_BC
    compare(exe, seal(p), p['binding'], False, code='bytecode_size_mismatch')


@pytest.mark.parametrize('size,encoded', [(1, 'AB=='), (2, 'AAB='), (1, 'AA-_'), (1, 'AA==AAAA')])
def test_base64_aliases_not_hidden_by_length_or_hash(exe, size, encoded):
    p = fixture(size)
    p['encoded_bc'] = encoded
    compare(exe, seal(p), p['binding'], False, code='invalid_base64')


def test_duplicate_package_members_at_each_level(exe):
    p = fixture()
    data = seal(p)
    for key, value in [('format_version', b'1'), ('generation', b'"1"'), ('isa_version', b'1')]:
        field = b'"' + key.encode() + b'":' + value
        duplicate = data.replace(field, field + b',' + field)
        compare(exe, duplicate, p['binding'], False, code='invalid_key_order')


def test_key_boundary_and_nested_large_token_exemption(exe):
    compare(exe, canonical({'a' * 64: 0}), {}, True, case='canonical')
    compare(exe, canonical({'a' * 65: 0}), {}, False, case='canonical', code='string_limit')
    compare(exe, canonical({'a': {'encoded_bc': 'A' * 257}}), {}, False,
            case='canonical', code='string_limit')


def test_helper_requires_explicit_root(monkeypatch, tmp_path):
    monkeypatch.delenv('XOLLVM_PROJECT_ROOT', raising=False)
    with pytest.raises(RuntimeError, match='required absolute XOLLVM_PROJECT_ROOT'):
        build_material_harness(tmp_path)
