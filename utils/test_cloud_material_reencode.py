"""Task 4 re-encodes genuine compiler material and remains C++ parser compatible."""
import json
import os
from pathlib import Path
import subprocess

REPO = Path(__file__).resolve().parents[1]
PROJECT = Path(os.environ.get(
    'XOLLVM_PROJECT_ROOT', '/data/user/0/com.termux/files/home/xollvm-android'))
MATERIAL_TEST = Path(os.environ.get(
    'XOVM_MATERIAL_TEST', PROJECT / 'build-sensitive/tools/Obfuscator/VMRequirementsTests'))


def require_native_bridge():
    result = subprocess.run(
        [str(MATERIAL_TEST), '--gtest_list_tests'], capture_output=True,
        text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'VMMaterial.\n' in result.stdout
    assert '  VerifyExecutionPackageFixture\n' in result.stdout, (
        'VMRequirementsTests lacks the opt-in material package bridge')


def genuine_region(tmp_path):
    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    result = subprocess.run(
        [str(MATERIAL_TEST), '--gtest_filter=VMMaterial.ExportFixtureForAggregator'],
        env={**os.environ, 'XOVM_TEST_EXPORT_ROOT': str(private)},
        capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
    for filename in private.rglob('*.region.json'):
        region = json.loads(filename.read_bytes())
        if region['region_name'] == 'auth/payment':
            descriptor = filename.with_name(f"{region['region_id']}.verifier").read_bytes()
            return region, descriptor
    raise AssertionError('genuine auth/payment region missing')


def binding(region):
    return {
        'build_id': 'a' * 64,
        'region_id': region['region_id'],
        'session_id': 'b' * 64,
        'generation': '7',
        'request_hash': 'c' * 64,
        'mode': 'lease',
        'lease_ms': 120000,
        'engine_abi_hash': region['engine_abi_hash'],
    }


def node_package(region, package_binding, descriptor):
    script = r'''
import {
  makePackage, validatePackagePairing, verifyRegisteredRegion,
} from './cloud/material_v2/package.mjs';
import {encodeCanonical} from './cloud/material_v2/codec.mjs';
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const {region, binding, descriptor} = JSON.parse(Buffer.concat(chunks));
let value = 17;
const randomBytes = size => {
  const out = Buffer.alloc(size);
  for (let i = 0; i < size; ++i) { value = (value * 73 + 41) & 255; out[i] = value; }
  return out;
};
const registered = verifyRegisteredRegion(region, Buffer.from(descriptor, 'base64'));
const pkg = makePackage(registered, binding, randomBytes);
validatePackagePairing(registered, pkg, binding);
process.stdout.write(encodeCanonical(pkg));
'''
    result = subprocess.run(
        ['node', '--input-type=module', '--eval', script], cwd=REPO,
        input=json.dumps({'region': region, 'binding': package_binding,
                          'descriptor': descriptor},
                         separators=(',', ':')).encode(),
        capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    return result.stdout


def test_genuine_export_reencodes_and_cpp_parser_recovers_protocol_package(tmp_path):
    assert MATERIAL_TEST.is_file()
    require_native_bridge()
    region, descriptor = genuine_region(tmp_path)
    package_binding = binding(region)
    descriptor_b64 = __import__('base64').b64encode(descriptor).decode()
    package_bytes = node_package(region, package_binding, descriptor_b64)
    package = json.loads(package_bytes)
    material_binding = package['binding']

    native_input = json.dumps({
        'binding': material_binding,
        'region': region,
        'verifier_descriptor': descriptor_b64,
    }, sort_keys=True, separators=(',', ':')).encode() + b'\n' + package_bytes
    native = subprocess.run(
        [str(MATERIAL_TEST), '--gtest_filter=VMMaterial.VerifyExecutionPackageFixture'],
        env={**os.environ, 'XOVM_TEST_PACKAGE_BRIDGE': '1'}, input=native_input,
        capture_output=True, timeout=45)
    assert native.returncode == 0, (native.stdout + native.stderr).decode(errors='replace')
    prefix = b'XOVM_NATIVE_VERDICT '
    verdicts = [line[len(prefix):] for line in native.stdout.splitlines()
                if line.startswith(prefix)]
    assert len(verdicts) == 1, native.stdout.decode(errors='replace')
    parsed = json.loads(verdicts[0])
    assert parsed == {
        'ok': True,
        'bytecode_size': region['bytecode_size'],
        'generation': package_binding['generation'],
        'package_hash': material_binding['package_hash'],
        'native_descriptor_verified': True,
        'native_semantics_verified': True,
        'reverse_matches_canonical': True,
    }
