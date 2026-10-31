import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import test from 'node:test';

import {encodeCanonical} from '../codec.mjs';
import * as packageApi from '../package.mjs';
import {frame, packageHash, parseExecutionPackage} from '../../../tools/cloud-material/format.mjs';
import {
  encodeRegistrationCanonical, FOUNDATION_VM_LAYOUTS, MATERIAL_CODEC_PROFILE,
} from '../../../tools/cloud-material/export.mjs';

const ENGINE_ABI = createHash('sha256').update(
    'xovm-engine-abi-v1|banks=vreg:i32,vreg64:i64,freg:f64,preg:ptr|' +
    'call-index:u8|opcode:u8|target:u32le|bytecode-size:u32', 'ascii').digest('hex');
const {makePackage, validatePackagePairing} = packageApi;

function verifyRegisteredRegion(...args) {
  assert.equal(typeof packageApi.verifyRegisteredRegion, 'function',
    'missing VerifiedRegisteredRegion factory');
  return packageApi.verifyRegisteredRegion(...args);
}

function le16(value) {
  const out = Buffer.alloc(2);
  out.writeUInt16LE(value);
  return out;
}

function le32(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(value >>> 0);
  return out;
}

function descriptorFor(region, options = {}) {
  const opcodeMap = Buffer.from(options.opcodeMap ?? Array.from({length: 0x60}, (_, i) => i));
  const calls = options.calls ?? [];
  const targetKey = options.targetKey ?? 0;
  const layoutParts = [];
  let layoutSpec = 'xovm-layout-v2';
  for (let opcode = 0; opcode < FOUNDATION_VM_LAYOUTS.length; ++opcode) {
    const registered = FOUNDATION_VM_LAYOUTS[opcode];
    const override = options.layouts?.get(opcode);
    const fields = registered.fields.map(field => ({
      ...field, offset: override?.get(field.role) ?? field.canonical,
    }));
    layoutParts.push(Buffer.from([registered.size, Number(registered.variable), fields.length]));
    layoutSpec += `|op=${opcode},size=${registered.size},var=${Number(registered.variable)}`;
    for (const field of fields) {
      layoutParts.push(Buffer.from([field.role, field.canonical, field.offset, field.width]));
      layoutSpec += `,field=${field.role}:${field.canonical}:${field.offset}:${field.width}`;
    }
  }
  let callSpec = 'xovm-call-table-v1';
  for (let slot = 0; slot < calls.length; ++slot) {
    const call = calls[slot];
    const returned = ['void', 'i32', 'ptr', 'i64', 'f64'][call.kind];
    callSpec += `|slot=${slot}|xovm-call-abi-v1|ret=${returned}|vararg=0`;
    for (let index = 0; index < call.arity; ++index)
      callSpec += '|arg=i32|attrs=';
    callSpec += '|retattrs=|fnattrs=';
  }
  const ranges = [
    ['bin', 0, 13], ['icmp', 32, 10], ['cast', 0, 8], ['fbin', 0, 5],
    ['fcmp', 1, 14], ['cast64', 0, 11], ['fcast', 0, 10], ['select', 0, 3],
  ];
  let operandSpec = 'xovm-operand-encoding-v2';
  for (const [name, base, count] of ranges)
    operandSpec += `|${name}=${Array.from({length: count}, (_, i) => base + i).join(',')}`;
  operandSpec += `|opcode=${[...opcodeMap].join(',')}|target-format=xor-le32-v1|target-key=${targetKey}`;
  region.layout_hash = createHash('sha256').update(layoutSpec, 'ascii').digest('hex');
  region.call_abi_hash = createHash('sha256').update(callSpec, 'ascii').digest('hex');
  region.static_decode_descriptor.layout_hash = region.layout_hash;
  region.static_decode_descriptor.operand_encoding_hash =
    createHash('sha256').update(operandSpec, 'ascii').digest('hex');
  rehashRegion(region);
  return Buffer.concat([
    Buffer.from('XOVMVR1\0', 'ascii'), le32(1), le32(targetKey), le16(0x60), opcodeMap,
    le16(calls.length), Buffer.from(calls.flatMap(call => [call.arity, call.kind])), le16(0x60),
    ...layoutParts, le32(Buffer.byteLength(callSpec)), Buffer.from(callSpec, 'ascii'),
    le32(Buffer.byteLength(operandSpec)), Buffer.from(operandSpec, 'ascii'),
  ]);
}

function rehashRegion(region) {
  const core = structuredClone(region);
  delete core.region_content_hash;
  delete core.region_id;
  region.region_content_hash = createHash('sha256').update(frame(
      'XOVM2/region-content', encodeRegistrationCanonical(
          core, MATERIAL_CODEC_PROFILE.canonicalRegion))).digest('hex');
  const identity = {
    format_version: 1,
    region_name: region.region_name,
    region_content_hash: region.region_content_hash,
    engine_abi_hash: region.engine_abi_hash,
    call_abi_hash: region.call_abi_hash,
    layout_hash: region.layout_hash,
    mode: region.mode,
    target_triple: region.target_triple,
  };
  region.region_id = createHash('sha256').update(frame(
      'XOVM2/region-id', encodeRegistrationCanonical(
          identity, MATERIAL_CODEC_PROFILE.canonicalRegion))).digest('hex');
  return region;
}

function fixtureRegistration(options = {}) {
  // LOADI, MOVR, LOADI. The repeated logical opcode proves one session byte is reused.
  const bytecode = Buffer.from([
    0x41, 3, 0x78, 0x56, 0x34, 0x12,
    0x52, 4, 3,
    0x41, 5, 1, 0, 0, 0,
  ]);
  const region = {
    format_version: 1,
    isa_version: 1,
    target_triple: 'aarch64-linux-android26',
    region_name: 'test/package',
    mode: 'lease',
    canonical_bc: bytecode.toString('base64'),
    bytecode_size: bytecode.length,
    instruction_offsets: [0, 6, 9],
    logical_opcodes: [0, 1, 0],
    opcode_count: 96,
    engine_abi_hash: ENGINE_ABI,
    register_counts: [6, 0, 0, 0],
    call_abi_hash: 'b'.repeat(64),
    layout_hash: 'c'.repeat(64),
    static_decode_descriptor: {
      decode_salt: 13,
      isa_version: 1,
      layout_hash: 'c'.repeat(64),
      operand_encoding_hash: 'd'.repeat(64),
    },
  };
  const opcodeMap = Array.from({length: 0x60}, (_, i) => i);
  [opcodeMap[0], opcodeMap[0x41]] = [opcodeMap[0x41], opcodeMap[0]];
  [opcodeMap[1], opcodeMap[0x52]] = [opcodeMap[0x52], opcodeMap[1]];
  return {region, descriptor: descriptorFor(region, {...options, opcodeMap})};
}

function callRegistration() {
  const bytecode = Buffer.from([0x10, 0, 0, 0, 0x0d, 0]);
  const region = {
    format_version: 1, isa_version: 1, target_triple: 'aarch64-linux-android26',
    region_name: 'test/call', mode: 'lease', canonical_bc: bytecode.toString('base64'),
    bytecode_size: bytecode.length, instruction_offsets: [0, 4], logical_opcodes: [0x10, 0x0d],
    opcode_count: 96, engine_abi_hash: ENGINE_ABI, register_counts: [1, 0, 0, 0],
    call_abi_hash: '0'.repeat(64), layout_hash: '0'.repeat(64),
    static_decode_descriptor: {
      decode_salt: 13, isa_version: 1, layout_hash: '0'.repeat(64),
      operand_encoding_hash: '0'.repeat(64),
    },
  };
  return {region, descriptor: descriptorFor(region, {calls: [{arity: 0, kind: 1}]})};
}

function repeatedBranchRegistration(count = 2048, targetKey = 0x12345678) {
  const jumpSize = 5;
  const bytecode = Buffer.alloc(count * jumpSize + 1);
  const offsets = [];
  const logical = [];
  const target = count * jumpSize;
  for (let index = 0; index < count; ++index) {
    const offset = index * jumpSize;
    offsets.push(offset);
    logical.push(0x0a);
    bytecode[offset] = 0x0a;
    bytecode.writeUInt32LE((target ^ targetKey) >>> 0, offset + 1);
  }
  offsets.push(target);
  logical.push(0x0c);
  bytecode[target] = 0x0c;
  const region = {
    format_version: 1, isa_version: 1, target_triple: 'aarch64-linux-android26',
    region_name: 'test/branches', mode: 'lease', canonical_bc: bytecode.toString('base64'),
    bytecode_size: bytecode.length, instruction_offsets: offsets, logical_opcodes: logical,
    opcode_count: 96, engine_abi_hash: ENGINE_ABI, register_counts: [0, 0, 0, 0],
    call_abi_hash: '0'.repeat(64), layout_hash: '0'.repeat(64),
    static_decode_descriptor: {
      decode_salt: 13, isa_version: 1, layout_hash: '0'.repeat(64),
      operand_encoding_hash: '0'.repeat(64),
    },
  };
  return {region, descriptor: descriptorFor(region, {targetKey})};
}

function binding(region, overrides = {}) {
  return {
    build_id: 'e'.repeat(64),
    region_id: region.region_id,
    session_id: 'f'.repeat(64),
    generation: '1',
    request_hash: '1'.repeat(64),
    mode: 'lease',
    lease_ms: 120000,
    engine_abi_hash: region.engine_abi_hash,
    ...overrides,
  };
}

function sequenceRandom(start = 0) {
  let next = start;
  return size => {
    const out = Buffer.alloc(size);
    for (let index = 0; index < size; ++index) out[index] = next++ & 0xff;
    return out;
  };
}

function reversePackage(region, pkg) {
  const result = Buffer.from(pkg.encoded_bc, 'base64');
  for (const offset of region.instruction_offsets) result[offset] = pkg.decode_map[result[offset]];
  return result;
}

test('only instruction opcodes change and reverse mapping restores canonical bytes', () => {
  const {region, descriptor} = fixtureRegistration();
  const registered = verifyRegisteredRegion(region, descriptor);
  const expectedBinding = binding(region);
  const pkg = makePackage(registered, expectedBinding, sequenceRandom());
  assert.deepEqual(Object.keys(pkg).sort(), [
    'binding', 'bytecode_size', 'decode_map', 'encoded_bc', 'format_version',
    'static_decode_descriptor',
  ]);
  assert.deepEqual(Object.keys(pkg.binding).sort(), [
    'build_id', 'engine_abi_hash', 'generation', 'lease_ms', 'mode', 'package_hash',
    'region_id', 'request_hash', 'session_id',
  ]);
  const canonical = Buffer.from(region.canonical_bc, 'base64');
  const encoded = Buffer.from(pkg.encoded_bc, 'base64');
  const offsets = new Set(region.instruction_offsets);
  for (let index = 0; index < encoded.length; ++index) {
    if (!offsets.has(index)) assert.equal(encoded[index], canonical[index]);
  }
  assert.equal(encoded[0], encoded[9]);
  assert.notEqual(encoded[0], encoded[6]);
  assert.equal(pkg.decode_map[encoded[0]], canonical[0]);
  assert.equal(pkg.decode_map[encoded[6]], canonical[6]);
  assert.equal(pkg.decode_map.filter(value => value !== 65535).length, 2);
  assert.deepEqual(reversePackage(region, pkg), canonical);
  assert.equal(pkg.binding.package_hash, packageHash(pkg));
  assert.equal(validatePackagePairing(registered, pkg, expectedBinding), pkg);
  assert.equal(parseExecutionPackage(encodeCanonical(pkg), pkg.binding).bytecode.length,
    region.bytecode_size);
});

test('controlled random streams change the actual opcode encoding and map relation', () => {
  const {region, descriptor} = fixtureRegistration();
  const registered = verifyRegisteredRegion(region, descriptor);
  const first = makePackage(registered, binding(region), sequenceRandom(0));
  const second = makePackage(registered, binding(region, {generation: '2'}), sequenceRandom(91));
  const firstBytes = Buffer.from(first.encoded_bc, 'base64');
  const secondBytes = Buffer.from(second.encoded_bc, 'base64');
  assert.notDeepEqual(firstBytes.subarray(0, 1), secondBytes.subarray(0, 1));
  for (const [pkg, bytes] of [[first, firstBytes], [second, secondBytes]]) {
    assert.equal(pkg.decode_map[bytes[0]], 0x41);
    assert.equal(pkg.decode_map[bytes[6]], 0x52);
  }
});

test('rejection sampling discards out-of-range bytes instead of applying modulo', () => {
  const {region, descriptor} = fixtureRegistration();
  const registered = verifyRegisteredRegion(region, descriptor);
  const values = [255, 255, 254];
  for (let value = 253; value >= 0; --value) values.push(value);
  let calls = 0;
  const pkg = makePackage(registered, binding(region), size => {
    assert.equal(size, 1);
    ++calls;
    return Buffer.from([values.shift() ?? 0]);
  });
  assert.equal(Buffer.from(pkg.encoded_bc, 'base64')[0], 0);
  assert.equal(calls, 256);
});

test('random source contract is strict and deterministic failure is bounded', () => {
  const {region, descriptor} = fixtureRegistration();
  const registered = verifyRegisteredRegion(region, descriptor);
  for (const random of [() => 'x', () => Buffer.alloc(0), () => Buffer.alloc(2)]) {
    assert.throws(() => makePackage(registered, binding(region), random), {code: 'invalid_random'});
  }
  let calls = 0;
  assert.throws(() => makePackage(registered, binding(region), size => {
    ++calls;
    return Buffer.alloc(size, 255);
  }), {code: 'random_stalled'});
  assert.ok(calls <= 1024);
});

test('strict region and binding validation rejects schema hash layout and ABI drift', () => {
  const cases = [
    region => { region.extra = 1; },
    region => { region.region_content_hash = '0'.repeat(64); },
    region => { region.static_decode_descriptor.layout_hash = '9'.repeat(64); },
    region => { region.engine_abi_hash = '9'.repeat(64); rehashRegion(region); },
    region => { region.bytecode_size += 1; rehashRegion(region); },
    region => { region.instruction_offsets[1] = 7; rehashRegion(region); },
    region => {
      const bytes = Buffer.from(region.canonical_bc, 'base64');
      bytes[9] = 0x53;
      region.canonical_bc = bytes.toString('base64');
      rehashRegion(region);
    },
  ];
  for (const mutate of cases) {
    const {region, descriptor} = fixtureRegistration();
    mutate(region);
    assert.throws(() => verifyRegisteredRegion(region, descriptor), undefined,
      JSON.stringify(region));
  }
  const {region, descriptor} = fixtureRegistration();
  const registered = verifyRegisteredRegion(region, descriptor);
  for (const bad of [
    {...binding(region), extra: 1},
    binding(region, {region_id: '8'.repeat(64)}),
    binding(region, {engine_abi_hash: '8'.repeat(64)}),
    binding(region, {mode: 'session', lease_ms: 1}),
    binding(region, {mode: 'lease', lease_ms: 0}),
    binding(region, {package_hash: '0'.repeat(64)}),
  ]) assert.throws(() => makePackage(registered, bad, sequenceRandom()));
});

test('pairing validator rejects recomputed-hash bytecode map record and tail corruption', () => {
  const {region, descriptor} = fixtureRegistration();
  const registered = verifyRegisteredRegion(region, descriptor);
  const expectedBinding = binding(region);
  const first = makePackage(registered, expectedBinding, sequenceRandom(0));
  const second = makePackage(registered, expectedBinding, sequenceRandom(91));
  const corruptions = [
    pkg => { pkg.decode_map = second.decode_map; },
    pkg => { pkg.encoded_bc = second.encoded_bc; },
    pkg => {
      const bytes = Buffer.from(pkg.encoded_bc, 'base64');
      bytes[4] ^= 1;
      pkg.encoded_bc = bytes.toString('base64');
    },
    pkg => {
      const bytes = Buffer.from(pkg.encoded_bc, 'base64');
      bytes[6] = bytes[0];
      pkg.encoded_bc = bytes.toString('base64');
    },
    pkg => { ++pkg.static_decode_descriptor.decode_salt; },
  ];
  for (const corrupt of corruptions) {
    const pkg = structuredClone(first);
    corrupt(pkg);
    pkg.binding.package_hash = packageHash(pkg);
    assert.throws(() => validatePackagePairing(registered, pkg, expectedBinding));
  }
});

test('plain or rehashed regions cannot substitute for verified registration capability', () => {
  const {region} = fixtureRegistration();
  assert.throws(() => makePackage(region, binding(region), sequenceRandom()),
    {code: 'unverified_registered_region'});
  const clone = structuredClone(region);
  rehashRegion(clone);
  assert.throws(() => makePackage(clone, binding(clone), sequenceRandom()),
    {code: 'unverified_registered_region'});
});

test('exact verifier rejects self-consistent physical opcode and CALL ABI mutations', () => {
  {
    const {region, descriptor} = fixtureRegistration();
    const bytecode = Buffer.from(region.canonical_bc, 'base64');
    bytecode[0] = bytecode[9] = 0x60;
    region.canonical_bc = bytecode.toString('base64');
    rehashRegion(region);
    assert.throws(() => verifyRegisteredRegion(region, descriptor));
  }
  for (const mutate of [
    (region, bytecode) => { bytecode[2] = 1; },
    (region, bytecode) => {
      bytecode[0] = 0x11;
      region.logical_opcodes[0] = 0x11;
    },
  ]) {
    const {region, descriptor} = callRegistration();
    const bytecode = Buffer.from(region.canonical_bc, 'base64');
    mutate(region, bytecode);
    region.canonical_bc = bytecode.toString('base64');
    rehashRegion(region);
    assert.throws(() => verifyRegisteredRegion(region, descriptor));
  }
});

test('exact descriptor accepts committed shuffled layout and rejects wrong target key', () => {
  const layouts = new Map([[0, new Map([[0, 5], [7, 1]])]]);
  const shuffled = fixtureRegistration({layouts});
  const registered = verifyRegisteredRegion(shuffled.region, shuffled.descriptor);
  assert.ok(makePackage(registered, binding(shuffled.region), sequenceRandom()));

  const branches = repeatedBranchRegistration(8, 0x12345678);
  const wrongDescriptor = descriptorFor(branches.region, {targetKey: 0x87654321});
  assert.throws(() => verifyRegisteredRegion(branches.region, wrongDescriptor));
});

test('repeated-target branch verification performs one bounded lookup per target', () => {
  const {region, descriptor} = repeatedBranchRegistration();
  const events = [];
  verifyRegisteredRegion(region, descriptor, {probe: event => events.push(event)});
  assert.deepEqual(events, [{kind: 'target_lookup_operations', operations: 2048}]);
});
