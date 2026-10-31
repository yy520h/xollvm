import {createHash} from 'node:crypto';

import {
  encodeRegistrationCanonical, FOUNDATION_VM_LAYOUTS, MATERIAL_CODEC_PROFILE,
} from '../../../tools/cloud-material/export.mjs';
import {frame} from '../../../tools/cloud-material/format.mjs';

export const ENGINE_ABI = createHash('sha256').update(
    'xovm-engine-abi-v1|banks=vreg:i32,vreg64:i64,freg:f64,preg:ptr|' +
    'call-index:u8|opcode:u8|target:u32le|bytecode-size:u32', 'ascii').digest('hex');

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

export function rehashRegion(region) {
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
}

function descriptorFor(region, opcodeMap) {
  const layoutParts = [];
  let layoutSpec = 'xovm-layout-v2';
  for (let opcode = 0; opcode < FOUNDATION_VM_LAYOUTS.length; ++opcode) {
    const registered = FOUNDATION_VM_LAYOUTS[opcode];
    layoutParts.push(Buffer.from([registered.size, Number(registered.variable),
      registered.fields.length]));
    layoutSpec += `|op=${opcode},size=${registered.size},var=${Number(registered.variable)}`;
    for (const field of registered.fields) {
      layoutParts.push(Buffer.from([field.role, field.canonical, field.canonical, field.width]));
      layoutSpec += `,field=${field.role}:${field.canonical}:${field.canonical}:${field.width}`;
    }
  }
  const callSpec = 'xovm-call-table-v1';
  const ranges = [
    ['bin', 0, 13], ['icmp', 32, 10], ['cast', 0, 8], ['fbin', 0, 5],
    ['fcmp', 1, 14], ['cast64', 0, 11], ['fcast', 0, 10], ['select', 0, 3],
  ];
  let operandSpec = 'xovm-operand-encoding-v2';
  for (const [name, base, count] of ranges)
    operandSpec += `|${name}=${Array.from({length: count}, (_, i) => base + i).join(',')}`;
  operandSpec += `|opcode=${opcodeMap.join(',')}|target-format=xor-le32-v1|target-key=0`;
  region.layout_hash = createHash('sha256').update(layoutSpec, 'ascii').digest('hex');
  region.call_abi_hash = createHash('sha256').update(callSpec, 'ascii').digest('hex');
  region.static_decode_descriptor.layout_hash = region.layout_hash;
  region.static_decode_descriptor.operand_encoding_hash =
    createHash('sha256').update(operandSpec, 'ascii').digest('hex');
  rehashRegion(region);
  return Buffer.concat([
    Buffer.from('XOVMVR1\0', 'ascii'), le32(1), le32(0), le16(0x60),
    Buffer.from(opcodeMap), le16(0), le16(0x60), ...layoutParts,
    le32(Buffer.byteLength(callSpec)), Buffer.from(callSpec, 'ascii'),
    le32(Buffer.byteLength(operandSpec)), Buffer.from(operandSpec, 'ascii'),
  ]);
}

export function fixtureRegion(name = 'test/lease', mode = 'lease') {
  const bytecode = Buffer.from([0x41, 3, 1, 0, 0, 0, 0x52, 4, 3]);
  const region = {
    format_version: 1,
    isa_version: 1,
    target_triple: 'aarch64-linux-android26',
    region_name: name,
    mode,
    canonical_bc: bytecode.toString('base64'),
    bytecode_size: bytecode.length,
    instruction_offsets: [0, 6],
    logical_opcodes: [0, 1],
    opcode_count: 96,
    engine_abi_hash: ENGINE_ABI,
    register_counts: [5, 0, 0, 0],
    call_abi_hash: '0'.repeat(64),
    layout_hash: '0'.repeat(64),
    static_decode_descriptor: {
      decode_salt: 7,
      isa_version: 1,
      layout_hash: '0'.repeat(64),
      operand_encoding_hash: '0'.repeat(64),
    },
  };
  const opcodeMap = Array.from({length: 0x60}, (_, index) => index);
  [opcodeMap[0], opcodeMap[0x41]] = [opcodeMap[0x41], opcodeMap[0]];
  [opcodeMap[1], opcodeMap[0x52]] = [opcodeMap[0x52], opcodeMap[1]];
  return {region, verifier: descriptorFor(region, opcodeMap)};
}

export function registrationFixture(regionFixtures, softwareId = 'test.software') {
  const ordered = [...regionFixtures].sort((left, right) =>
    left.region.region_id.localeCompare(right.region.region_id));
  const publicRegions = ordered.map(({region}) => ({
    region_id: region.region_id,
    region_content_hash: region.region_content_hash,
    region_name: region.region_name,
    mode: region.mode,
    engine_abi_hash: region.engine_abi_hash,
    call_abi_hash: region.call_abi_hash,
    layout_hash: region.layout_hash,
  }));
  const core = {
    format_version: 1,
    protocol_version: 2,
    vm_format_version: 1,
    target_triple: 'aarch64-linux-android26',
    software_id: softwareId,
    regions: publicRegions,
  };
  const buildId = createHash('sha256').update(frame(
      'XOVM2/build-id', encodeRegistrationCanonical(
          core, MATERIAL_CODEC_PROFILE.publicManifest))).digest('hex');
  return {
    manifest: {...core, build_id: buildId},
    registration: {
      format_version: 1,
      build_id: buildId,
      regions: ordered.map(({region}) => structuredClone(region)),
    },
    verifiers: new Map(ordered.map(({region, verifier}) =>
      [region.region_id, Buffer.from(verifier)])),
  };
}
