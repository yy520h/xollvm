import {createHash, randomBytes as productionRandomBytes} from 'node:crypto';

import {encodeCanonical, fail, MAX_BYTECODE} from './codec.mjs';
import {
  decodeBytecode, frame, packageHash, parseExecutionPackage, validatePackageBinding,
} from '../../tools/cloud-material/format.mjs';
import {
  encodeRegistrationCanonical, FOUNDATION_VM_LAYOUTS, MATERIAL_CODEC_PROFILE,
  parseVerifierDescriptor, verifyCanonicalBytecodeBytes,
} from '../../tools/cloud-material/export.mjs';

const HASH = /^[0-9a-f]{64}$/;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const REGION_FIELDS = [
  'format_version', 'isa_version', 'target_triple', 'region_name', 'mode',
  'canonical_bc', 'bytecode_size', 'instruction_offsets', 'logical_opcodes',
  'opcode_count', 'engine_abi_hash', 'register_counts', 'call_abi_hash',
  'layout_hash', 'static_decode_descriptor', 'region_content_hash', 'region_id',
];
const DESCRIPTOR_FIELDS = ['decode_salt', 'isa_version', 'layout_hash', 'operand_encoding_hash'];
const PACKAGE_FIELDS = [
  'format_version', 'binding', 'bytecode_size', 'encoded_bc', 'decode_map',
  'static_decode_descriptor',
];
const MATERIAL_BINDING_FIELDS = [
  'build_id', 'region_id', 'session_id', 'generation', 'request_hash', 'mode',
  'lease_ms', 'engine_abi_hash', 'package_hash',
];
const MAX_RANDOM_DRAWS = 1024;
const FOUNDATION_ENGINE_ABI_HASH = createHash('sha256').update(
    'xovm-engine-abi-v1|banks=vreg:i32,vreg64:i64,freg:f64,preg:ptr|' +
    'call-index:u8|opcode:u8|target:u32le|bytecode-size:u32', 'ascii').digest('hex');

function closed(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) ||
      Object.getOwnPropertySymbols(value).length || Object.keys(value).length !== fields.length ||
      fields.some(field => !Object.hasOwn(value, field))) fail('invalid_schema');
}

function u32(value, minimum = 0, maximum = 0xffffffff) {
  if (!Number.isInteger(value) || Object.is(value, -0) || value < minimum || value > maximum)
    fail('invalid_u32');
  return value;
}

function hash(value) {
  if (typeof value !== 'string' || !HASH.test(value)) fail('invalid_hash');
  return value;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function validateCanonicalRegion(region) {
  closed(region, REGION_FIELDS);
  u32(region.format_version, 1, 1);
  u32(region.isa_version, 1, 1);
  if (region.target_triple !== 'aarch64-linux-android26' ||
      typeof region.region_name !== 'string' || !NAME.test(region.region_name) ||
      !['session', 'lease', 'operation'].includes(region.mode)) fail('invalid_region');
  const size = u32(region.bytecode_size, 1, MAX_BYTECODE);
  const opcodeCount = u32(region.opcode_count, 1, 256);
  if (opcodeCount !== FOUNDATION_VM_LAYOUTS.length) fail('descriptor_mismatch');
  for (const key of ['engine_abi_hash', 'call_abi_hash', 'layout_hash',
    'region_content_hash', 'region_id']) hash(region[key]);
  if (region.engine_abi_hash !== FOUNDATION_ENGINE_ABI_HASH) fail('engine_abi_mismatch');
  if (!Array.isArray(region.register_counts) || !region.register_counts.length ||
      region.register_counts.length !== 4) fail('invalid_register_counts');
  for (const count of region.register_counts) u32(count, 0, 65535);
  const descriptor = region.static_decode_descriptor;
  closed(descriptor, DESCRIPTOR_FIELDS);
  u32(descriptor.decode_salt);
  u32(descriptor.isa_version, 1, 1);
  hash(descriptor.layout_hash);
  hash(descriptor.operand_encoding_hash);
  if (descriptor.isa_version !== region.isa_version || descriptor.layout_hash !== region.layout_hash)
    fail('descriptor_mismatch');
  const bytecode = decodeBytecode(region.canonical_bc, size);
  if (!Array.isArray(region.instruction_offsets) ||
      !Array.isArray(region.logical_opcodes) || !region.instruction_offsets.length ||
      region.instruction_offsets.length !== region.logical_opcodes.length ||
      region.instruction_offsets.length > MAX_BYTECODE) fail('invalid_instructions');

  let previous = -1;
  for (let index = 0; index < region.instruction_offsets.length; ++index) {
    const offset = u32(region.instruction_offsets[index], 0, size - 1);
    const logical = u32(region.logical_opcodes[index], 0, opcodeCount - 1);
    if (offset <= previous || logical >= FOUNDATION_VM_LAYOUTS.length) fail('invalid_instructions');
    previous = offset;
  }

  const core = {...region};
  delete core.region_content_hash;
  delete core.region_id;
  const contentHash = sha256(frame('XOVM2/region-content', encodeRegistrationCanonical(
      core, MATERIAL_CODEC_PROFILE.canonicalRegion)));
  if (contentHash !== region.region_content_hash) fail('region_content_hash_mismatch');
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
  const regionId = sha256(frame('XOVM2/region-id', encodeRegistrationCanonical(
      identity, MATERIAL_CODEC_PROFILE.canonicalRegion)));
  if (regionId !== region.region_id) fail('region_id_mismatch');
  return bytecode;
}

const VERIFIED_REGIONS = new WeakMap();

export function verifyRegisteredRegion(regionValue, verifierBytes, options = {}) {
  if (!(verifierBytes instanceof Uint8Array)) fail('invalid_verifier_descriptor');
  let region;
  try { region = structuredClone(regionValue); }
  catch { fail('invalid_schema'); }
  const bytecode = validateCanonicalRegion(region);
  const descriptor = parseVerifierDescriptor(Buffer.from(verifierBytes), region);
  verifyCanonicalBytecodeBytes({
    bytecode,
    instruction_offsets: region.instruction_offsets,
    logical_opcodes: region.logical_opcodes,
    opcode_count: region.opcode_count,
  }, descriptor, options);
  const logicalToPhysical = new Int16Array(256).fill(-1);
  const physicalToLogical = new Int16Array(256).fill(-1);
  for (let index = 0; index < region.instruction_offsets.length; ++index) {
    const logical = region.logical_opcodes[index];
    const physical = descriptor.opcodeMap[logical];
    if ((logicalToPhysical[logical] >= 0 && logicalToPhysical[logical] !== physical) ||
        (physicalToLogical[physical] >= 0 && physicalToLogical[physical] !== logical))
      fail('invalid_opcode_relation');
    logicalToPhysical[logical] = physical;
    physicalToLogical[physical] = logical;
  }
  const capability = Object.freeze(Object.create(null));
  VERIFIED_REGIONS.set(capability, {region, bytecode, logicalToPhysical});
  return capability;
}

function registeredState(capability) {
  const state = capability && typeof capability === 'object'
    ? VERIFIED_REGIONS.get(capability) : undefined;
  if (!state) fail('unverified_registered_region');
  return state;
}

function nextRandomInteger(bound, randomBytes, state) {
  const limit = Math.floor(256 / bound) * bound;
  while (true) {
    if (state.draws === MAX_RANDOM_DRAWS) fail('random_stalled');
    ++state.draws;
    let bytes;
    try { bytes = randomBytes(1); }
    catch { fail('invalid_random'); }
    if (!(bytes instanceof Uint8Array) || bytes.length !== 1) fail('invalid_random');
    const value = bytes[0];
    if (value < limit) return value - Math.floor(value / bound) * bound;
  }
}

function randomPermutation(randomBytes) {
  if (typeof randomBytes !== 'function') fail('invalid_random');
  const values = Array.from({length: 256}, (_, index) => index);
  const state = {draws: 0};
  for (let index = values.length - 1; index > 0; --index) {
    const other = nextRandomInteger(index + 1, randomBytes, state);
    [values[index], values[other]] = [values[other], values[index]];
  }
  return values;
}

function validateBindingForRegion(region, binding) {
  validatePackageBinding(binding);
  if (binding.region_id !== region.region_id || binding.engine_abi_hash !== region.engine_abi_hash ||
      binding.mode !== region.mode) fail('binding_mismatch');
}

export function makePackage(registeredRegion, binding, randomBytes = productionRandomBytes) {
  const validated = registeredState(registeredRegion);
  const {region} = validated;
  validateBindingForRegion(region, binding);
  const permutation = randomPermutation(randomBytes);
  const usedLogical = [...new Set(region.logical_opcodes)].sort((left, right) => left - right);
  const logicalToSession = new Int16Array(256).fill(-1);
  const decodeMap = new Array(256).fill(65535);
  for (let index = 0; index < usedLogical.length; ++index) {
    const logical = usedLogical[index];
    const session = permutation[index];
    logicalToSession[logical] = session;
    decodeMap[session] = validated.logicalToPhysical[logical];
  }
  const encoded = Buffer.from(validated.bytecode);
  for (let index = 0; index < region.instruction_offsets.length; ++index)
    encoded[region.instruction_offsets[index]] = logicalToSession[region.logical_opcodes[index]];
  const packageBinding = {
    build_id: binding.build_id,
    region_id: binding.region_id,
    session_id: binding.session_id,
    generation: binding.generation,
    request_hash: binding.request_hash,
    mode: binding.mode,
    lease_ms: binding.lease_ms,
    engine_abi_hash: binding.engine_abi_hash,
  };
  const descriptor = {
    decode_salt: region.static_decode_descriptor.decode_salt,
    isa_version: region.static_decode_descriptor.isa_version,
    layout_hash: region.static_decode_descriptor.layout_hash,
    operand_encoding_hash: region.static_decode_descriptor.operand_encoding_hash,
  };
  const core = {
    format_version: 1,
    binding: packageBinding,
    bytecode_size: encoded.length,
    encoded_bc: encoded.toString('base64'),
    decode_map: decodeMap,
    static_decode_descriptor: descriptor,
  };
  const digest = packageHash(core);
  return {...core, binding: {...packageBinding, package_hash: digest}};
}

export function validatePackagePairing(registeredRegion, packageValue, expectedBinding) {
  const validated = registeredState(registeredRegion);
  const {region} = validated;
  validateBindingForRegion(region, expectedBinding);
  closed(packageValue, PACKAGE_FIELDS);
  closed(packageValue.binding, MATERIAL_BINDING_FIELDS);
  const expectedMaterialBinding = {...expectedBinding, package_hash: packageValue.binding.package_hash};
  const parsed = parseExecutionPackage(encodeCanonical(packageValue), expectedMaterialBinding);
  if (packageValue.bytecode_size !== region.bytecode_size ||
      packageValue.static_decode_descriptor.decode_salt !== region.static_decode_descriptor.decode_salt ||
      packageValue.static_decode_descriptor.isa_version !== region.static_decode_descriptor.isa_version ||
      packageValue.static_decode_descriptor.layout_hash !== region.static_decode_descriptor.layout_hash ||
      packageValue.static_decode_descriptor.operand_encoding_hash !==
        region.static_decode_descriptor.operand_encoding_hash) fail('package_region_mismatch');

  const expectedMap = new Array(256).fill(65535);
  const logicalToSession = new Int16Array(256).fill(-1);
  const sessionToLogical = new Int16Array(256).fill(-1);
  const boundaries = new Uint8Array(Math.ceil(parsed.bytecode.length / 8));
  for (let index = 0; index < region.instruction_offsets.length; ++index) {
    const offset = region.instruction_offsets[index];
    const logical = region.logical_opcodes[index];
    const session = parsed.bytecode[offset];
    if ((logicalToSession[logical] >= 0 && logicalToSession[logical] !== session) ||
        (sessionToLogical[session] >= 0 && sessionToLogical[session] !== logical) ||
        parsed.decode_map[session] !== validated.logicalToPhysical[logical])
      fail('package_pairing_mismatch');
    logicalToSession[logical] = session;
    sessionToLogical[session] = logical;
    expectedMap[session] = validated.logicalToPhysical[logical];
    boundaries[offset >> 3] |= 1 << (offset & 7);
  }
  for (let index = 0; index < 256; ++index)
    if (parsed.decode_map[index] !== expectedMap[index]) fail('package_pairing_mismatch');
  for (let index = 0; index < parsed.bytecode.length; ++index) {
    if (!(boundaries[index >> 3] & (1 << (index & 7))) &&
        parsed.bytecode[index] !== validated.bytecode[index]) fail('package_pairing_mismatch');
  }
  return packageValue;
}
