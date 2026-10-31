import {createHash} from 'node:crypto';
import {decodeCanonical, encodeCanonical, fail, readU64, MAX_BYTECODE, MAX_B64} from '../../cloud/material_v2/codec.mjs';

export function frame(label, ...parts) {
  if (typeof label !== 'string' || !/^[\x20-\x7e]+$/.test(label)) fail('invalid_label');
  const pieces = [Buffer.from(label + '\0', 'ascii')];
  for (const part of parts) {
    if (!(part instanceof Uint8Array) || part.length > 0xffffffff) fail('invalid_frame');
    const size = Buffer.alloc(4);
    size.writeUInt32BE(part.length);
    pieces.push(size, part);
  }
  return Buffer.concat(pieces);
}

export function packageHash(packageValue) {
  const binding = {...packageValue.binding};
  delete binding.package_hash;
  return createHash('sha256').update(frame('XOVM2/package',
    encodeCanonical({...packageValue, binding}))).digest('hex');
}

function closed(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some(k => !Object.hasOwn(value, k))) fail('invalid_schema');
}
function u32(value, min = 0, max = 4294967295) {
  if (!Number.isInteger(value) || Object.is(value, -0) || value < min || value > max) fail('invalid_u32');
  return value;
}
function hash(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('invalid_hash');
}
const packageBindingFields = ['build_id', 'region_id', 'session_id', 'generation', 'request_hash',
  'mode', 'lease_ms', 'engine_abi_hash'];
const bindingFields = [...packageBindingFields, 'package_hash'];

function validateBindingValues(binding) {
  for (const key of ['build_id', 'region_id', 'session_id', 'request_hash', 'engine_abi_hash']) hash(binding[key]);
  if (binding.session_id === '0'.repeat(64)) fail('invalid_session');
  if (readU64(binding.generation) === 0n) fail('invalid_generation');
  if (binding.mode !== 'session' && binding.mode !== 'lease') fail('invalid_mode');
  u32(binding.lease_ms, binding.mode === 'session' ? 0 : 1, binding.mode === 'session' ? 0 : 120000);
  return binding;
}

export function validatePackageBinding(binding) {
  closed(binding, packageBindingFields);
  return validateBindingValues(binding);
}

export function validateMaterialBinding(binding) {
  closed(binding, bindingFields);
  hash(binding.package_hash);
  return validateBindingValues(binding);
}

export function decodeBytecode(text, size) {
  if (typeof text !== 'string' || text.length > MAX_B64 || text.length % 4 !== 0 || !text.length) fail('invalid_base64');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const padding = text.endsWith('==') ? 2 : text.endsWith('=') ? 1 : 0;
  const end = text.length - padding;
  for (let i = 0; i < end; ++i) if (alphabet.indexOf(text[i]) < 0) fail('invalid_base64');
  if ((padding === 2 && (alphabet.indexOf(text[end - 1]) & 15)) ||
      (padding === 1 && (alphabet.indexOf(text[end - 1]) & 3))) fail('invalid_base64');
  if (3 * (text.length / 4) - padding !== size) fail('bytecode_size_mismatch');
  const result = Buffer.from(text, 'base64');
  if (result.length !== size || result.toString('base64') !== text) fail('invalid_base64');
  return result;
}

// 仅结构结果；没有 install、认证标志或 VerifiedPackage 转换入口。
export function parseExecutionPackage(bytes, expectedBinding) {
  const p = decodeCanonical(bytes);
  closed(p, ['format_version', 'binding', 'bytecode_size', 'encoded_bc', 'decode_map', 'static_decode_descriptor']);
  u32(p.format_version, 1, 1);
  validateMaterialBinding(p.binding);
  validateMaterialBinding(expectedBinding);
  const size = u32(p.bytecode_size, 1, MAX_BYTECODE);
  const d = p.static_decode_descriptor;
  closed(d, ['decode_salt', 'isa_version', 'layout_hash', 'operand_encoding_hash']);
  u32(d.decode_salt);
  u32(d.isa_version, 1, 1);
  hash(d.layout_hash);
  hash(d.operand_encoding_hash);
  if (!Array.isArray(p.decode_map) || p.decode_map.length !== 256) fail('invalid_map');
  const seen = new Set();
  for (const op of p.decode_map) {
    u32(op, 0, 65535);
    if (op === 65535) continue;
    if (op > 255 || seen.has(op)) fail('invalid_map');
    seen.add(op);
  }
  if (!seen.size) fail('invalid_map');
  const decoded = decodeBytecode(p.encoded_bc, size);
  if (packageHash(p) !== p.binding.package_hash) fail('package_hash_mismatch');
  for (const key of bindingFields) if (p.binding[key] !== expectedBinding[key]) fail('binding_mismatch');
  return {binding: p.binding, bytecode: decoded, decode_map: p.decode_map, static_decode_descriptor: d};
}
