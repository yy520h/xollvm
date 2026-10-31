#!/usr/bin/env node
import {createHash, randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {
  createReadStream, createWriteStream,
} from 'node:fs';
import {
  lstat, mkdir, open, opendir, readFile, readdir, realpath, rm,
} from 'node:fs/promises';
import {constants} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const MAX_REGION = 192 * 1024 * 1024;
const MAX_REGISTRATION = 512 * 1024 * 1024;
const MAX_MANIFEST = 4 * 1024 * 1024;
const MAX_BYTECODE = 8388608;
const MAX_B64 = 11184812;
const MAX_ITEMS = 8388608;
const MAX_REGIONS = 4096;
const HASH = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const HELPER_NAME = 'xollvm-cloud-material-fs-helper';
const O_CLOEXEC = 0x80000;
const WITNESS_TOKEN = Symbol('verified-stage-witness');
const OUTPUT_MEMBERS = Object.freeze([
  'public-manifest.json', 'registration.private.json',
]);
const HELP = `Usage: xollvm-cloud-material-export --input-dir <absolute-private-dir> --output-dir <new-absolute-dir>

Helper resolution order:
  1. XOVM_MATERIAL_FS_HELPER absolute path
  2. ${HELPER_NAME} sibling beside the running script (installed layout)
  3. ${HELPER_NAME} on PATH

Every helper candidate must be a non-symlink regular executable owned by the
effective user or root and must not be group- or other-writable. Candidate
parent directories must provide the same non-writable trust boundary.
Android execution is bound to the securely opened native ELF through an inherited
/proc/self/fd descriptor; platforms without that execution contract fail closed.
`;

export const MATERIAL_CODEC_PROFILE = Object.freeze({
  canonicalRegion: Object.freeze({name: 'canonical-region', maximum: MAX_REGION}),
  publicManifest: Object.freeze({name: 'public-manifest', maximum: MAX_MANIFEST}),
  privateRegistration: Object.freeze({name: 'private-registration', maximum: MAX_REGISTRATION}),
});

class ExportError extends Error {
  constructor(code, detail = '') {
    super(detail ? `${code} ${detail}` : code);
    this.code = code;
    this.detail = detail;
  }
}

function fail(code, detail = '') { throw new ExportError(code, detail); }

export function frame(label, ...parts) {
  if (typeof label !== 'string' || !/^[\x20-\x7e]+$/.test(label) || label.includes('\0')) fail('invalid_frame');
  const output = [Buffer.from(`${label}\0`, 'ascii')];
  for (const part of parts) {
    if (!(part instanceof Uint8Array) || part.length > 0xffffffff) fail('invalid_frame');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(part.length);
    output.push(length, Buffer.from(part));
  }
  return Buffer.concat(output);
}

function requireProfile(profile) {
  if (!Object.values(MATERIAL_CODEC_PROFILE).includes(profile)) fail('invalid_codec_profile');
  return profile;
}

function arrayLimit(key, profile) {
  if (key === 'instruction_offsets' || key === 'logical_opcodes') return MAX_ITEMS;
  if (key === 'regions') return MAX_REGIONS;
  if (key === 'register_counts') return 32;
  return 256;
}

function canonicalPreflight(bytes, profile) {
  requireProfile(profile);
  if (!(bytes instanceof Uint8Array) || bytes.length > profile.maximum) fail('size_limit');
  let position = 0;
  const at = () => bytes[position];
  const take = expected => {
    if (at() !== expected) fail('invalid_canonical');
    ++position;
  };
  function string(limit, key = false) {
    take(34);
    const start = position;
    let count = 0;
    while (position < bytes.length && at() !== 34) {
      if (++count > limit) fail('string_limit');
      let value = bytes[position++];
      if (value < 32 || value > 126) fail('invalid_ascii');
      if (value === 92) {
        value = bytes[position++];
        if (key || (value !== 34 && value !== 92)) fail('invalid_canonical');
      }
    }
    const end = position;
    take(34);
    return Buffer.from(bytes.subarray(start, end)).toString('ascii');
  }
  function value(depth, owner = '') {
    if (depth > 8) fail('depth_limit');
    const first = at();
    if (first === 123) {
      ++position;
      let count = 0;
      let previous = '';
      if (at() === 125) { ++position; return; }
      while (true) {
        if (++count > 40) fail('object_limit');
        const key = string(64, true);
        if (!/^[a-z][a-z0-9_]{0,63}$/.test(key) || key <= previous) fail('invalid_key_order');
        previous = key;
        take(58);
        value(depth + 1, key);
        if (at() === 125) { ++position; break; }
        take(44);
      }
      return;
    }
    if (first === 91) {
      ++position;
      let count = 0;
      if (at() === 93) { ++position; return; }
      while (true) {
        if (++count > arrayLimit(owner, profile)) fail('array_limit');
        value(depth + 1);
        if (at() === 93) { ++position; break; }
        take(44);
      }
      return;
    }
    if (first === 34) {
      string(owner === 'canonical_bc' && profile !== MATERIAL_CODEC_PROFILE.publicManifest ? MAX_B64 : 256);
      return;
    }
    if (first >= 48 && first <= 57) {
      const start = position;
      let number = 0;
      while (at() >= 48 && at() <= 57) {
        if (position - start === 10) fail('number_limit');
        number = number * 10 + bytes[position++] - 48;
      }
      if (position - start > 1 && first === 48) fail('invalid_canonical');
      if (number > 0xffffffff) fail('invalid_u32');
      return;
    }
    const word = first === 116 ? 'true' : first === 102 ? 'false' : '';
    if (!word) fail('invalid_canonical');
    for (const character of word) take(character.charCodeAt(0));
  }
  value(1);
  if (position !== bytes.length) fail('invalid_canonical');
}

export function encodeRegistrationCanonical(value, profile) {
  requireProfile(profile);
  if (profile === MATERIAL_CODEC_PROFILE.privateRegistration) fail('streaming_required');
  const chunks = [];
  let currentChunk = '';
  let length = 0;
  const put = text => {
    length += Buffer.byteLength(text, 'ascii');
    if (length > profile.maximum) fail('size_limit');
    while (text.length) {
      const available = 64 * 1024 - currentChunk.length;
      currentChunk += text.slice(0, available);
      text = text.slice(available);
      if (currentChunk.length === 64 * 1024) {
        chunks.push(currentChunk);
        currentChunk = '';
      }
    }
  };
  function write(current, depth, owner = '') {
    if (depth > 8) fail('depth_limit');
    if (typeof current === 'string') {
      const limit = owner === 'canonical_bc' && profile !== MATERIAL_CODEC_PROFILE.publicManifest ? MAX_B64 : 256;
      if (current.length > limit || /[^\x20-\x7e]/.test(current)) fail('invalid_ascii');
      put(`"${current.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`);
      return;
    }
    if (typeof current === 'number') {
      if (!Number.isInteger(current) || Object.is(current, -0) || current < 0 || current > 0xffffffff) fail('invalid_u32');
      put(String(current));
      return;
    }
    if (typeof current === 'boolean') { put(current ? 'true' : 'false'); return; }
    if (!current || typeof current !== 'object') fail('invalid_type');
    const array = Array.isArray(current);
    if (!array && Object.getPrototypeOf(current) !== Object.prototype && Object.getPrototypeOf(current) !== null) fail('invalid_object');
    const keys = array ? Array.from({length: current.length}, (_, index) => String(index)) : Object.keys(current).sort();
    if (keys.length > (array ? arrayLimit(owner, profile) : 40)) fail(array ? 'array_limit' : 'object_limit');
    if (array && Object.keys(current).length !== current.length) fail('invalid_array');
    put(array ? '[' : '{');
    for (let index = 0; index < keys.length; ++index) {
      const key = keys[index];
      if (!Object.hasOwn(current, key)) fail('invalid_array');
      if (index) put(',');
      if (!array) {
        if (!/^[a-z][a-z0-9_]{0,63}$/.test(key)) fail('invalid_key');
        put(`"${key}":`);
      }
      write(current[key], depth + 1, array ? '' : key);
    }
    put(array ? ']' : '}');
  }
  write(value, 1);
  if (currentChunk) chunks.push(currentChunk);
  const bytes = Buffer.from(chunks.join(''), 'ascii');
  canonicalPreflight(bytes, profile);
  return bytes;
}

function u32(value, minimum = 0, maximum = 0xffffffff) {
  if (!Number.isInteger(value) || Object.is(value, -0) || value < minimum || value > maximum) fail('invalid_u32');
  return value;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function framedHash(label, value, profile) {
  return sha256(frame(label, encodeRegistrationCanonical(value, profile)));
}

const coreFields = [
  'format_version', 'isa_version', 'target_triple', 'region_name', 'mode',
  'canonical_bc', 'bytecode_size', 'instruction_offsets', 'logical_opcodes',
  'opcode_count', 'engine_abi_hash', 'register_counts', 'call_abi_hash',
  'layout_hash', 'static_decode_descriptor',
];
const regionFields = [...coreFields, 'region_content_hash', 'region_id'];

class StreamCursor {
  constructor(source, spool, maximum) {
    this.source = source;
    this.spool = spool;
    this.maximum = maximum;
    this.position = 0;
    this.chunk = Buffer.alloc(0);
    this.index = 0;
  }

  async start() {
    this.output = createWriteStream(this.spool, {flags: 'wx', mode: 0o600});
    this.iterator = this.source.createReadStream({autoClose: false, highWaterMark: 64 * 1024})
        [Symbol.asyncIterator]();
    await this.fill();
  }

  async fill() {
    const next = await this.iterator.next();
    if (next.done) {
      this.chunk = Buffer.alloc(0);
      this.index = 0;
      return false;
    }
    this.chunk = Buffer.from(next.value);
    this.index = 0;
    if (this.position + this.chunk.length > this.maximum) fail('region_size_limit');
    if (!this.output.write(this.chunk)) await once(this.output, 'drain');
    return true;
  }

  async peek() {
    while (this.index === this.chunk.length && await this.fill()) {}
    return this.index === this.chunk.length ? -1 : this.chunk[this.index];
  }

  async take(expected = undefined) {
    const value = await this.peek();
    if (value < 0 || (expected !== undefined && value !== expected)) fail('invalid_canonical');
    ++this.index;
    ++this.position;
    return value;
  }

  async finish() {
    if (await this.peek() !== -1) fail('invalid_canonical');
    this.output.end();
    await once(this.output, 'finish');
  }

  async abort() {
    this.output?.destroy();
    await this.iterator?.return?.();
  }
}

async function parseString(cursor, limit, pattern = undefined) {
  await cursor.take(34);
  let result = '';
  while (await cursor.peek() !== 34) {
    let value = await cursor.take();
    if (value < 32 || value > 126 || result.length === limit) fail('invalid_ascii');
    if (value === 92) {
      value = await cursor.take();
      if (value !== 34 && value !== 92) fail('invalid_canonical');
    }
    result += String.fromCharCode(value);
  }
  await cursor.take(34);
  if (pattern && !pattern.test(result)) fail('invalid_schema');
  return result;
}

async function parseU32(cursor, minimum = 0, maximum = 0xffffffff) {
  const first = await cursor.peek();
  if (first < 48 || first > 57) fail('invalid_u32');
  let digits = '';
  while (await cursor.peek() >= 48 && await cursor.peek() <= 57) {
    if (digits.length === 10) fail('invalid_u32');
    digits += String.fromCharCode(await cursor.take());
  }
  if (digits.length > 1 && digits[0] === '0') fail('invalid_canonical');
  const value = Number(digits);
  return u32(value, minimum, maximum);
}

async function writeBuffer(handle, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const {bytesWritten} = await handle.write(bytes, offset, bytes.length - offset);
    if (!bytesWritten) fail('export_io');
    offset += bytesWritten;
  }
}

async function parseU32Array(cursor, filename, maximum = 0xffffffff) {
  const handle = await open(filename, 'wx', 0o600);
  let count = 0;
  let previous = -1;
  try {
    await cursor.take(91);
    if (await cursor.peek() === 93) fail('invalid_instructions');
    const output = Buffer.allocUnsafe(64 * 1024);
    let used = 0;
    while (true) {
      if (++count > MAX_ITEMS) fail('array_limit');
      const value = await parseU32(cursor, 0, maximum);
      if (value <= previous) fail('invalid_instructions');
      previous = value;
      output.writeUInt32LE(value, used);
      used += 4;
      if (used === output.length) {
        await writeBuffer(handle, output);
        used = 0;
      }
      if (await cursor.peek() === 93) break;
      await cursor.take(44);
    }
    await cursor.take(93);
    if (used) await writeBuffer(handle, output.subarray(0, used));
    await handle.sync();
  } finally { await handle.close(); }
  return count;
}

async function parseOpcodeArray(cursor, filename, maximum) {
  const handle = await open(filename, 'wx', 0o600);
  let count = 0;
  try {
    await cursor.take(91);
    if (await cursor.peek() === 93) fail('invalid_instructions');
    const output = Buffer.allocUnsafe(64 * 1024);
    let used = 0;
    while (true) {
      if (++count > MAX_ITEMS) fail('array_limit');
      output[used++] = await parseU32(cursor, 0, maximum);
      if (used === output.length) {
        await writeBuffer(handle, output);
        used = 0;
      }
      if (await cursor.peek() === 93) break;
      await cursor.take(44);
    }
    await cursor.take(93);
    if (used) await writeBuffer(handle, output.subarray(0, used));
    await handle.sync();
  } finally { await handle.close(); }
  return count;
}

async function parseSmallU32Array(cursor, maximum, limit) {
  const values = [];
  await cursor.take(91);
  if (await cursor.peek() === 93) fail('invalid_schema');
  while (true) {
    if (values.length === limit) fail('array_limit');
    values.push(await parseU32(cursor, 0, maximum));
    if (await cursor.peek() === 93) break;
    await cursor.take(44);
  }
  await cursor.take(93);
  return values;
}

async function parseBase64ToFile(cursor, filename) {
  const handle = await open(filename, 'wx', 0o600);
  let encoded = 0;
  let decoded = 0;
  let encodedChunk = '';
  let paddingSeen = false;
  try {
    await cursor.take(34);
    while (await cursor.peek() !== 34) {
      const value = await cursor.take();
      if (!((value >= 65 && value <= 90) || (value >= 97 && value <= 122) ||
            (value >= 48 && value <= 57) || value === 43 || value === 47 || value === 61) ||
          ++encoded > MAX_B64) fail('invalid_base64');
      if (paddingSeen && value !== 61) fail('invalid_base64');
      paddingSeen ||= value === 61;
      encodedChunk += String.fromCharCode(value);
      if (encodedChunk.length === 64 * 1024) {
        if (encodedChunk.includes('=') && await cursor.peek() !== 34) fail('invalid_base64');
        const bytes = Buffer.from(encodedChunk, 'base64');
        if (bytes.toString('base64') !== encodedChunk || decoded + bytes.length > MAX_BYTECODE)
          fail('invalid_base64');
        await writeBuffer(handle, bytes);
        decoded += bytes.length;
        encodedChunk = '';
      }
    }
    await cursor.take(34);
    if (!encoded || encoded % 4) fail('invalid_base64');
    if (encodedChunk) {
      const bytes = Buffer.from(encodedChunk, 'base64');
      if (bytes.toString('base64') !== encodedChunk || decoded + bytes.length > MAX_BYTECODE)
        fail('invalid_base64');
      await writeBuffer(handle, bytes);
      decoded += bytes.length;
    }
    await handle.sync();
  } finally { await handle.close(); }
  return decoded;
}

async function parseDescriptor(cursor) {
  const result = {};
  const fields = ['decode_salt', 'isa_version', 'layout_hash', 'operand_encoding_hash'];
  await cursor.take(123);
  for (let index = 0; index < fields.length; ++index) {
    if (index) await cursor.take(44);
    if (await parseString(cursor, 64, /^[a-z][a-z0-9_]*$/) !== fields[index]) fail('invalid_schema');
    await cursor.take(58);
    result[fields[index]] = fields[index].endsWith('hash')
      ? await parseString(cursor, 64, HASH)
      : await parseU32(cursor);
  }
  await cursor.take(125);
  return result;
}

async function hashFileRanges(label, filename, ranges) {
  let length = 2;
  for (const [field, start, end] of ranges) {
    length += (length > 2 ? 1 : 0) + field.length + 3 + end - start;
  }
  const framedLength = Buffer.alloc(4);
  framedLength.writeUInt32BE(length);
  const digest = createHash('sha256').update(`${label}\0`, 'ascii').update(framedLength).update('{');
  const handle = await open(filename, 'r');
  try {
    const buffer = Buffer.allocUnsafe(64 * 1024);
    for (let index = 0; index < ranges.length; ++index) {
      const [field, start, end] = ranges[index];
      if (index) digest.update(',');
      digest.update(`"${field}":`, 'ascii');
      for (let position = start; position < end;) {
        const size = Math.min(buffer.length, end - position);
        const {bytesRead} = await handle.read(buffer, 0, size, position);
        if (bytesRead !== size) fail('private_input_changed');
        digest.update(buffer.subarray(0, bytesRead));
        position += bytesRead;
      }
    }
  } finally { await handle.close(); }
  digest.update('}');
  return digest.digest('hex');
}

async function parseCanonicalRegion(source, spoolBase, expectedSize) {
  const raw = `${spoolBase}.json`;
  const bytecodeFile = `${spoolBase}.bc`;
  const offsetsFile = `${spoolBase}.offsets`;
  const opcodesFile = `${spoolBase}.opcodes`;
  const cursor = new StreamCursor(source, raw, MAX_REGION);
  await cursor.start();
  try {
    const sortedFields = [...regionFields].sort();
    const values = {};
    const ranges = [];
    let offsetCount = 0;
    let opcodeCount = 0;
    await cursor.take(123);
    for (let index = 0; index < sortedFields.length; ++index) {
      if (index) await cursor.take(44);
      const field = await parseString(cursor, 64, /^[a-z][a-z0-9_]*$/);
      if (field !== sortedFields[index]) fail('invalid_schema');
      await cursor.take(58);
      const start = cursor.position;
      switch (field) {
      case 'bytecode_size': values[field] = await parseU32(cursor, 1, MAX_BYTECODE); break;
      case 'canonical_bc': values.decodedSize = await parseBase64ToFile(cursor, bytecodeFile); break;
      case 'format_version': values[field] = await parseU32(cursor, 1, 1); break;
      case 'isa_version': values[field] = await parseU32(cursor, 1, 1); break;
      case 'opcode_count': values[field] = await parseU32(cursor, 1, 256); break;
      case 'instruction_offsets': offsetCount = await parseU32Array(cursor, offsetsFile, MAX_BYTECODE - 1); break;
      case 'logical_opcodes': opcodeCount = await parseOpcodeArray(cursor, opcodesFile, 255); break;
      case 'register_counts': values[field] = await parseSmallU32Array(cursor, 65535, 32); break;
      case 'static_decode_descriptor': values[field] = await parseDescriptor(cursor); break;
      case 'region_name': values[field] = await parseString(cursor, 128, NAME); break;
      case 'mode': values[field] = await parseString(cursor, 16, /^(session|lease)$/); break;
      case 'target_triple': values[field] = await parseString(cursor, 64); break;
      default: values[field] = await parseString(cursor, 64, HASH); break;
      }
      if (coreFields.includes(field)) ranges.push([field, start, cursor.position]);
    }
    await cursor.take(125);
    await cursor.finish();
    if (cursor.position !== expectedSize) fail('private_input_changed');
    if (values.target_triple !== 'aarch64-linux-android26' ||
        values.decodedSize !== values.bytecode_size || offsetCount !== opcodeCount || !offsetCount)
      fail('invalid_schema');
    const descriptor = values.static_decode_descriptor;
    if (descriptor.isa_version !== 1 || descriptor.layout_hash !== values.layout_hash)
      fail('descriptor_mismatch');
    const contentHash = await hashFileRanges('XOVM2/region-content', raw, ranges);
    if (contentHash !== values.region_content_hash) fail('region_content_hash_mismatch');
    const identity = {
      format_version: 1,
      region_name: values.region_name,
      region_content_hash: contentHash,
      engine_abi_hash: values.engine_abi_hash,
      call_abi_hash: values.call_abi_hash,
      layout_hash: values.layout_hash,
      mode: values.mode,
      target_triple: values.target_triple,
    };
    if (framedHash('XOVM2/region-id', identity, MATERIAL_CODEC_PROFILE.canonicalRegion) !== values.region_id)
      fail('region_id_mismatch');
    return {
      ...values, raw, bytecodeFile, offsetsFile, opcodesFile,
      instructionCount: offsetCount,
    };
  } catch (error) {
    await cursor.abort();
    throw error;
  }
}

const ROLE = Object.freeze({
  Dst: 0, SrcA: 1, SrcB: 2, SrcC: 3, SrcD: 4, Predicate: 5, Kind: 6,
  Immediate: 7, Pointer: 8, Index: 9, Scale: 10, Target: 11,
  FalseTarget: 12, Callee: 13, ArgCount: 14, CaseCount: 15, Alignment: 16,
});

function registeredLayouts() {
  const layouts = Array.from({length: 0x60});
  const define = (opcode, fields, variable = false) => {
    let canonical = 1;
    layouts[opcode] = {
      size: 1 + fields.reduce((sum, [, width]) => sum + width, 0), variable,
      fields: fields.map(([role, width]) => {
        const field = {role, canonical, width};
        canonical += width;
        return field;
      }),
    };
  };
  for (const opcode of [0x00, 0x33, 0x21])
    define(opcode, [[ROLE.Dst, 1], [ROLE.Immediate, opcode === 0 ? 4 : 8]]);
  for (const opcode of [0x01, 0x22, 0x2c, 0x05, 0x13, 0x06])
    define(opcode, [[ROLE.Dst, 1], [ROLE.SrcA, 1]]);
  for (const opcode of [0x02, 0x17, 0x23])
    define(opcode, [[ROLE.Dst, 1], [ROLE.SrcA, 1], [ROLE.SrcB, 1], [ROLE.Kind, 1]]);
  for (const opcode of [0x03, 0x1a, 0x24, 0x37])
    define(opcode, [[ROLE.Dst, 1], [ROLE.SrcA, 1], [ROLE.SrcB, 1], [ROLE.Predicate, 1]]);
  for (const opcode of [0x04, 0x16, 0x25, 0x2f, 0x30, 0x31, 0x32])
    define(opcode, [[ROLE.Dst, 1], [ROLE.SrcA, 1], [ROLE.Kind, 1]]);
  for (const opcode of [0x1b, 0x1d, 0x07, 0x14, 0x1f, 0x26, 0x2d])
    define(opcode, [[ROLE.Dst, 1], [ROLE.Pointer, 1]]);
  for (const opcode of [0x1c, 0x1e, 0x08, 0x15, 0x20, 0x27, 0x2e])
    define(opcode, [[ROLE.SrcA, 1], [ROLE.Pointer, 1]]);
  for (const opcode of [0x09, 0x19])
    define(opcode, [[ROLE.Dst, 1], [ROLE.Pointer, 1], [ROLE.Index, 1], [ROLE.Scale, 2]]);
  define(0x0a, [[ROLE.Target, 4]]);
  define(0x0b, [[ROLE.Index, 1], [ROLE.Target, 4], [ROLE.FalseTarget, 4]]);
  define(0x0c, []);
  for (const opcode of [0x0d, 0x0e, 0x28]) define(opcode, [[ROLE.SrcA, 1]]);
  define(0x12, [[ROLE.Kind, 1], [ROLE.Dst, 1], [ROLE.Index, 1], [ROLE.SrcA, 1], [ROLE.SrcB, 1]]);
  define(0x29, [[ROLE.Dst, 1], [ROLE.Index, 1], [ROLE.SrcA, 1], [ROLE.SrcB, 1]]);
  for (const opcode of [0x34, 0x35])
    define(opcode, [[ROLE.Dst, 1], [ROLE.SrcA, 1], [ROLE.SrcB, 1], [ROLE.SrcC, 1]]);
  define(0x36, [[ROLE.Dst, 1], [ROLE.SrcA, 1], [ROLE.SrcB, 1], [ROLE.Predicate, 1], [ROLE.SrcC, 1], [ROLE.SrcD, 1]]);
  define(0x0f, [[ROLE.Callee, 1], [ROLE.ArgCount, 1]], true);
  for (const opcode of [0x10, 0x2a, 0x11, 0x2b])
    define(opcode, [[ROLE.Dst, 1], [ROLE.Callee, 1], [ROLE.ArgCount, 1]], true);
  define(0x18, [[ROLE.Index, 1], [ROLE.CaseCount, 2], [ROLE.Target, 4]], true);
  for (let opcode = 0x38; opcode <= 0x49; ++opcode)
    define(opcode, [[ROLE.Dst, 1], [ROLE.SrcA, 1], [ROLE.Immediate, opcode >= 0x41 ? 8 : 4]]);
  for (let opcode = 0x4a; opcode <= 0x59; ++opcode) {
    if (opcode === 0x4c || opcode === 0x4d) continue;
    define(opcode, [[ROLE.Dst, 1], [ROLE.SrcA, 1], [ROLE.SrcB, 1], [ROLE.SrcC, 1]]);
  }
  define(0x4c, [[ROLE.Dst, 1], [ROLE.SrcA, 1], [ROLE.SrcB, 1], [ROLE.Predicate, 1], [ROLE.SrcC, 1], [ROLE.SrcD, 1]]);
  define(0x4d, [[ROLE.Dst, 1], [ROLE.SrcA, 1], [ROLE.SrcB, 1], [ROLE.Predicate, 1]]);
  for (let opcode = 0x5a; opcode <= 0x5f; ++opcode)
    define(opcode, [[ROLE.Dst, 1], [ROLE.Pointer, 1], [ROLE.Index, 1], [ROLE.Kind, 1], [ROLE.Scale, 2], [ROLE.Alignment, 1]]);
  if (layouts.some(layout => !layout)) fail('invalid_verifier_descriptor');
  return layouts;
}

export const FOUNDATION_VM_LAYOUTS = Object.freeze(registeredLayouts().map(layout =>
  Object.freeze({...layout, fields: Object.freeze(layout.fields.map(field => Object.freeze(field)))})));
const REGISTERED_LAYOUTS = FOUNDATION_VM_LAYOUTS;

export function parseVerifierDescriptor(bytes, region) {
  if (!(bytes instanceof Uint8Array) || bytes.length > 65536) fail('invalid_verifier_descriptor');
  let position = 0;
  const take = count => {
    if (count > bytes.length - position) fail('invalid_verifier_descriptor');
    const value = Buffer.from(bytes.subarray(position, position + count));
    position += count;
    return value;
  };
  const readU16 = () => take(2).readUInt16LE();
  const readU32 = () => take(4).readUInt32LE();
  if (!take(8).equals(Buffer.from('XOVMVR1\0', 'ascii')) || readU32() !== 1)
    fail('invalid_verifier_descriptor');
  const targetKey = readU32();
  if (readU16() !== 0x60) fail('invalid_verifier_descriptor');
  const opcodeMap = take(0x60);
  if (new Set(opcodeMap).size !== 0x60 || opcodeMap.some(value => value >= 0x60))
    fail('invalid_verifier_descriptor');
  const callCount = readU16();
  if (callCount > 252) fail('invalid_verifier_descriptor');
  const calls = take(callCount * 2);
  const callArities = Buffer.alloc(callCount);
  const callReturnKinds = Buffer.alloc(callCount);
  for (let index = 0; index < callCount; ++index) {
    callArities[index] = calls[index * 2];
    callReturnKinds[index] = calls[index * 2 + 1];
  }
  if (callArities.some(value => value > 16) || callReturnKinds.some(value => value > 4))
    fail('invalid_verifier_descriptor');
  if (readU16() !== 0x60) fail('invalid_verifier_descriptor');
  const layouts = [];
  let layoutSpec = 'xovm-layout-v2';
  for (let opcode = 0; opcode < 0x60; ++opcode) {
    const size = take(1)[0];
    const variable = take(1)[0];
    const count = take(1)[0];
    const registered = REGISTERED_LAYOUTS[opcode];
    if (size !== registered.size || variable > 1 || Boolean(variable) !== registered.variable ||
        count !== registered.fields.length) fail('invalid_verifier_descriptor');
    const fields = [];
    const occupied = new Uint8Array(size);
    occupied[0] = 1;
    for (let index = 0; index < count; ++index) {
      const raw = take(4);
      const field = {role: raw[0], canonical: raw[1], offset: raw[2], width: raw[3]};
      const expected = registered.fields.find(value => value.role === field.role);
      if (!expected || expected.canonical !== field.canonical || expected.width !== field.width ||
          field.offset === 0 || field.offset + field.width > size ||
          (variable && field.offset !== field.canonical)) fail('invalid_verifier_descriptor');
      for (let byte = 0; byte < field.width; ++byte) {
        if (occupied[field.offset + byte]) fail('invalid_verifier_descriptor');
        occupied[field.offset + byte] = 1;
      }
      fields.push(field);
    }
    if (occupied.some(value => !value) || new Set(fields.map(field => field.role)).size !== fields.length)
      fail('invalid_verifier_descriptor');
    layoutSpec += `|op=${opcode},size=${size},var=${variable}`;
    for (const field of fields)
      layoutSpec += `,field=${field.role}:${field.canonical}:${field.offset}:${field.width}`;
    layouts.push({size, variable: Boolean(variable), fields});
  }
  const callSpec = take(readU32()).toString('ascii');
  const operandSpec = take(readU32()).toString('ascii');
  if (position !== bytes.length || /[^\x20-\x7e]/.test(callSpec + operandSpec) ||
      sha256(Buffer.from(layoutSpec, 'ascii')) !== region.layout_hash ||
      sha256(Buffer.from(callSpec, 'ascii')) !== region.call_abi_hash ||
      sha256(Buffer.from(operandSpec, 'ascii')) !== region.static_decode_descriptor.operand_encoding_hash)
    fail('invalid_verifier_descriptor');
  const callParts = callSpec.split('|slot=');
  if (callParts.shift() !== 'xovm-call-table-v1' || callParts.length !== callCount)
    fail('invalid_verifier_descriptor');
  for (let slot = 0; slot < callParts.length; ++slot) {
    const fields = callParts[slot].split('|');
    if (fields.shift() !== String(slot) ||
        fields.filter(field => field.startsWith('arg=')).length !== callArities[slot])
      fail('invalid_verifier_descriptor');
    const returned = fields.find(field => field.startsWith('ret='))?.slice(4);
    const kind = returned === 'void' ? 0 : returned === 'i32' ? 1 : returned === 'ptr' ? 2 :
      returned === 'i64' ? 3 : returned === 'f32' || returned === 'f64' ? 4 : 0xff;
    if (kind !== callReturnKinds[slot]) fail('invalid_verifier_descriptor');
  }
  const operandParts = new Map();
  for (const part of operandSpec.split('|').slice(1)) {
    const split = part.indexOf('=');
    if (split < 1 || operandParts.has(part.slice(0, split))) fail('invalid_verifier_descriptor');
    operandParts.set(part.slice(0, split), part.slice(split + 1));
  }
  const permutations = [
    ['bin', 0, 13], ['icmp', 32, 10], ['cast', 0, 8], ['fbin', 0, 5],
    ['fcmp', 1, 14], ['cast64', 0, 11], ['fcast', 0, 10], ['select', 0, 3],
    ['opcode', 0, 0x60],
  ];
  if (!operandSpec.startsWith('xovm-operand-encoding-v2|') || operandParts.size !== 11 ||
      operandParts.get('target-format') !== 'xor-le32-v1' ||
      operandParts.get('target-key') !== String(targetKey)) fail('invalid_verifier_descriptor');
  for (const [name, base, count] of permutations) {
    const values = (operandParts.get(name) || '').split(',').map(Number);
    if (values.length !== count || new Set(values).size !== count ||
        values.some(value => !Number.isInteger(value) || value < base || value >= base + count))
      fail('invalid_verifier_descriptor');
    if (name === 'opcode' && !Buffer.from(values).equals(opcodeMap))
      fail('invalid_verifier_descriptor');
  }
  return {targetKey, opcodeMap, callArities, callReturnKinds, layouts};
}

function fieldOffset(layout, role) {
  const field = layout.fields.find(value => value.role === role);
  if (!field) fail('invalid_verifier_descriptor');
  return field.offset;
}

function verifyInstruction(bytecode, offset, logical, descriptor, onTarget) {
  if (logical >= descriptor.layouts.length || bytecode[offset] !== descriptor.opcodeMap[logical])
    fail('invalid_bytecode');
  const layout = descriptor.layouts[logical];
  let size = layout.size;
  if (size > bytecode.length - offset) fail('invalid_bytecode');
  if ([0x0f, 0x10, 0x11, 0x2a, 0x2b].includes(logical)) {
    const callee = bytecode[offset + fieldOffset(layout, ROLE.Callee)];
    const arity = bytecode[offset + fieldOffset(layout, ROLE.ArgCount)];
    const expectedKind = logical === 0x0f ? 0 : logical === 0x10 ? 1 :
      logical === 0x11 ? 2 : logical === 0x2a ? 3 : 4;
    if (arity > 16 || callee >= descriptor.callArities.length ||
        descriptor.callArities[callee] !== arity ||
        descriptor.callReturnKinds[callee] !== expectedKind ||
        arity > bytecode.length - offset - size) fail('invalid_bytecode');
    size += arity;
  } else if (logical === 0x18) {
    const countOffset = offset + fieldOffset(layout, ROLE.CaseCount);
    const cases = bytecode.readUInt16LE(countOffset);
    if (cases > Math.floor((bytecode.length - offset - size) / 8)) fail('invalid_bytecode');
    onTarget(bytecode.readUInt32LE(offset + fieldOffset(layout, ROLE.Target)) ^ descriptor.targetKey);
    for (let item = 0; item < cases; ++item)
      onTarget(bytecode.readUInt32LE(offset + size + item * 8 + 4) ^ descriptor.targetKey);
    size += cases * 8;
  } else if (logical === 0x0a) {
    onTarget(bytecode.readUInt32LE(offset + fieldOffset(layout, ROLE.Target)) ^ descriptor.targetKey);
  } else if (logical === 0x0b) {
    onTarget(bytecode.readUInt32LE(offset + fieldOffset(layout, ROLE.Target)) ^ descriptor.targetKey);
    onTarget(bytecode.readUInt32LE(offset + fieldOffset(layout, ROLE.FalseTarget)) ^ descriptor.targetKey);
  }
  return size;
}

export function verifyCanonicalBytecodeBytes(region, descriptor, options = {}) {
  const bytecode = Buffer.from(region.bytecode);
  const offsets = region.instruction_offsets;
  const opcodes = region.logical_opcodes;
  if (!Array.isArray(offsets) || !Array.isArray(opcodes) || !offsets.length ||
      offsets.length !== opcodes.length || region.opcode_count !== descriptor.layouts.length)
    fail('invalid_bytecode');
  const starts = new Uint8Array(Math.ceil(bytecode.length / 8));
  let previous = -1;
  for (const offset of offsets) {
    if (!Number.isInteger(offset) || offset <= previous || offset >= bytecode.length)
      fail('invalid_bytecode');
    starts[offset >> 3] |= 1 << (offset & 7);
    previous = offset;
  }
  let expected = 0;
  let operations = 0;
  const validateTarget = target => {
    ++operations;
    if (target >= bytecode.length || !(starts[target >> 3] & (1 << (target & 7))))
      fail('invalid_bytecode');
  };
  for (let index = 0; index < offsets.length; ++index) {
    const offset = offsets[index];
    const logical = opcodes[index];
    if (offset !== expected || !Number.isInteger(logical) || logical < 0 ||
        logical >= region.opcode_count) fail('invalid_bytecode');
    expected += verifyInstruction(bytecode, offset, logical, descriptor, validateTarget);
    if (expected > bytecode.length) fail('invalid_bytecode');
  }
  if (expected !== bytecode.length) fail('invalid_bytecode');
  options.probe?.({kind: 'target_lookup_operations', operations});
  return {operations};
}

async function verifyCanonicalBytecode(region, descriptor, targetFile) {
  const bytecode = await readFile(region.bytecodeFile);
  if (bytecode.length !== region.bytecode_size) fail('invalid_bytecode');
  const offsets = await open(region.offsetsFile, 'r');
  const opcodes = await open(region.opcodesFile, 'r');
  const targets = await open(targetFile, 'wx', 0o600);
  const starts = new Uint8Array(Math.ceil(bytecode.length / 8));
  region.probe?.({kind: 'verification_workspace',
                  bytecodeBytes: bytecode.length, boundaryBytes: starts.length});
  const offsetBuffer = Buffer.allocUnsafe(64 * 1024);
  const opcodeBuffer = Buffer.allocUnsafe(16 * 1024);
  const targetBuffer = Buffer.allocUnsafe(64 * 1024);
  let targetUsed = 0;
  let expected = 0;
  const writeTarget = async value => {
    targetBuffer.writeUInt32LE(value >>> 0, targetUsed);
    targetUsed += 4;
    if (targetUsed === targetBuffer.length) {
      await writeBuffer(targets, targetBuffer);
      targetUsed = 0;
    }
  };
  try {
    for (let base = 0; base < region.instructionCount; base += opcodeBuffer.length) {
      const count = Math.min(opcodeBuffer.length, region.instructionCount - base);
      const offsetRead = await offsets.read(offsetBuffer, 0, count * 4, base * 4);
      const opcodeRead = await opcodes.read(opcodeBuffer, 0, count, base);
      if (offsetRead.bytesRead !== count * 4 || opcodeRead.bytesRead !== count)
        fail('invalid_bytecode');
      for (let index = 0; index < count; ++index) {
        const offset = offsetBuffer.readUInt32LE(index * 4);
        const logical = opcodeBuffer[index];
        if (region.opcode_count !== descriptor.layouts.length || offset !== expected ||
            logical >= region.opcode_count) fail('invalid_bytecode');
        starts[offset >> 3] |= 1 << (offset & 7);
        const pendingTargets = [];
        const size = verifyInstruction(bytecode, offset, logical, descriptor,
            target => pendingTargets.push(target));
        for (const target of pendingTargets) await writeTarget(target);
        expected += size;
        if (expected > bytecode.length) fail('invalid_bytecode');
      }
    }
    if (expected !== bytecode.length) fail('invalid_bytecode');
    if (targetUsed) await writeBuffer(targets, targetBuffer.subarray(0, targetUsed));
    await targets.sync();
  } finally {
    await Promise.allSettled([offsets.close(), opcodes.close(), targets.close()]);
  }
  const handle = await open(targetFile, 'r');
  try {
    let position = 0;
    while (true) {
      const {bytesRead} = await handle.read(targetBuffer, 0, targetBuffer.length, position);
      if (!bytesRead) break;
      if (bytesRead % 4) fail('invalid_bytecode');
      for (let offset = 0; offset < bytesRead; offset += 4) {
        const target = targetBuffer.readUInt32LE(offset);
        if (target >= bytecode.length || !(starts[target >> 3] & (1 << (target & 7))))
          fail('invalid_bytecode');
      }
      position += bytesRead;
    }
  } finally { await handle.close(); }
}

async function requireSecureAbsoluteDirectory(directory, code, privateMode = true) {
  if (!path.isAbsolute(directory) || path.resolve(directory) !== directory) fail(code);
  let info;
  try { info = await lstat(directory); }
  catch { fail(code); }
  if (!info.isDirectory() || info.isSymbolicLink()) fail(code);
  if (privateMode && (info.mode & 0o777) !== 0o700) fail('private_mode');
  let resolved;
  try { resolved = await realpath(directory); }
  catch { fail(code); }
  if (resolved !== directory) fail(code);
}

async function readPrivateInput(input, spool, options) {
  await requireSecureAbsoluteDirectory(input, 'invalid_input_dir');
  let total = 0;
  let softwareId;
  const byId = new Map();
  const byName = new Map();
  const pending = [];
  const entries = [];
  const rootDirectory = await opendir(input);
  for await (const entry of rootDirectory) {
    if (entry.name === '.xovm-publish.lock') continue;
    if (entries.length === MAX_REGIONS) fail('invalid_registration');
    entries.push(entry);
  }
  if (!entries.length) fail('empty_input');
  let fileCount = 0;
  for (const entry of entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
    if (!entry.isDirectory() || entry.isSymbolicLink() || !/^[0-9a-f]{64}\.materials$/.test(entry.name)) fail('invalid_private_entry');
    const bundle = path.join(input, entry.name);
    const bundleReal = await realpath(bundle);
    if (bundleReal !== bundle) fail('invalid_private_entry');
    const bundleInfo = await lstat(bundle);
    if ((bundleInfo.mode & 0o777) !== 0o700) fail('private_mode');
    const files = [];
    const bundleDirectory = await opendir(bundle);
    for await (const file of bundleDirectory) {
      if (++fileCount > MAX_REGIONS * 3) fail('invalid_registration');
      files.push(file);
    }
    for (const file of files.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
      if (!file.isFile() || file.isSymbolicLink()) fail('invalid_private_entry');
      const filename = path.join(bundle, file.name);
      const info = await lstat(filename);
      if ((info.mode & 0o777) !== 0o600) fail('private_mode');
      total += info.size;
      if (total > MAX_REGISTRATION) fail('registration_size_limit');
      pending.push({filename, name: file.name, size: info.size, dev: info.dev, ino: info.ino});
    }
  }
  const descriptors = new Map();
  for (const file of pending) {
    const match = /^([0-9a-f]{64})\.verifier$/.exec(file.name);
    if (!match) continue;
    if (file.size > 65536) fail('invalid_verifier_descriptor');
    const handle = await open(file.filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const info = await handle.stat();
      if (!info.isFile() || (info.mode & 0o777) !== 0o600 || info.size !== file.size ||
          info.dev !== file.dev || info.ino !== file.ino) fail('private_input_changed');
      const bytes = await handle.readFile();
      if (bytes.length !== file.size) fail('private_input_changed');
      const descriptorHash = sha256(bytes);
      const prior = descriptors.get(match[1]);
      if (prior && prior.hash !== descriptorHash) fail('invalid_verifier_descriptor');
      if (!prior) descriptors.set(match[1], {file, hash: descriptorHash});
    } finally { await handle.close(); }
  }
  let spoolIndex = 0;
  for (const file of pending) {
      if (file.name === 'software-id') {
        const handle = await open(file.filename, constants.O_RDONLY | constants.O_NOFOLLOW);
        let current;
        try {
          const info = await handle.stat();
          if (!info.isFile() || (info.mode & 0o777) !== 0o600 || info.size !== file.size ||
              info.dev !== file.dev || info.ino !== file.ino) fail('private_input_changed');
          current = await handle.readFile('ascii');
          const after = await handle.stat();
          if (after.size !== file.size || after.dev !== file.dev || after.ino !== file.ino)
            fail('private_input_changed');
        } finally { await handle.close(); }
        if (!ID.test(current) || (softwareId !== undefined && softwareId !== current)) fail('software_id_mismatch');
        softwareId = current;
        continue;
      }
      if (file.name.endsWith('.verifier')) continue;
      const match = /^([0-9a-f]{64})\.([0-9a-f]{64})\.([0-9a-f]{64})\.region\.json$/.exec(file.name);
      if (!match) fail('invalid_private_entry');
      if (file.size > MAX_REGION) fail('region_size_limit');
      const handle = await open(file.filename, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const info = await handle.stat();
        if (!info.isFile() || (info.mode & 0o777) !== 0o600 || info.size !== file.size ||
            info.dev !== file.dev || info.ino !== file.ino) fail('private_input_changed');
        const region = await parseCanonicalRegion(handle,
            path.join(spool, `region-${spoolIndex++}`), file.size);
        const after = await handle.stat();
        if (after.size !== file.size || after.dev !== file.dev || after.ino !== file.ino)
          fail('private_input_changed');
        if (match[1] !== sha256(Buffer.from(region.region_name, 'ascii')) ||
            match[2] !== region.region_id || match[3] !== region.region_content_hash)
          fail('filename_identity_mismatch');
        const descriptorMetadata = descriptors.get(region.region_id);
        if (!descriptorMetadata) fail('invalid_verifier_descriptor');
        const descriptorHandle = await open(descriptorMetadata.file.filename,
            constants.O_RDONLY | constants.O_NOFOLLOW);
        let descriptorBytes;
        try {
          const info = await descriptorHandle.stat();
          if (!info.isFile() || (info.mode & 0o777) !== 0o600 ||
              info.size !== descriptorMetadata.file.size ||
              info.dev !== descriptorMetadata.file.dev || info.ino !== descriptorMetadata.file.ino)
            fail('private_input_changed');
          descriptorBytes = await descriptorHandle.readFile();
          const after = await descriptorHandle.stat();
          if (after.size !== descriptorMetadata.file.size ||
              after.dev !== descriptorMetadata.file.dev || after.ino !== descriptorMetadata.file.ino)
            fail('private_input_changed');
        } finally { await descriptorHandle.close(); }
        const descriptor = parseVerifierDescriptor(descriptorBytes, region);
        region.probe = options.probe;
        await verifyCanonicalBytecode(region, descriptor,
            path.join(spool, `targets-${spoolIndex}`));
        delete region.probe;
        options.probe?.({kind: 'region_spooled', bytes: file.size});
        const rawHash = await new Promise((resolve, reject) => {
          const digest = createHash('sha256');
          const stream = createReadStream(region.raw);
          stream.on('data', chunk => digest.update(chunk));
          stream.on('error', reject);
          stream.on('end', () => resolve(digest.digest('hex')));
        });
        const priorId = byId.get(region.region_id);
        if (priorId && priorId.rawHash !== rawHash) fail('region_identity_conflict');
        const priorName = byName.get(region.region_name);
        if (priorName && priorName.region_content_hash !== region.region_content_hash)
          fail('region_name_conflict',
              `name=${region.region_name} old_id=${priorName.region_id} old_hash=${priorName.region_content_hash} new_id=${region.region_id} new_hash=${region.region_content_hash}`);
        const retained = {
          region_id: region.region_id,
          region_content_hash: region.region_content_hash,
          region_name: region.region_name,
          mode: region.mode,
          engine_abi_hash: region.engine_abi_hash,
          call_abi_hash: region.call_abi_hash,
          layout_hash: region.layout_hash,
          raw: region.raw,
        };
        if (!priorId) byId.set(region.region_id, {region: retained, rawHash});
        byName.set(region.region_name, retained);
      } finally { await handle.close(); }
  }
  if (!softwareId || !byId.size || byId.size > MAX_REGIONS) fail('invalid_registration');
  if (descriptors.size !== byId.size) fail('invalid_verifier_descriptor');
  return {softwareId, regions: [...byId.values()].map(value => value.region).sort(
      (left, right) => left.region_id < right.region_id ? -1 : left.region_id > right.region_id ? 1 : 0)};
}

function makeOutputs(softwareId, regions) {
  const publicRegions = regions.map(region => ({
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
  const buildId = framedHash('XOVM2/build-id', core, MATERIAL_CODEC_PROFILE.publicManifest);
  return {
    publicBytes: encodeRegistrationCanonical(
        {...core, build_id: buildId}, MATERIAL_CODEC_PROFILE.publicManifest),
    buildId,
  };
}

async function writePrivateFile(directory, name, bytes) {
  const handle = await open(path.join(directory, name), 'wx', 0o600);
  try {
    await handle.chmod(0o600);
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function writeRegistration(filename, buildId, regions, options) {
  const handle = await open(filename, 'wx', 0o600);
  let total = 0;
  const put = async bytes => {
    if (!(bytes instanceof Uint8Array)) bytes = Buffer.from(bytes, 'ascii');
    total += bytes.length;
    if (total > MAX_REGISTRATION) fail('registration_size_limit');
    await writeBuffer(handle, bytes);
    options.probe?.({kind: 'registration_chunk', bytes: bytes.length});
  };
  try {
    await put(`{"build_id":"${buildId}","format_version":1,"regions":[`);
    for (let index = 0; index < regions.length; ++index) {
      if (index) await put(',');
      const stream = createReadStream(regions[index].raw, {highWaterMark: 64 * 1024});
      for await (const chunk of stream) await put(chunk);
    }
    await put(']}');
    await handle.sync();
  } finally { await handle.close(); }
}

function sameStatIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mode === right.mode && left.uid === right.uid && left.nlink === right.nlink &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

async function validateHelperParents(candidate) {
  const owner = typeof process.geteuid === 'function' ? process.geteuid() : undefined;
  let current = path.dirname(candidate);
  while (true) {
    let info;
    try { info = await lstat(current, {bigint: true}); }
    catch { fail('helper_untrusted'); }
    if (!info.isDirectory() || info.isSymbolicLink() ||
        (Number(info.uid) !== owner && info.uid !== 0n) || (info.mode & 0o022n) !== 0n)
      fail('helper_untrusted');
    if ((Number(info.uid) === owner && (info.mode & 0o077n) === 0n) || current === path.parse(current).root)
      return;
    current = path.dirname(current);
  }
}

async function trustedHelper(candidate, required) {
  let handle;
  try { handle = await open(candidate, constants.O_RDONLY | O_CLOEXEC | constants.O_NOFOLLOW); }
  catch (error) {
    if (error.code === 'ENOENT' && !required) return false;
    fail(error.code === 'ENOENT' ? 'helper_not_found' : 'helper_untrusted');
  }
  try {
    await validateHelperParents(candidate);
    const info = await handle.stat({bigint: true});
    const owner = BigInt(typeof process.geteuid === 'function' ? process.geteuid() : Number(info.uid));
    const magic = Buffer.alloc(4);
    const read = await handle.read(magic, 0, magic.length, 0);
    if (!path.isAbsolute(candidate) || !info.isFile() ||
        (info.uid !== owner && info.uid !== 0n) || (info.mode & 0o022n) !== 0n ||
        (info.mode & 0o111n) === 0n || info.nlink !== 1n || read.bytesRead !== 4 ||
        !magic.equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) fail('helper_untrusted');
    return {candidate, handle};
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function resolveHelper(options) {
  const override = process.env.XOVM_MATERIAL_FS_HELPER;
  if (override !== undefined) {
    if (!path.isAbsolute(override)) fail('helper_untrusted');
    const helper = await trustedHelper(override, true);
    try { if (options.afterHelperOpen) await options.afterHelperOpen(override); }
    catch (error) { await helper.handle.close(); throw error; }
    return helper;
  }
  const sibling = path.join(path.dirname(fileURLToPath(import.meta.url)), HELPER_NAME);
  const siblingHelper = await trustedHelper(sibling, false);
  if (siblingHelper) {
    try { if (options.afterHelperOpen) await options.afterHelperOpen(sibling); }
    catch (error) { await siblingHelper.handle.close(); throw error; }
    return siblingHelper;
  }
  for (const entry of (process.env.PATH || '').split(path.delimiter)) {
    if (!entry) continue;
    const candidate = path.resolve(entry, HELPER_NAME);
    const helper = await trustedHelper(candidate, false);
    if (helper) {
      try { if (options.afterHelperOpen) await options.afterHelperOpen(candidate); }
      catch (error) { await helper.handle.close(); throw error; }
      return helper;
    }
  }
  fail('helper_not_found');
}

async function startLockHelper(roots, options, stageHandle = undefined, recovery = false) {
  const helper = await resolveHelper(options);
  const stdio = ['pipe', 'pipe', 'pipe', helper.handle.fd];
  const env = {...process.env};
  for (const name of [
    'XOVM_HELPER_STAGE_FD', 'XOVM_HELPER_FAULT_AFTER_COMMIT',
    'XOVM_HELPER_FAULT_EXIT_AFTER_COMMIT', 'XOVM_HELPER_FAULT_CLOSE',
    'XOVM_HELPER_FAULT_SWAP_DURING_COMPARE', 'XOVM_HELPER_FAULT_MEMBER_CONTENT',
    'XOVM_HELPER_FAULT_MEMBER_SWAP',
  ]) delete env[name];
  if (stageHandle) {
    env.XOVM_HELPER_STAGE_FD = String(stdio.length);
    stdio.push(stageHandle.fd);
  }
  if (!recovery && options.fault === 'after_commit')
    env.XOVM_HELPER_FAULT_AFTER_COMMIT = '1';
  if (!recovery && ['exit_after_commit', 'swap_during_reconcile',
    'member_content_during_reconcile', 'member_swap_during_reconcile'].includes(options.fault))
    env.XOVM_HELPER_FAULT_EXIT_AFTER_COMMIT = '1';
  if (!recovery && options.fault === 'close_after_commit')
    env.XOVM_HELPER_FAULT_CLOSE = '1';
  if (recovery && options.fault === 'swap_during_reconcile')
    env.XOVM_HELPER_FAULT_SWAP_DURING_COMPARE = '1';
  if (recovery && options.fault === 'member_content_during_reconcile')
    env.XOVM_HELPER_FAULT_MEMBER_CONTENT = '1';
  if (recovery && options.fault === 'member_swap_during_reconcile')
    env.XOVM_HELPER_FAULT_MEMBER_SWAP = '1';
  const child = spawn('/proc/self/fd/3', roots, {
    stdio,
    env,
    shell: false,
  });
  let buffered = '';
  const lines = [];
  const waiters = [];
  let stderr = '';
  let childReported = false;
  let exitedCode;
  let acknowledgedFailure = false;
  const spawnFailed = new Promise(resolve => child.once('error', resolve));
  const outputEnded = new Promise(resolve => child.stdout.once('end', resolve));
  const exited = new Promise(resolve => child.once('close', code => {
    exitedCode = code;
    resolve(code);
  }));
  child.stdin.on('error', () => {});
  child.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); });
  child.stdout.on('data', chunk => {
    buffered += chunk.toString('ascii');
    while (buffered.includes('\n')) {
      const split = buffered.indexOf('\n');
      const line = buffered.slice(0, split);
      buffered = buffered.slice(split + 1);
      if (waiters.length) waiters.shift()(line);
      else lines.push(line);
    }
  });
  try {
    await Promise.race([
      once(child, 'spawn'),
      spawnFailed.then(() => fail('helper_exec_unsupported')),
    ]);
  } finally {
    await helper.handle.close();
  }
  const nextLine = async () => {
    if (lines.length) return lines.shift();
    const line = await Promise.race([
      new Promise(resolve => waiters.push(resolve)),
      exited.then(() => fail('helper_response_lost')),
      spawnFailed.then(() => fail('helper_response_lost')),
      outputEnded.then(() => fail('helper_response_lost')),
    ]);
    if (line.startsWith('ERR ')) {
      childReported = true;
      fail(line.slice(4));
    }
    return line;
  };
  try {
    if (await nextLine() !== 'READY') fail('lock_failed');
  } catch {
    fail('lock_failed');
  }
  const command = async (text, ambiguous = false) => {
    try {
      await new Promise((resolve, reject) => {
        child.stdin.write(`${text}\n`, 'ascii', error => error ? reject(error) : resolve());
      });
      return await nextLine();
    } catch (error) {
      if (ambiguous) {
        if (error instanceof ExportError && error.code !== 'helper_response_lost') throw error;
        fail('helper_response_lost');
      }
      if (error instanceof ExportError && error.code !== 'helper_response_lost') throw error;
      fail('lock_failed');
    }
  };
  return {
    command,
    acknowledgeFailure() { acknowledgedFailure = true; },
    async abort() {
      acknowledgedFailure = true;
      if (exitedCode === undefined) child.kill('SIGKILL');
      await exited;
    },
    async close() {
      if (exitedCode !== undefined) {
        if (exitedCode !== 0 && !childReported && !acknowledgedFailure) fail('lock_failed');
        return;
      }
      child.stdin.end();
      const code = await exited;
      if (code !== 0 && !childReported && !acknowledgedFailure) fail('lock_failed');
    },
  };
}

async function buildStageWitness(stageHandle) {
  const opened = [];
  const owner = BigInt(typeof process.geteuid === 'function' ? process.geteuid() : 0);
  try {
    const directoryBefore = await stageHandle.stat({bigint: true});
    if (!directoryBefore.isDirectory() || (directoryBefore.mode & 0o777n) !== 0o700n ||
        directoryBefore.uid !== owner) fail('witness_invalid');
    for (const name of OUTPUT_MEMBERS) {
      const memberPath = `/proc/self/fd/${stageHandle.fd}/${name}`;
      const handle = await open(memberPath, constants.O_RDONLY | O_CLOEXEC | constants.O_NOFOLLOW);
      const before = await handle.stat({bigint: true});
      if (!before.isFile() || before.uid !== owner || (before.mode & 0o777n) !== 0o600n ||
          before.nlink !== 1n) fail('witness_invalid');
      opened.push({name, memberPath, handle, before});
    }
    const entries = [];
    for (const member of opened) {
      const digest = createHash('sha256');
      const buffer = Buffer.allocUnsafe(64 * 1024);
      let position = 0;
      while (true) {
        const {bytesRead} = await member.handle.read(buffer, 0, buffer.length, position);
        if (!bytesRead) break;
        digest.update(buffer.subarray(0, bytesRead));
        position += bytesRead;
      }
      entries.push(Object.freeze({name: member.name, type: 'file', mode: 0o600,
                                  uid: Number(owner), nlink: 1,
                                  size: member.before.size,
                                  hash: digest.digest('hex')}));
    }
    for (const member of opened) {
      const after = await member.handle.stat({bigint: true});
      const named = await lstat(member.memberPath, {bigint: true});
      if (!sameStatIdentity(member.before, after) || !sameStatIdentity(after, named))
        fail('witness_invalid');
    }
    const directoryAfter = await stageHandle.stat({bigint: true});
    if (!sameStatIdentity(directoryBefore, directoryAfter)) fail('witness_invalid');
    return Object.freeze({token: WITNESS_TOKEN,
                          directory: Object.freeze({type: 'directory', mode: 0o700,
                                                    uid: Number(owner)}),
                          entries: Object.freeze(entries)});
  } finally {
    await Promise.allSettled(opened.map(member => member.handle.close()));
  }
}

async function installWitness(lock, witness) {
  if (witness?.token !== WITNESS_TOKEN || witness.entries.length !== OUTPUT_MEMBERS.length)
    fail('witness_invalid');
  if (witness.directory?.type !== 'directory' || witness.directory.mode !== 0o700 ||
      !Number.isSafeInteger(witness.directory.uid) ||
      await lock.command(
          `WITNESS_DIR ${witness.directory.mode} ${witness.directory.uid}`) !== 'WITNESS_DIR_OK')
    fail('witness_invalid');
  for (const entry of witness.entries) {
    if (entry.type !== 'file' || entry.mode !== 0o600 || entry.nlink !== 1 ||
        !Number.isSafeInteger(entry.uid)) fail('witness_invalid');
    const name = Buffer.from(entry.name, 'ascii').toString('hex');
    if (await lock.command(
        `WITNESS ${name} ${entry.type} ${entry.mode} ${entry.uid} ${entry.nlink} ${entry.size} ${entry.hash}`) !== 'WITNESS_OK')
      fail('witness_invalid');
  }
  if (await lock.command('WITNESS_DONE') !== 'WITNESS_READY') fail('witness_invalid');
}

async function reconcileAmbiguousCommit(roots, stageHandle, stageIdentity,
    destinationHex, witness, options) {
  let result;
  let failure;
  let recovery;
  try { recovery = await startLockHelper(roots, options, stageHandle, true); }
  catch { throw new ExportError('commit_outcome_unknown'); }
  try {
    await installWitness(recovery, witness);
    const identity = `${stageIdentity.dev} ${stageIdentity.ino}`;
    if (await recovery.command(`OPENFD 1 73 - ${identity}`) !== 'OPENED')
      fail('commit_outcome_unknown');
    const response = await recovery.command(`RECONCILE 1 73 ${destinationHex}`, true);
    if (response === 'EXISTS_SAME')
      result = {committed: true, durability: 'durable'};
    else if (response === 'EXISTS_SAME_UNKNOWN')
      result = {committed: true, durability: 'unknown'};
    else
      fail('commit_outcome_unknown');
    options.probe?.({kind: 'commit_reconciled'});
  } catch (error) {
    failure = error instanceof ExportError && error.code === 'commit_outcome_unknown'
      ? error : new ExportError('commit_outcome_unknown');
  }
  try { await recovery.close(); }
  catch {
    if (result) result = {...result, durability: 'unknown'};
    else if (!failure) failure = new ExportError('commit_outcome_unknown');
  }
  if (failure) throw failure;
  return result;
}

async function writeOutputs(output, publicBytes, buildId, regions, options, lock, roots) {
  const parent = path.dirname(output);
  const stageName = `.xovm-export-${randomBytes(16).toString('hex')}`;
  const stage = path.join(parent, stageName);
  let cleanupStage = true;
  let result;
  let failure;
  let stageHandle;
  try {
    await mkdir(stage, {mode: 0o700});
    stageHandle = await open(stage, constants.O_RDONLY | constants.O_NOFOLLOW);
    await stageHandle.chmod(0o700);
    const stageIdentity = await stageHandle.stat({bigint: true});
    await writePrivateFile(stage, 'public-manifest.json', publicBytes);
    await writeRegistration(path.join(stage, 'registration.private.json'), buildId, regions, options);
    await stageHandle.sync();
    const witness = await buildStageWitness(stageHandle);
    await installWitness(lock, witness);
    if (options.fault === 'before_rename') fail('test_before_rename');
    const sourceHex = Buffer.from(stageName, 'utf8').toString('hex');
    if (await lock.command(
        `OPEN 1 ${sourceHex} - ${stageIdentity.dev} ${stageIdentity.ino}`) !== 'OPENED')
      fail('export_io');
    if (options.beforePromote) await options.beforePromote();
    const destinationHex = Buffer.from(path.basename(output), 'utf8').toString('hex');
    let response;
    let reconciled = false;
    try {
      response = await lock.command(`COMMIT 1 ${sourceHex} ${destinationHex}`, true);
    } catch (error) {
      if (!(error instanceof ExportError) || error.code !== 'helper_response_lost') throw error;
      cleanupStage = false;
      await lock.abort();
      result = await reconcileAmbiguousCommit(
          roots, stageHandle, stageIdentity, destinationHex, witness, options);
      reconciled = true;
    }
    if (reconciled) {
      cleanupStage = false;
    } else if (response === 'EXISTS') {
      fail('output_exists');
    } else if (response === 'EXISTS_SAME' || response === 'EXISTS_SAME_UNKNOWN') {
      result = {committed: true,
                durability: response === 'EXISTS_SAME' ? 'durable' : 'unknown'};
    } else if (response === 'COMMITTED DURABLE') {
      cleanupStage = false;
      result = {committed: true, durability: 'durable'};
    } else if (response === 'COMMITTED UNKNOWN') {
      cleanupStage = false;
      result = {committed: true, durability: 'unknown'};
    } else if (response === 'COMMITTED INDETERMINATE') {
      cleanupStage = false;
      result = {committed: true, durability: 'unknown', integrity: 'unknown'};
    } else {
      cleanupStage = false;
      fail('commit_outcome_unknown');
    }
  } catch (error) {
    failure = error;
  } finally {
    try {
      if (stageHandle) await stageHandle.close();
      if (cleanupStage) await rm(stage, {recursive: true, force: true});
    } catch (error) {
      if (result?.committed)
        result = {...result, durability: 'unknown', integrity: 'unknown'};
      else if (!failure) failure = error;
    }
  }
  if (failure) throw failure;
  return result;
}

function parseCLI(argv) {
  if (argv.length !== 4 || argv[0] !== '--input-dir' || argv[2] !== '--output-dir') fail('usage');
  return {input: argv[1], output: argv[3]};
}

export async function aggregate(argv, options = {}) {
  const {input, output} = parseCLI(argv);
  if (!path.isAbsolute(output) || path.resolve(output) !== output) fail('invalid_output_dir');
  const parent = path.dirname(output);
  await requireSecureAbsoluteDirectory(parent, 'invalid_output_dir', false);
  if (parent === input) fail('invalid_output_dir');
  const lock = await startLockHelper([input, parent], options);
  const spool = path.join(parent, `.xovm-spool-${randomBytes(16).toString('hex')}`);
  let result;
  let failure;
  try {
    if (options.afterLock) {
      await options.afterLock([path.join(input, '.xovm-publish.lock'),
                               path.join(parent, '.xovm-publish.lock')]);
      const response = await lock.command('VERIFY');
      if (response !== 'OK') fail('lock_replaced');
    }
    try { await lstat(output); }
    catch (error) { if (error.code !== 'ENOENT') fail('invalid_output_dir'); }
    await mkdir(spool, {mode: 0o700});
    const {softwareId, regions} = await readPrivateInput(input, spool, options);
    const {publicBytes, buildId} = makeOutputs(softwareId, regions);
    result = await writeOutputs(output, publicBytes, buildId, regions, options, lock,
        [input, parent]);
  } catch (error) {
    failure = error;
  }
  try { await rm(spool, {recursive: true, force: true}); }
  catch (error) {
    if (result?.committed)
      result = {...result, durability: 'unknown', integrity: 'unknown'};
    else if (!failure) failure = error;
  }
  try { await lock.close(); }
  catch (error) {
    if (result?.committed)
      result = {...result, durability: 'unknown'};
    else if (!failure) failure = error;
  }
  if (failure) throw failure;
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  if (argv.length === 1 && argv[0] === '--help') {
    process.stdout.write(HELP);
  } else aggregate(argv).then(result => {
    if (result.durability === 'unknown')
      process.stderr.write('cloud-material export committed: durability_unknown\n');
  }).catch(error => {
    const code = error instanceof ExportError ? error.code : 'export_io';
    const detail = error instanceof ExportError && error.detail ? ` ${error.detail}` : '';
    process.stderr.write(`cloud-material export failed: ${code}${detail}\n`);
    process.exitCode = 1;
  });
}
