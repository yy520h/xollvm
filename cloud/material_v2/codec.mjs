// 协议 v2 的执行包 profile；扫描完成前不调用 JSON.parse。
export const MAX_PLAINTEXT = 11250348;
export const MAX_BYTECODE = 8388608;
export const MAX_B64 = 11184812;
export const MAX_OVERHEAD = 65536;

export class FormatError extends Error {
  constructor(code) { super(code); this.code = code; }
}
export function fail(code) { throw new FormatError(code); }

export function readU64(text) {
  if (typeof text !== 'string' || text.length > 20 || !/^(0|[1-9][0-9]*)$/.test(text)) fail('invalid_u64');
  const n = BigInt(text);
  if (n > 0xffffffffffffffffn) fail('u64_overflow');
  return n;
}

function preflight(bytes) {
  if (!(bytes instanceof Uint8Array)) fail('invalid_bytes');
  if (bytes.length > MAX_PLAINTEXT) fail('size_limit');
  let pos = 0;
  let bcLength = 0;
  const at = () => bytes[pos];
  const take = c => { if (at() !== c) fail('invalid_canonical'); ++pos; };
  function string(limit, key = false) {
    take(34);
    const start = pos;
    let count = 0;
    while (pos < bytes.length && at() !== 34) {
      if (++count > limit) fail('string_limit');
      let c = bytes[pos++];
      if (c < 32 || c > 126) fail('invalid_ascii');
      if (c === 92) {
        c = bytes[pos++];
        if (key || (c !== 34 && c !== 92)) fail('invalid_canonical');
      }
    }
    const end = pos;
    take(34);
    return [start, end];
  }
  function value(depth, large = false) {
    const c = at();
    if (c === 123 || c === 91) {
      if (depth > 8) fail('depth_limit');
      ++pos;
      let count = 0;
      const object = c === 123;
      const close = object ? 125 : 93;
      let previous = '';
      if (at() === close) { ++pos; return; }
      while (true) {
        if (++count > (object ? 40 : 256)) fail(object ? 'object_limit' : 'array_limit');
        let key = '';
        if (object) {
          const [start, end] = string(64, true);
          key = Buffer.from(bytes.subarray(start, end)).toString('ascii');
          if (!/^[a-z][a-z0-9_]{0,63}$/.test(key) || key <= previous) fail('invalid_key_order');
          previous = key;
          take(58);
        }
        value(depth + 1, object && depth === 1 && key === 'encoded_bc');
        if (at() === close) { ++pos; break; }
        take(44);
      }
    } else if (c === 34) {
      const [start, end] = string(large ? MAX_B64 : 256);
      if (large) {
        bcLength = end - start;
        if (bcLength > MAX_B64) fail('string_limit');
      }
    } else if (c >= 48 && c <= 57) {
      const start = pos;
      let n = 0;
      while (at() >= 48 && at() <= 57) {
        if (pos - start === 10) fail('number_limit');
        n = n * 10 + bytes[pos++] - 48;
      }
      if (pos - start > 1 && c === 48) fail('invalid_canonical');
      if (n > 4294967295) fail('invalid_u32');
    } else {
      const word = c === 116 ? 'true' : c === 102 ? 'false' : '';
      if (!word) fail('invalid_canonical');
      for (const ch of word) take(ch.charCodeAt(0));
    }
  }
  value(1);
  if (pos !== bytes.length) fail('invalid_canonical');
  if (bytes.length - bcLength > MAX_OVERHEAD) fail('overhead_limit');
}

export function encodeCanonical(value) {
  let total = 0;
  const pieces = [];
  function put(text) {
    total += text.length;
    if (total > MAX_PLAINTEXT) fail('size_limit');
    pieces.push(text);
  }
  function write(v, depth) {
    if (typeof v === 'string') {
      if (v.length > MAX_B64 || /[^\x20-\x7e]/.test(v)) fail('invalid_ascii');
      put(JSON.stringify(v));
    } else if (typeof v === 'number') {
      if (!Number.isInteger(v) || Object.is(v, -0) || v < 0 || v > 4294967295) fail('invalid_u32');
      put(String(v));
    } else if (typeof v === 'boolean') {
      put(v ? 'true' : 'false');
    } else if (v && typeof v === 'object') {
      if (depth > 8) fail('depth_limit');
      const array = Array.isArray(v);
      if (!array && Object.getPrototypeOf(v) !== Object.prototype && Object.getPrototypeOf(v) !== null) fail('invalid_object');
      if (Object.getOwnPropertySymbols(v).length) fail('invalid_object');
      const keys = array ? Array.from({length: Math.min(v.length, 257)}, (_, i) => String(i)) : Object.keys(v).sort();
      if (keys.length > (array ? 256 : 40)) fail(array ? 'array_limit' : 'object_limit');
      if (array && Object.keys(v).length !== v.length) fail('invalid_array');
      put(array ? '[' : '{');
      for (let i = 0; i < keys.length; ++i) {
        const key = keys[i];
        if (!Object.hasOwn(v, key)) fail('invalid_array');
        if (i) put(',');
        if (!array) {
          if (!/^[a-z][a-z0-9_]{0,63}$/.test(key)) fail('invalid_key');
          put(`"${key}":`);
        }
        write(v[key], depth + 1);
      }
      put(array ? ']' : '}');
    } else fail('invalid_type');
  }
  write(value, 1);
  const bytes = Buffer.from(pieces.join(''), 'ascii');
  preflight(bytes);
  return bytes;
}

export function decodeCanonical(bytes) {
  preflight(bytes);
  // 扫描已拒绝全部非 ASCII 字节，因此不存在 UTF-8 replacement 修复。
  const value = JSON.parse(Buffer.from(bytes).toString('ascii'));
  if (!encodeCanonical(value).equals(Buffer.from(bytes))) fail('invalid_canonical');
  return value;
}
