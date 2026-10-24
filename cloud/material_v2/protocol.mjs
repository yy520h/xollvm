import {
  createDecipheriv, createHash, createPrivateKey, createPublicKey, diffieHellman,
  hkdfSync, verify,
} from 'node:crypto';

import {decodeCanonical, encodeCanonical, fail, readU64} from './codec.mjs';
import {frame, parseExecutionPackage, validateMaterialBinding} from '../../tools/cloud-material/format.mjs';

export const SUITE = 'X25519-Ed25519-HKDF-SHA256-AES256GCM';
export const MAX_RESPONSE = 16 * 1024 * 1024;
export const MAX_REQUEST = 8192;

const HASH = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const X25519_SPKI = Buffer.from('302a300506032b656e032100', 'hex');
const ED25519_SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const X25519_P = Buffer.from(
    'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex');
const PENDING = new WeakMap();
const VERIFIED = new WeakMap();
const TRUST_BUNDLES = new WeakMap();

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

function id(value) {
  if (typeof value !== 'string' || !ID.test(value)) fail('invalid_id');
  return value;
}

function r32(value) {
  hash(value);
  if (value === '0'.repeat(64)) fail('invalid_random_value');
  return value;
}

function exactBase64(value, size) {
  if (typeof value !== 'string' || value.length !== 4 * Math.ceil(size / 3) ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) fail('invalid_base64');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== size || bytes.toString('base64') !== value) fail('invalid_base64');
  return bytes;
}

function compareLittleEndian(left, right) {
  for (let index = left.length - 1; index >= 0; --index) {
    if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
  }
  return 0;
}

export function validateX25519Public(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32 ||
      (bytes[31] & 0x80) !== 0 || compareLittleEndian(bytes, X25519_P) >= 0)
    fail('invalid_key');
  return Buffer.from(bytes);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest();
}

function validateRequestValue(q) {
  const common = [
    'protocol_version', 'suite', 'type', 'software_id', 'build_id',
    'final_artifact_hash', 'request_id', 'client_nonce', 'client_ephemeral_key',
  ];
  const extra = {
    'session.open': [],
    'session.renew': ['session_id', 'counter_epoch', 'previous_counter'],
    'session.close': ['session_id', 'counter_epoch', 'previous_counter'],
    'material.issue': [
      'session_id', 'counter_epoch', 'region_id', 'engine_abi_hash', 'mode',
      'previous_generation',
    ],
  }[q?.type];
  if (!extra) fail('invalid_request_type');
  closed(q, [...common, ...extra]);
  u32(q.protocol_version, 2, 2);
  if (q.suite !== SUITE) fail('unsupported_suite');
  id(q.software_id);
  hash(q.build_id);
  hash(q.final_artifact_hash);
  r32(q.request_id);
  r32(q.client_nonce);
  validateX25519Public(exactBase64(q.client_ephemeral_key, 32));
  if (q.type !== 'session.open') {
    r32(q.session_id);
    r32(q.counter_epoch);
  }
  if (q.type === 'session.renew' || q.type === 'session.close') readU64(q.previous_counter);
  if (q.type === 'material.issue') {
    hash(q.region_id);
    hash(q.engine_abi_hash);
    if (!['session', 'lease', 'operation'].includes(q.mode)) fail('invalid_mode');
    readU64(q.previous_generation);
  }
  return q;
}

export function parseRequest(bytes) {
  if (!(bytes instanceof Uint8Array)) fail('invalid_bytes');
  if (bytes.length > MAX_REQUEST) fail('request_size_limit');
  return validateRequestValue(decodeCanonical(bytes));
}

export function requestHash(bytes) {
  parseRequest(bytes);
  return sha256(frame('XOVM2/request', Buffer.from(bytes))).toString('hex');
}

// Envelope 使用独立 16 MiB profile；扫描完成前不调用 JSON.parse。
function decodeEnvelopeCanonical(bytes) {
  if (!(bytes instanceof Uint8Array)) fail('invalid_bytes');
  if (bytes.length > MAX_RESPONSE) fail('response_size_limit');
  let position = 0;
  const at = () => position < bytes.length ? bytes[position] : -1;
  const take = wanted => { if (at() !== wanted) fail('invalid_canonical'); ++position; };
  function string(limit, key = false) {
    take(34);
    let count = 0;
    while (position < bytes.length && at() !== 34) {
      if (++count > limit) fail('string_limit');
      let current = bytes[position++];
      if (current < 32 || current > 126) fail('invalid_ascii');
      if (current === 92) {
        current = at();
        ++position;
        if (key || (current !== 34 && current !== 92)) fail('invalid_canonical');
      }
    }
    take(34);
  }
  function value(depth, owner = '') {
    if (depth > 8) fail('depth_limit');
    if (at() === 123) {
      ++position;
      let count = 0;
      let previous = '';
      if (at() === 125) { ++position; return; }
      while (true) {
        if (++count > 40) fail('object_limit');
        const start = position + 1;
        string(64, true);
        const key = Buffer.from(bytes.subarray(start, position - 1)).toString('ascii');
        if (!/^[a-z][a-z0-9_]{0,63}$/.test(key) || key <= previous) fail('invalid_key_order');
        previous = key;
        take(58);
        value(depth + 1, key);
        if (at() === 125) { ++position; break; }
        take(44);
      }
      return;
    }
    if (at() === 91) {
      ++position;
      let count = 0;
      if (at() === 93) { ++position; return; }
      while (true) {
        if (++count > 256) fail('array_limit');
        value(depth + 1);
        if (at() === 93) { ++position; break; }
        take(44);
      }
      return;
    }
    if (at() === 34) {
      string(owner === 'ciphertext' ? 15000000 : 256);
      return;
    }
    if (at() >= 48 && at() <= 57) {
      const first = at();
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
    fail('invalid_canonical');
  }
  value(1);
  if (position !== bytes.length) fail('invalid_canonical');
  let decoded;
  try { decoded = JSON.parse(Buffer.from(bytes).toString('ascii')); }
  catch { fail('invalid_canonical'); }
  if (!encodeEnvelopeCanonical(decoded).equals(Buffer.from(bytes))) fail('invalid_canonical');
  return decoded;
}

export function encodeEnvelopeCanonical(envelope) {
  closed(envelope, ['transcript', 'ciphertext', 'tag', 'signature']);
  const transcript = encodeCanonical(envelope.transcript);
  for (const field of ['ciphertext', 'tag', 'signature'])
    if (typeof envelope[field] !== 'string' || /[^A-Za-z0-9+/=]/.test(envelope[field]))
      fail('invalid_base64');
  const result = Buffer.concat([
    Buffer.from('{"ciphertext":', 'ascii'), Buffer.from(JSON.stringify(envelope.ciphertext), 'ascii'),
    Buffer.from(',"signature":', 'ascii'), Buffer.from(JSON.stringify(envelope.signature), 'ascii'),
    Buffer.from(',"tag":', 'ascii'), Buffer.from(JSON.stringify(envelope.tag), 'ascii'),
    Buffer.from(',"transcript":', 'ascii'), transcript, Buffer.from('}', 'ascii'),
  ]);
  if (result.length > MAX_RESPONSE) fail('response_size_limit');
  return result;
}

function validateTranscript(transcript, q, expected) {
  closed(transcript, [
    'protocol_version', 'suite', 'type', 'software_id', 'build_id',
    'final_artifact_hash', 'request_id', 'request_hash', 'client_nonce',
    'client_ephemeral_key', 'server_nonce', 'server_ephemeral_key', 'server_key_id',
    'trust_epoch', 'session_id', 'counter_epoch', 'counter', 'issued_at_ms',
    'auth_valid_until_ms', 'session_valid_until_ms', 'accept_for_ms', 'payload_hash',
    'binding',
  ]);
  u32(transcript.protocol_version, 2, 2);
  if (transcript.suite !== SUITE || transcript.type !== q.type) fail('response_mismatch');
  id(transcript.software_id);
  id(transcript.server_key_id);
  for (const field of ['build_id', 'final_artifact_hash', 'request_hash', 'payload_hash'])
    hash(transcript[field]);
  for (const field of ['request_id', 'client_nonce', 'server_nonce', 'session_id', 'counter_epoch'])
    r32(transcript[field]);
  validateX25519Public(exactBase64(transcript.client_ephemeral_key, 32));
  validateX25519Public(exactBase64(transcript.server_ephemeral_key, 32));
  for (const field of ['trust_epoch', 'counter', 'issued_at_ms', 'auth_valid_until_ms',
    'session_valid_until_ms']) readU64(transcript[field]);
  if (readU64(transcript.counter) === 0n) fail('invalid_counter');
  u32(transcript.accept_for_ms, 1, 120000);
  for (const field of ['software_id', 'build_id', 'final_artifact_hash', 'request_id',
    'client_nonce', 'client_ephemeral_key'])
    if (transcript[field] !== q[field]) fail('response_mismatch');
  const digest = sha256(frame('XOVM2/request', encodeCanonical(q))).toString('hex');
  if (transcript.request_hash !== digest) fail('request_hash_mismatch');
  if (q.type !== 'session.open') {
    if (transcript.session_id !== q.session_id || transcript.counter_epoch !== q.counter_epoch)
      fail('response_mismatch');
  }
  for (const [field, value] of Object.entries(expected)) {
    if (value !== undefined && Object.hasOwn(transcript, field) && transcript[field] !== value)
      fail('response_mismatch');
  }
  return transcript;
}

function validateTrustBundle(bundle, q, transcript, trustedTime) {
  bundle = TRUST_BUNDLES.get(bundle);
  if (!bundle) fail('invalid_trust_bundle');
  if (bundle.counter_epoch !== transcript.counter_epoch || bundle.trust_epoch !== transcript.trust_epoch)
    fail('counter_epoch_mismatch');
  const issued = readU64(bundle.issued_at_ms);
  const validUntil = readU64(bundle.valid_until_ms);
  const lower = readU64(trustedTime?.lower_ms);
  const upper = readU64(trustedTime?.upper_ms);
  if (upper < lower || upper - lower > 5000n || lower < issued || upper >= validUntil)
    fail('untrusted_time');
  const key = bundle.keys.find(candidate => candidate.key_id === transcript.server_key_id);
  if (!key) fail('unknown_key_id');
  closed(key, ['key_id', 'public_key', 'not_before_ms', 'signing_until_ms', 'not_after_ms', 'status']);
  if (key.status === 'revoked') fail('revoked_key');
  if (key.status !== 'active' && key.status !== 'retired') fail('invalid_trust_bundle');
  const notBefore = readU64(key.not_before_ms);
  const signingUntil = readU64(key.signing_until_ms);
  const notAfter = readU64(key.not_after_ms);
  const issuedAt = readU64(transcript.issued_at_ms);
  if (!(notBefore < signingUntil && signingUntil <= notAfter) ||
      issuedAt < notBefore || issuedAt >= signingUntil ||
      issuedAt + BigInt(transcript.accept_for_ms) > notAfter ||
      issuedAt + BigInt(transcript.accept_for_ms) > validUntil)
    fail('key_unavailable');
  return exactBase64(key.public_key, 32);
}

export function verifyTrustBundle(bundleBytes, installed) {
  if (!(bundleBytes instanceof Uint8Array) || bundleBytes.length > 65536)
    fail('invalid_trust_bundle');
  const bundle = decodeCanonical(bundleBytes);
  closed(bundle, ['body', 'signature']);
  const body = bundle.body;
  closed(body, ['format_version', 'protocol_version', 'software_id', 'root_key_id',
    'trust_epoch', 'counter_epoch', 'issued_at_ms', 'valid_until_ms', 'keys']);
  u32(body.format_version, 1, 1);
  u32(body.protocol_version, 2, 2);
  id(body.software_id);
  id(body.root_key_id);
  if (body.software_id !== installed?.software_id || body.root_key_id !== installed?.root_key_id)
    fail('invalid_trust_bundle');
  if (!(installed.root_public_key instanceof Uint8Array) || installed.root_public_key.length !== 32)
    fail('invalid_trust_bundle');
  const trustEpoch = readU64(body.trust_epoch);
  if (trustEpoch === 0n) fail('invalid_trust_bundle');
  r32(body.counter_epoch);
  const issued = readU64(body.issued_at_ms);
  const validUntil = readU64(body.valid_until_ms);
  if (issued >= validUntil || !Array.isArray(body.keys) || !body.keys.length || body.keys.length > 64)
    fail('invalid_trust_bundle');
  let previous = '';
  for (const key of body.keys) {
    closed(key, ['key_id', 'public_key', 'not_before_ms', 'signing_until_ms', 'not_after_ms', 'status']);
    id(key.key_id);
    if (key.key_id <= previous) fail('invalid_trust_bundle');
    previous = key.key_id;
    exactBase64(key.public_key, 32);
    const notBefore = readU64(key.not_before_ms);
    const signingUntil = readU64(key.signing_until_ms);
    const notAfter = readU64(key.not_after_ms);
    if (!(notBefore < signingUntil && signingUntil <= notAfter) ||
        !['active', 'retired', 'revoked'].includes(key.status)) fail('invalid_trust_bundle');
  }
  const lower = readU64(installed.trusted_time?.lower_ms);
  const upper = readU64(installed.trusted_time?.upper_ms);
  if (upper < lower || upper - lower > 5000n || lower < issued || upper >= validUntil)
    fail('untrusted_time');
  let root;
  try {
    root = createPublicKey({key: Buffer.concat([ED25519_SPKI, Buffer.from(installed.root_public_key)]),
      format: 'der', type: 'spki'});
  } catch { fail('invalid_key'); }
  if (!verify(null, frame('XOVM2/trust-bundle', encodeCanonical(body)), root,
      exactBase64(bundle.signature, 64))) fail('bad_signature');
  const capability = Object.freeze(Object.create(null));
  TRUST_BUNDLES.set(capability, structuredClone(body));
  return capability;
}

export function createPendingRequest(requestBytes, options) {
  const q = parseRequest(requestBytes);
  if (!options || typeof options !== 'object' || !options.client_private_key ||
      typeof options.origin !== 'string' || !options.origin.startsWith('https://') ||
      options.pid !== process.pid || typeof options.process_epoch !== 'string' ||
      typeof options.current_origin !== 'function' ||
      typeof options.current_process_epoch !== 'function' ||
      typeof options.sent_boot_ns !== 'bigint' || typeof options.now_boot_ns !== 'function')
    fail('invalid_pending_request');
  const capability = Object.freeze(Object.create(null));
  PENDING.set(capability, {
    q: structuredClone(q),
    requestBytes: Buffer.from(requestBytes),
    requestHash: sha256(frame('XOVM2/request', Buffer.from(requestBytes))).toString('hex'),
    clientPrivateKey: options.client_private_key,
    origin: options.origin,
    processEpoch: options.process_epoch,
    currentOrigin: options.current_origin,
    currentProcessEpoch: options.current_process_epoch,
    pid: options.pid,
    sentBootNs: options.sent_boot_ns,
    nowBootNs: options.now_boot_ns,
    trustedTime: structuredClone(options.trusted_time),
    expected: Object.freeze({...options.expected}),
    trustBundle: options.trust_bundle,
  });
  return capability;
}

class AuthenticatedPackage {
  constructor(token, state) {
    if (token !== VERIFIED) fail('unverified_package');
    VERIFIED.set(this, state);
    Object.freeze(this);
  }
}

export function isVerifiedPackage(value) {
  return value instanceof AuthenticatedPackage && VERIFIED.has(value);
}

export function inspectVerifiedPackage(value) {
  const state = isVerifiedPackage(value) ? VERIFIED.get(value) : undefined;
  if (!state) fail('unverified_package');
  return {
    binding: {...state.parsed.binding},
    bytecode: Buffer.from(state.parsed.bytecode),
    decode_map: [...state.parsed.decode_map],
    static_decode_descriptor: {...state.parsed.static_decode_descriptor},
  };
}

export function authenticateResponse(responseBytes, pendingCapability) {
  const pending = PENDING.get(pendingCapability);
  if (!pending || pending.pid !== process.pid || pending.currentOrigin() !== pending.origin ||
      pending.currentProcessEpoch() !== pending.processEpoch) fail('invalid_pending_request');
  PENDING.delete(pendingCapability);
  if (!(responseBytes instanceof Uint8Array) || responseBytes.length > MAX_RESPONSE)
    fail('response_size_limit');
  const envelope = decodeEnvelopeCanonical(responseBytes);
  closed(envelope, ['transcript', 'ciphertext', 'tag', 'signature']);
  const transcript = validateTranscript(envelope.transcript, pending.q, pending.expected);
  if (transcript.request_hash !== pending.requestHash) fail('request_hash_mismatch');
  const transcriptBytes = encodeCanonical(transcript);
  const ciphertext = exactBase64(envelope.ciphertext,
      Buffer.from(envelope.ciphertext, 'base64').length);
  if (ciphertext.length > 11250348) fail('size_limit');
  const tag = exactBase64(envelope.tag, 16);
  const signature = exactBase64(envelope.signature, 64);
  const signingPublic = validateTrustBundle(
      pending.trustBundle, pending.q, transcript, pending.trustedTime);
  let signingKey;
  try {
    signingKey = createPublicKey({key: Buffer.concat([ED25519_SPKI, signingPublic]),
      format: 'der', type: 'spki'});
  } catch { fail('invalid_key'); }
  if (!verify(null, frame('XOVM2/signature', transcriptBytes, ciphertext, tag),
      signingKey, signature)) fail('bad_signature');

  const peer = validateX25519Public(exactBase64(transcript.server_ephemeral_key, 32));
  let shared;
  let key;
  let iv;
  let plaintext;
  try {
    let peerKey;
    try {
      peerKey = createPublicKey({key: Buffer.concat([X25519_SPKI, peer]),
        format: 'der', type: 'spki'});
      shared = diffieHellman({privateKey: pending.clientPrivateKey, publicKey: peerKey});
    } catch { fail('invalid_key'); }
    if (shared.length !== 32 || shared.every(byte => byte === 0)) fail('zero_shared_secret');
    const transcriptHash = sha256(frame('XOVM2/transcript', transcriptBytes));
    key = Buffer.from(hkdfSync('sha256', shared, transcriptHash,
        frame('XOVM2/response-key', transcriptHash), 32));
    iv = Buffer.from(hkdfSync('sha256', shared, transcriptHash,
        frame('XOVM2/response-iv', transcriptHash), 12));
    const decipher = createDecipheriv('aes-256-gcm', key, iv, {authTagLength: 16});
    decipher.setAAD(frame('XOVM2/aad', transcriptBytes));
    decipher.setAuthTag(tag);
    try { plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]); }
    catch { fail('bad_tag'); }
    if (plaintext.length !== ciphertext.length ||
        sha256(plaintext).toString('hex') !== transcript.payload_hash) fail('payload_hash_mismatch');
    if (pending.q.type !== 'material.issue') fail('unexpected_control_response');
    validateMaterialBinding(transcript.binding);
    const parsed = parseExecutionPackage(plaintext, transcript.binding);
    const bindingExpected = {
      build_id: pending.q.build_id,
      region_id: pending.q.region_id,
      session_id: pending.q.session_id,
      request_hash: pending.requestHash,
      mode: pending.q.mode,
      engine_abi_hash: pending.q.engine_abi_hash,
    };
    for (const [field, value] of Object.entries(bindingExpected))
      if (parsed.binding[field] !== value) fail('binding_mismatch');
    const generation = readU64(parsed.binding.generation);
    if (generation <= readU64(pending.q.previous_generation)) fail('generation_replay');
    const issued = readU64(transcript.issued_at_ms);
    const authUntil = readU64(transcript.auth_valid_until_ms);
    const sessionUntil = readU64(transcript.session_valid_until_ms);
    const responseUntil = issued + BigInt(transcript.accept_for_ms);
    if (responseUntil > 0xffffffffffffffffn || issued >= authUntil || issued >= sessionUntil ||
        responseUntil > authUntil || responseUntil > sessionUntil) fail('expired_response');
    if ((pending.q.mode === 'session' && parsed.binding.lease_ms !== 0) ||
        (pending.q.mode === 'lease' && parsed.binding.lease_ms !== transcript.accept_for_ms))
      fail('binding_mismatch');
    const deadline = pending.sentBootNs + BigInt(transcript.accept_for_ms) * 1000000n;
    if (pending.nowBootNs() >= deadline) fail('expired_response');
    return new AuthenticatedPackage(VERIFIED, {parsed, response: Buffer.from(responseBytes)});
  } finally {
    shared?.fill(0);
    key?.fill(0);
    iv?.fill(0);
    plaintext?.fill(0);
  }
}

export const protocolInternals = Object.freeze({
  exactBase64, sha256,
});
