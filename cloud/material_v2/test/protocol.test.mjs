import assert from 'node:assert/strict';
import {
  createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, diffieHellman,
  hkdfSync, sign, verify,
} from 'node:crypto';
import test from 'node:test';

import {decodeCanonical, encodeCanonical} from '../codec.mjs';
import {
  authenticateResponse, createPendingRequest, encodeEnvelopeCanonical, inspectVerifiedPackage,
  isVerifiedPackage, requestHash, SUITE, verifyTrustBundle,
} from '../protocol.mjs';
import {frame, packageHash} from '../../../tools/cloud-material/format.mjs';

const X25519_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI = Buffer.from('302a300506032b656e032100', 'hex');
const ED25519_PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const CLIENT_PRIVATE = Buffer.from(
    '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex');
const CLIENT_PUBLIC = Buffer.from(
    '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex');
const SERVER_PRIVATE = Buffer.from(
    '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb', 'hex');
const SERVER_PUBLIC = Buffer.from(
    'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f', 'hex');
const SHARED = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';
const SIGNING_SEED = Buffer.from(
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
const SIGNING_PRIVATE = createPrivateKey({
  key: Buffer.concat([ED25519_PKCS8, SIGNING_SEED]), format: 'der', type: 'pkcs8',
});
const SIGNING_PUBLIC = createPublicKey(SIGNING_PRIVATE).export({format: 'der', type: 'spki'}).subarray(-32);
const ROOT_PRIVATE = createPrivateKey({
  key: Buffer.concat([ED25519_PKCS8, Buffer.from(
      '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', 'hex')]),
  format: 'der', type: 'pkcs8',
});
const ROOT_PUBLIC = createPublicKey(ROOT_PRIVATE).export({format: 'der', type: 'spki'}).subarray(-32);
const CLIENT_KEY = createPrivateKey({
  key: Buffer.concat([X25519_PKCS8, CLIENT_PRIVATE]), format: 'der', type: 'pkcs8',
});
const SERVER_KEY = createPrivateKey({
  key: Buffer.concat([X25519_PKCS8, SERVER_PRIVATE]), format: 'der', type: 'pkcs8',
});
const HASHES = Object.freeze({
  build: '11'.repeat(32), artifact: '22'.repeat(32), region: '33'.repeat(32),
  engine: '44'.repeat(32), session: '55'.repeat(32), epoch: '66'.repeat(32),
  requestId: '77'.repeat(32), clientNonce: '88'.repeat(32), serverNonce: '99'.repeat(32),
});

function request() {
  return {
    protocol_version: 2,
    suite: SUITE,
    type: 'material.issue',
    software_id: 'test.software',
    build_id: HASHES.build,
    final_artifact_hash: HASHES.artifact,
    request_id: HASHES.requestId,
    client_nonce: HASHES.clientNonce,
    client_ephemeral_key: CLIENT_PUBLIC.toString('base64'),
    session_id: HASHES.session,
    counter_epoch: HASHES.epoch,
    region_id: HASHES.region,
    engine_abi_hash: HASHES.engine,
    mode: 'lease',
    previous_generation: '0',
  };
}

export function publicProtocolVector(overrides = {}) {
  const q = {...request(), ...overrides.request};
  const qBytes = encodeCanonical(q);
  const requestDigest = createHash('sha256').update(frame('XOVM2/request', qBytes)).digest('hex');
  const binding = {
    build_id: HASHES.build,
    region_id: HASHES.region,
    session_id: q.session_id,
    generation: '1',
    request_hash: requestDigest,
    mode: 'lease',
    lease_ms: 45000,
    engine_abi_hash: HASHES.engine,
    ...overrides.binding,
  };
  const core = {
    format_version: 1,
    binding,
    bytecode_size: 1,
    encoded_bc: 'AQ==',
    decode_map: [0, ...new Array(255).fill(65535)],
    static_decode_descriptor: {
      decode_salt: 7,
      isa_version: 1,
      layout_hash: 'aa'.repeat(32),
      operand_encoding_hash: 'bb'.repeat(32),
    },
  };
  const executionPackage = {
    ...core,
    binding: {...binding, package_hash: packageHash(core)},
  };
  const plaintext = encodeCanonical(executionPackage);
  const transcript = {
    protocol_version: 2,
    suite: SUITE,
    type: q.type,
    software_id: q.software_id,
    build_id: q.build_id,
    final_artifact_hash: q.final_artifact_hash,
    request_id: q.request_id,
    request_hash: requestDigest,
    client_nonce: q.client_nonce,
    client_ephemeral_key: q.client_ephemeral_key,
    server_nonce: HASHES.serverNonce,
    server_ephemeral_key: SERVER_PUBLIC.toString('base64'),
    server_key_id: 'test-signing-key',
    trust_epoch: '7',
    session_id: q.session_id,
    counter_epoch: q.counter_epoch,
    counter: '9',
    issued_at_ms: '1000000',
    auth_valid_until_ms: '1100000',
    session_valid_until_ms: '1100000',
    accept_for_ms: 45000,
    payload_hash: createHash('sha256').update(plaintext).digest('hex'),
    binding: executionPackage.binding,
    ...overrides.transcript,
  };
  const transcriptBytes = encodeCanonical(transcript);
  const transcriptHash = createHash('sha256').update(
      frame('XOVM2/transcript', transcriptBytes)).digest();
  const shared = diffieHellman({privateKey: SERVER_KEY, publicKey: createPublicKey(CLIENT_KEY)});
  const key = Buffer.from(hkdfSync('sha256', shared, transcriptHash,
      frame('XOVM2/response-key', transcriptHash), 32));
  const iv = Buffer.from(hkdfSync('sha256', shared, transcriptHash,
      frame('XOVM2/response-iv', transcriptHash), 12));
  const cipher = createCipheriv('aes-256-gcm', key, iv, {authTagLength: 16});
  cipher.setAAD(frame('XOVM2/aad', transcriptBytes));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const signature = sign(null,
      frame('XOVM2/signature', transcriptBytes, ciphertext, tag), SIGNING_PRIVATE);
  const envelope = {transcript, ciphertext: ciphertext.toString('base64'),
    tag: tag.toString('base64'), signature: signature.toString('base64')};
  return {q, qBytes, requestDigest, executionPackage, plaintext, transcriptHash,
    shared, key, iv, ciphertext, tag, signature, envelope,
    response: encodeEnvelopeCanonical(envelope)};
}

function pending(qBytes = publicProtocolVector().qBytes, context = {}) {
  const {bytes: trustBytes} = trustFixture();
  const trustBundle = verifyTrustBundle(trustBytes, {
    root_key_id: 'test-root-key', root_public_key: ROOT_PUBLIC,
    software_id: 'test.software', trusted_time: {lower_ms: '1000001', upper_ms: '1000002'},
  });
  return createPendingRequest(qBytes, {
    client_private_key: CLIENT_KEY,
    origin: 'https://material.test',
    process_epoch: 'test-process',
    current_origin: () => context.origin ?? 'https://material.test',
    current_process_epoch: () => context.process_epoch ?? 'test-process',
    pid: process.pid,
    sent_boot_ns: 1000000000n,
    now_boot_ns: () => 1001000000n,
    trusted_time: {lower_ms: '1000001', upper_ms: '1000002'},
    expected: {
      software_id: 'test.software', build_id: HASHES.build,
      final_artifact_hash: HASHES.artifact, session_id: HASHES.session,
      counter_epoch: HASHES.epoch, region_id: HASHES.region,
      engine_abi_hash: HASHES.engine, mode: 'lease',
    },
    trust_bundle: trustBundle,
  });
}

function trustFixture() {
  const trustBody = {
    format_version: 1,
    protocol_version: 2,
    software_id: 'test.software',
    root_key_id: 'test-root-key',
    trust_epoch: '7',
    counter_epoch: HASHES.epoch,
    issued_at_ms: '900000',
    valid_until_ms: '1200000',
    keys: [{key_id: 'test-signing-key', public_key: SIGNING_PUBLIC.toString('base64'),
      not_before_ms: '900000', signing_until_ms: '1050000',
      not_after_ms: '1200000', status: 'active'}],
  };
  const bytes = encodeCanonical({body: trustBody,
    signature: sign(null, frame('XOVM2/trust-bundle', encodeCanonical(trustBody)),
        ROOT_PRIVATE).toString('base64')});
  return {body: trustBody, bytes};
}

function resign(envelope) {
  const transcript = encodeCanonical(envelope.transcript);
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  envelope.signature = sign(null,
      frame('XOVM2/signature', transcript, ciphertext, tag), SIGNING_PRIVATE).toString('base64');
}

function mutateVector(current, name) {
  if (['valid', 'lease_120', 'lease_120_gen2', 'lease_120_other_session',
    'lease_10', 'late_response',
    'session_material', 'short_lease', 'short_auth_window',
    'wrong_request_hash', 'wrong_ephemeral_key',
    'wrong_region', 'unknown_key_id', 'wrong_lease_binding'].includes(name)) return;
  if (name === 'truncated_envelope') {
    current.response = current.response.subarray(0, current.response.length - 1);
    return;
  }
  const mutations = {
    wrong_signature: envelope => {
      const bytes = Buffer.from(envelope.signature, 'base64'); bytes[0] ^= 1;
      envelope.signature = bytes.toString('base64');
    },
    bad_tag: envelope => {
      const bytes = Buffer.from(envelope.tag, 'base64'); bytes[0] ^= 1;
      envelope.tag = bytes.toString('base64');
      resign(envelope);
    },
    wrong_aad: envelope => {
      envelope.transcript.accept_for_ms = 44999;
      resign(envelope);
    },
    zero_shared_secret: envelope => {
      envelope.transcript.server_ephemeral_key = Buffer.alloc(32).toString('base64');
      resign(envelope);
    },
    noncanonical_x25519: envelope => {
      envelope.transcript.server_ephemeral_key = Buffer.from(
          'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex').toString('base64');
      resign(envelope);
    },
  };
  const mutate = mutations[name];
  if (!mutate) throw new Error('unknown_fixture_case');
  mutate(current.envelope);
  current.response = encodeEnvelopeCanonical(current.envelope);
}

if (process.argv[2] === '--native-fixture') {
  const options = {
    lease_120: {binding: {lease_ms: 120000}, transcript: {accept_for_ms: 120000,
      auth_valid_until_ms: '1200000', session_valid_until_ms: '1200000'}},
    lease_120_gen2: {request: {request_id: 'ab'.repeat(32), client_nonce: 'ac'.repeat(32),
      previous_generation: '1'}, binding: {generation: '2', lease_ms: 120000},
      transcript: {accept_for_ms: 120000, auth_valid_until_ms: '1200000',
        session_valid_until_ms: '1200000'}},
    lease_120_other_session: {request: {request_id: 'ad'.repeat(32), client_nonce: 'ae'.repeat(32),
      session_id: 'dd'.repeat(32)}, binding: {session_id: 'dd'.repeat(32), lease_ms: 120000},
      transcript: {accept_for_ms: 120000, auth_valid_until_ms: '1200000',
        session_valid_until_ms: '1200000'}},
    lease_10: {binding: {lease_ms: 10000}, transcript: {accept_for_ms: 10000}},
    late_response: {binding: {lease_ms: 120000}, transcript: {accept_for_ms: 120000,
      auth_valid_until_ms: '1200000', session_valid_until_ms: '1200000'},
      receive_at_deadline: true},
    session_material: {request: {mode: 'session'}, binding: {mode: 'session', lease_ms: 0}},
    short_lease: {binding: {lease_ms: 45000}, transcript: {accept_for_ms: 45000}},
    short_auth_window: {transcript: {auth_valid_until_ms: '1001000'}},
    wrong_request_hash: {binding: {request_hash: 'ff'.repeat(32)},
      transcript: {request_hash: 'ff'.repeat(32)}},
    wrong_ephemeral_key: {transcript: {client_ephemeral_key: SERVER_PUBLIC.toString('base64')}},
    wrong_region: {request: {region_id: 'fe'.repeat(32)}},
    unknown_key_id: {transcript: {server_key_id: 'unknown-key'}},
    wrong_lease_binding: {binding: {lease_ms: 44000}},
  }[process.argv[3]] ?? {};
  const current = publicProtocolVector(options);
  mutateVector(current, process.argv[3] ?? 'valid');
  const trust = trustFixture();
  process.stdout.write(JSON.stringify({
    request: current.qBytes.toString('base64'),
    response: current.response.toString('base64'),
    trust_bundle: trust.bytes.toString('base64'),
    client_private_key: CLIENT_PRIVATE.toString('hex'),
    root_public_key: ROOT_PUBLIC.toString('hex'),
    installed: {
      software_id: 'test.software', root_key_id: 'test-root-key',
      trusted_lower_ms: '1000001', trusted_upper_ms: '1000002',
    },
    expected: {
      software_id: 'test.software', build_id: HASHES.build,
      final_artifact_hash: HASHES.artifact, session_id: current.q.session_id,
      counter_epoch: HASHES.epoch, region_id: HASHES.region,
      engine_abi_hash: HASHES.engine, mode: current.q.mode,
    },
    sent_boot_ns: '1000000000',
    received_boot_ns: options.receive_at_deadline ? '121000000000' : '1001000000',
  }));
  process.exit(0);
}

if (process.argv[2] === '--native-auth') {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  try {
    const input = JSON.parse(Buffer.concat(chunks).toString());
    const requestBytes = Buffer.from(input.request, 'base64');
    const trustBytes = Buffer.from(input.trust_bundle, 'base64');
    const clientPrivateKey = createPrivateKey({
      key: Buffer.concat([X25519_PKCS8, Buffer.from(input.client_private_key, 'hex')]),
      format: 'der', type: 'pkcs8',
    });
    const trust = verifyTrustBundle(trustBytes, {
      root_key_id: 'fixture-root-key',
      root_public_key: ROOT_PUBLIC,
      software_id: 'fixture.software',
      trusted_time: {lower_ms: '1000', upper_ms: '1001'},
    });
    const pendingRequest = createPendingRequest(requestBytes, {
      client_private_key: clientPrivateKey,
      origin: 'https://fixture.test',
      process_epoch: 'fixture-process',
      current_origin: () => 'https://fixture.test',
      current_process_epoch: () => 'fixture-process',
      pid: process.pid,
      sent_boot_ns: 1000000000n,
      now_boot_ns: () => 1001000000n,
      trusted_time: {lower_ms: '1000', upper_ms: '1001'},
      expected: input.expected,
      trust_bundle: trust,
    });
    const verified = authenticateResponse(Buffer.from(input.response, 'base64'), pendingRequest);
    const inspected = inspectVerifiedPackage(verified);
    console.log(JSON.stringify({ok: true, binding: inspected.binding,
      generation: inspected.binding.generation, bytecode_size: inspected.bytecode.length,
      bytecode_hash: createHash('sha256').update(inspected.bytecode).digest('hex')}));
  } catch (error) {
    console.log(JSON.stringify({ok: false, code: error.code ?? 'unexpected_error'}));
    process.exitCode = 1;
  }
  process.exit();
}

if (process.argv[2] === '--native-control-auth') {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  try {
    const input = JSON.parse(Buffer.concat(chunks).toString());
    const requestBytes = Buffer.from(input.request, 'base64');
    const requestValue = decodeCanonical(requestBytes);
    const trust = verifyTrustBundle(Buffer.from(input.trust_bundle, 'base64'), {
      root_key_id: 'fixture-root-key', root_public_key: ROOT_PUBLIC,
      software_id: 'fixture.software', trusted_time: {lower_ms: '1000', upper_ms: '1001'},
    });
    const envelopeBytes = Buffer.from(input.response, 'base64');
    const envelope = JSON.parse(envelopeBytes.toString());
    assert.deepEqual(encodeEnvelopeCanonical(envelope), envelopeBytes);
    const transcript = envelope.transcript;
    assert.equal(transcript.type, 'session.open');
    assert.equal(transcript.request_hash, requestHash(requestBytes));
    assert.equal(transcript.server_key_id, 'fixture-key');
    assert.equal(transcript.trust_epoch, '1');
    assert.equal(transcript.build_id, requestValue.build_id);
    assert.equal(transcript.final_artifact_hash, requestValue.final_artifact_hash);
    assert.equal(transcript.request_id, requestValue.request_id);
    assert.equal(transcript.client_nonce, requestValue.client_nonce);
    assert.equal(transcript.client_ephemeral_key, requestValue.client_ephemeral_key);
    const transcriptBytes = encodeCanonical(transcript);
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
    const tag = Buffer.from(envelope.tag, 'base64');
    const signature = Buffer.from(envelope.signature, 'base64');
    const signingKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI, SIGNING_PUBLIC]), format: 'der', type: 'spki',
    });
    assert.equal(verify(null, frame('XOVM2/signature', transcriptBytes, ciphertext, tag),
      signingKey, signature), true);
    const clientKey = createPrivateKey({
      key: Buffer.concat([X25519_PKCS8, Buffer.from(input.client_private_key, 'hex')]),
      format: 'der', type: 'pkcs8',
    });
    const serverKey = createPublicKey({
      key: Buffer.concat([X25519_SPKI, Buffer.from(transcript.server_ephemeral_key, 'base64')]),
      format: 'der', type: 'spki',
    });
    const shared = diffieHellman({privateKey: clientKey, publicKey: serverKey});
    const transcriptHash = createHash('sha256').update(
      frame('XOVM2/transcript', transcriptBytes)).digest();
    const key = Buffer.from(hkdfSync('sha256', shared, transcriptHash,
      frame('XOVM2/response-key', transcriptHash), 32));
    const iv = Buffer.from(hkdfSync('sha256', shared, transcriptHash,
      frame('XOVM2/response-iv', transcriptHash), 12));
    const decipher = createDecipheriv('aes-256-gcm', key, iv, {authTagLength: 16});
    decipher.setAAD(frame('XOVM2/aad', transcriptBytes));
    decipher.setAuthTag(tag);
    const payload = JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
    assert.equal(payload.session_id, transcript.session_id);
    assert.equal(payload.counter_epoch, transcript.counter_epoch);
    console.log(JSON.stringify({ok: true, session_id: transcript.session_id,
      counter_epoch: transcript.counter_epoch}));
  } catch (error) {
    console.log(JSON.stringify({ok: false, code: error.code ?? error.message ?? 'unexpected_error'}));
    process.exitCode = 1;
  }
  process.exit();
}

test('fixed public vector has independent RFC X25519 and exact protocol bytes', () => {
  const current = publicProtocolVector();
  assert.equal(createPublicKey(CLIENT_KEY).export({format: 'der', type: 'spki'}).subarray(-32).toString('hex'),
    CLIENT_PUBLIC.toString('hex'));
  assert.equal(createPublicKey(SERVER_KEY).export({format: 'der', type: 'spki'}).subarray(-32).toString('hex'),
    SERVER_PUBLIC.toString('hex'));
  assert.equal(current.shared.toString('hex'), SHARED);
  assert.deepEqual({
    transcript_hash: current.transcriptHash.toString('hex'),
    response_key: current.key.toString('hex'),
    response_iv: current.iv.toString('hex'),
    response_tag: current.tag.toString('hex'),
    signature: current.signature.toString('hex'),
  }, {
    transcript_hash: 'b59d3358bacce2859a83b4c960bc0bf19aec91b4b249feac32c7544465dcf1a4',
    response_key: 'afee04bdbfc15bbfc059f8c703d27805dd2fd0642000eaaf1f77add58f5cb210',
    response_iv: 'e0e7bdea67349cd20bbdf7eb',
    response_tag: '5c6c779f21c8414f3cccd30bd2f62dd3',
    signature: '92b5a1e22129fe956b6451e1d453c59c1c2e9a9fb6c1207bf7bc9fb69c911ab4316873abc7dbe181bbc03129baffc9eb763e150acb27e3d19de28c6382111702',
  });
});

test('authentication creates an opaque verified package only after all checks', () => {
  const current = publicProtocolVector();
  assert.equal(requestHash(current.qBytes), current.requestDigest);
  const verified = authenticateResponse(current.response, pending(current.qBytes));
  assert.equal(isVerifiedPackage(verified), true);
  assert.equal(inspectVerifiedPackage(verified).binding.package_hash,
    current.executionPackage.binding.package_hash);
  const forged = Object.create(Object.getPrototypeOf(verified));
  assert.equal(isVerifiedPackage(forged), false);
  assert.throws(() => inspectVerifiedPackage(forged), {code: 'unverified_package'});
});

test('verified package inspection cannot mutate authenticated private state', () => {
  const current = publicProtocolVector();
  const verified = authenticateResponse(current.response, pending(current.qBytes));
  const first = inspectVerifiedPackage(verified);
  const originalByte = first.bytecode[0];
  const originalMap = first.decode_map[0];
  first.bytecode[0] ^= 0xff;
  first.decode_map[0] = 65535;
  first.binding.package_hash = '00'.repeat(32);
  const second = inspectVerifiedPackage(verified);
  assert.equal(second.bytecode[0], originalByte);
  assert.equal(second.decode_map[0], originalMap);
  assert.equal(second.binding.package_hash, current.executionPackage.binding.package_hash);
});

test('authentication consumes pending request on success and terminal failure', () => {
  const current = publicProtocolVector();
  const successful = pending(current.qBytes);
  authenticateResponse(current.response, successful);
  assert.throws(() => authenticateResponse(current.response, successful),
    {code: 'invalid_pending_request'});

  const rejected = pending(current.qBytes);
  const bad = structuredClone(current.envelope);
  const signature = Buffer.from(bad.signature, 'base64');
  signature[0] ^= 1;
  bad.signature = signature.toString('base64');
  assert.throws(() => authenticateResponse(encodeEnvelopeCanonical(bad), rejected),
    {code: 'bad_signature'});
  assert.throws(() => authenticateResponse(current.response, rejected),
    {code: 'invalid_pending_request'});
});

test('identity signature AAD tag truncation and X25519 failures publish nothing', () => {
  for (const name of ['wrong_signature', 'wrong_request_hash', 'wrong_ephemeral_key',
    'wrong_region', 'unknown_key_id', 'bad_tag', 'wrong_aad', 'zero_shared_secret',
    'noncanonical_x25519', 'wrong_lease_binding']) {
    const options = {
      wrong_request_hash: {binding: {request_hash: 'ff'.repeat(32)},
        transcript: {request_hash: 'ff'.repeat(32)}},
      wrong_ephemeral_key: {transcript: {client_ephemeral_key: SERVER_PUBLIC.toString('base64')}},
      wrong_region: {request: {region_id: 'fe'.repeat(32)}},
      unknown_key_id: {transcript: {server_key_id: 'unknown-key'}},
      wrong_lease_binding: {binding: {lease_ms: 44000}},
    }[name] ?? {};
    const current = publicProtocolVector(options);
    mutateVector(current, name);
    assert.throws(() => authenticateResponse(current.response, pending(current.qBytes)),
      undefined, name);
  }
  const current = publicProtocolVector();
  assert.throws(() => authenticateResponse(current.response.subarray(0, current.response.length - 1),
    pending(current.qBytes)));
});

test('pending origin and process epoch are rechecked when response arrives', () => {
  const current = publicProtocolVector();
  for (const field of ['origin', 'process_epoch']) {
    const context = {};
    const pendingRequest = pending(current.qBytes, context);
    context[field] = 'changed';
    assert.throws(() => authenticateResponse(current.response, pendingRequest),
      {code: 'invalid_pending_request'});
  }
});

test('response cap is enforced before parsing or allocation-derived publication', () => {
  assert.throws(() => authenticateResponse(Buffer.alloc(16 * 1024 * 1024 + 1), pending()),
    {code: 'response_size_limit'});
});

test('fully authenticated response window cannot exceed authorization or session deadline', () => {
  for (const transcript of [
    {auth_valid_until_ms: '1001000'},
    {session_valid_until_ms: '1001000'},
  ]) {
    const current = publicProtocolVector({transcript});
    assert.throws(() => authenticateResponse(current.response, pending(current.qBytes)),
      {code: 'expired_response'});
  }
});
