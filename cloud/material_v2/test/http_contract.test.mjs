import assert from 'node:assert/strict';
import test from 'node:test';

import {encodeCanonical} from '../codec.mjs';
import {MAX_REQUEST, parseRequest} from '../protocol.mjs';
import {encodeRelaySuccess, parseRelayRequest, RELAY_REQUEST_ENVELOPE_MAX} from '../http_contract.mjs';

const CLIENT_KEY = Buffer.from(
    '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex');

function request(type = 'material.issue') {
  const common = {
    protocol_version: 2,
    suite: 'X25519-Ed25519-HKDF-SHA256-AES256GCM',
    type,
    software_id: 'test.software',
    build_id: '11'.repeat(32),
    final_artifact_hash: '22'.repeat(32),
    request_id: '33'.repeat(32),
    client_nonce: '44'.repeat(32),
    client_ephemeral_key: CLIENT_KEY.toString('base64'),
  };
  if (type === 'session.open') return common;
  return {...common,
    session_id: '55'.repeat(32),
    counter_epoch: '66'.repeat(32),
    region_id: '77'.repeat(32),
    engine_abi_hash: '88'.repeat(32),
    mode: 'lease',
    previous_generation: '0',
  };
}

function envelope(bytes) {
  return Buffer.from(JSON.stringify({protocol: 'xovm2_relay', request_b64: bytes.toString('base64')}));
}

const headers = {'content-type': 'application/json; charset=utf-8'};

test('relay request preserves canonical material.issue bytes', () => {
  const bytes = encodeCanonical(request());
  const parsed = parseRelayRequest(headers, envelope(bytes));
  assert.deepEqual(parsed.requestBytes, bytes);
  assert.equal(parseRequest(parsed.requestBytes).type, 'material.issue');
});

test('relay request accepts canonical session.open bytes', () => {
  const bytes = encodeCanonical(request('session.open'));
  assert.deepEqual(parseRelayRequest(headers, envelope(bytes)).requestBytes, bytes);
});

test('relay envelope rejects duplicate JSON keys before JSON.parse can collapse them', () => {
  const bytes = encodeCanonical(request());
  const body = Buffer.from(`{"protocol":"xovm2_relay","request_b64":"${bytes.toString('base64')}","protocol":"xovm2_relay"}`);
  assert.throws(() => parseRelayRequest(headers, body), {code: 'invalid_json'});
});

test('relay envelope rejects unknown fields', () => {
  const bytes = encodeCanonical(request());
  const body = Buffer.from(JSON.stringify({protocol: 'xovm2_relay', request_b64: bytes.toString('base64'), ignored: true}));
  assert.throws(() => parseRelayRequest(headers, body), {code: 'invalid_schema'});
});

test('relay envelope rejects invalid and non-canonical base64', () => {
  for (const request_b64 of ['@@@=', 'YQ', 'YQ==\n']) {
    const body = Buffer.from(JSON.stringify({protocol: 'xovm2_relay', request_b64}));
    assert.throws(() => parseRelayRequest(headers, body));
  }
});

test('relay envelope rejects malformed canonical request bytes', () => {
  const body = envelope(Buffer.from('{"not":"a request"}'));
  assert.throws(() => parseRelayRequest(headers, body));
});

test('relay envelope enforces decoded request size and derived JSON envelope limit', () => {
  const tooLargeRequest = Buffer.alloc(MAX_REQUEST + 1);
  assert.throws(() => parseRelayRequest(headers, envelope(tooLargeRequest)), {code: 'request_size_limit'});
  assert.throws(() => parseRelayRequest(headers, Buffer.alloc(RELAY_REQUEST_ENVELOPE_MAX + 1)),
      {code: 'request_size_limit'});
});

test('relay envelope enforces content type and explicit relay discriminator', () => {
  const bytes = encodeCanonical(request());
  assert.throws(() => parseRelayRequest({'content-type': 'text/plain'}, envelope(bytes)),
      {code: 'invalid_content_type'});
  const body = Buffer.from(JSON.stringify({protocol: 'capability_v1', request_b64: bytes.toString('base64')}));
  assert.throws(() => parseRelayRequest(headers, body), {code: 'invalid_protocol'});
});

test('relay success envelope preserves exact response bytes', () => {
  const bytes = Buffer.from([0, 1, 2, 127, 128, 254, 255]);
  const encoded = encodeRelaySuccess(bytes);
  const parsed = JSON.parse(encoded.toString('utf8'));
  assert.deepEqual(Object.keys(parsed).sort(), ['protocol', 'response_b64']);
  assert.equal(parsed.protocol, 'xovm2_relay');
  assert.deepEqual(Buffer.from(parsed.response_b64, 'base64'), bytes);
});
