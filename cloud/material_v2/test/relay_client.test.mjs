import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import test from 'node:test';

import {encodeCanonical} from '../codec.mjs';
import {forwardXovm2Request} from '../relay_client.js';

function validRequest() {
  return encodeCanonical({protocol_version: 2,
    suite: 'X25519-Ed25519-HKDF-SHA256-AES256GCM', type: 'session.open',
    software_id: 'test.software', build_id: '11'.repeat(32),
    final_artifact_hash: '22'.repeat(32), request_id: '33'.repeat(32),
    client_nonce: '44'.repeat(32),
    client_ephemeral_key: Buffer.from('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex').toString('base64')});
}

test('relay posts byte-preserving envelope to a fixed HTTPS route with service auth', async () => {
  const requestBytes = validRequest();
  let observed;
  const transport = {request(options, callback) {
    observed = options;
    const req = new EventEmitter();
    req.write = body => { observed.body = body; };
    req.destroy = () => {};
    req.end = body => {
      observed.body = body;
      const response = new EventEmitter();
      response.statusCode = 200;
      response.headers = {'content-type': 'application/json; charset=utf-8'};
      callback(response);
      response.emit('data', Buffer.from(JSON.stringify({protocol: 'xovm2_relay',
        response_b64: Buffer.from([255, 0, 7]).toString('base64')})));
      response.emit('end');
    };
    return req;
  }};
  const result = await forwardXovm2Request(requestBytes, {backendOrigin: 'https://backend.example',
    relayCredential: 'R'.repeat(32), timeoutMs: 1000}, transport);
  assert.deepEqual(result, Buffer.from([255, 0, 7]));
  assert.equal(observed.hostname, 'backend.example');
  assert.equal(observed.path, '/v2/relay');
  assert.equal(observed.method, 'POST');
  assert.equal(observed.headers['x-xovm-relay-token'], 'R'.repeat(32));
  assert.deepEqual(JSON.parse(observed.body), {protocol: 'xovm2_relay', request_b64: requestBytes.toString('base64')});
});

test('relay rejects non-HTTPS origin and URL path injection', async () => {
  assert.throws(() => forwardXovm2Request(Buffer.from('x'), {backendOrigin: 'http://bad.example',
    relayCredential: 'R'.repeat(32), timeoutMs: 1000}), {code: 'invalid_relay_config'});
  assert.throws(() => forwardXovm2Request(Buffer.from('x'), {backendOrigin: 'https://good.example/path',
    relayCredential: 'R'.repeat(32), timeoutMs: 1000}), {code: 'invalid_relay_config'});
});

test('relay rejects redirect, wrong status, invalid content type and oversized response', async () => {
  for (const result of [
    {statusCode: 302, headers: {location: 'https://elsewhere'}},
    {statusCode: 500, headers: {'content-type': 'application/json'}},
    {statusCode: 200, headers: {'content-type': 'text/plain'}},
    {statusCode: 200, headers: {'content-type': 'application/json'}, body: JSON.stringify({protocol: 'xovm2_relay', response_b64: 'YQ==', extra: true})},
  ]) {
    const transport = {request(options, callback) {
      const req = new EventEmitter();
      req.destroy = () => {};
      req.write = () => {};
      req.end = () => {
        const response = new EventEmitter();
        Object.assign(response, result);
        callback(response);
        if (response.statusCode === 200) {
          response.emit('data', Buffer.from(result.body ?? ''));
          response.emit('end');
        }
      };
      return req;
    }};
    await assert.rejects(forwardXovm2Request(validRequest(), {backendOrigin: 'https://backend.example',
      relayCredential: 'R'.repeat(32), timeoutMs: 1000}, transport));
  }
});
