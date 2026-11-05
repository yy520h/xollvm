import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import test from 'node:test';

import {createServer} from '../server.mjs';
import {encodeCanonical} from '../codec.mjs';

function fakeHttp() {
  return {createServer(handler) {
    return {handler, listening: false, async listen() { this.listening = true; },
      async close() { this.listening = false; }};
  }};
}

test('malformed URL returns 400 and subsequent health checks still succeed', async () => {
  let checked = 0;
  const instance = createServer({http: fakeHttp(), productionService: {
    async readiness() { ++checked; return {ready: true}; },
  }, config: {host: '127.0.0.1', port: 8080, requestTimeoutMs: 5000,
    maxConcurrentRequests: 20, relayToken: 'R'.repeat(32), adminToken: 'A'.repeat(32)}});
  let resumed = false;
  const badResponse = {setHeader() {}, end(value) { this.body = value; }};
  await instance.server.handler({method: 'GET', url: '//[', headers: {},
    resume() { resumed = true; }}, badResponse);
  assert.equal(badResponse.statusCode, 400);
  assert.deepEqual(JSON.parse(badResponse.body), {error: 'invalid_url'});
  assert.equal(checked, 0);
  assert.equal(resumed, true);
  const health = {setHeader() {}, end(value) { this.body = value; }};
  await instance.server.handler({method: 'GET', url: '/healthz', headers: {}}, health);
  assert.equal(health.statusCode, 200);
  assert.equal(checked, 1);
});

test('server refuses to listen unless production adapters are ready', async () => {
  let checked = false;
  const server = createServer({http: fakeHttp(), productionService: {
    async readiness() { checked = true; return {ready: false}; },
  }, config: {host: '127.0.0.1', port: 8080, requestTimeoutMs: 5000,
    maxConcurrentRequests: 20, relayToken: 'R'.repeat(32), adminToken: 'A'.repeat(32)}});
  await assert.rejects(server.listen(), {code: 'production_adapter_missing'});
  assert.equal(checked, true);
  assert.equal(server.server.listening, false);
});

test('server exposes no wildcard bind and requires loopback plaintext listener', () => {
  assert.throws(() => createServer({http: fakeHttp(), productionService: {},
    config: {host: '0.0.0.0', port: 8080}}), {code: 'invalid_config'});
});

test('server rejects wrong method and unknown route without calling production service', async () => {
  let called = false;
  const instance = createServer({http: fakeHttp(), productionService: {
    async readiness() { return {ready: true}; },
    async handleRuntimeRequest() { called = true; },
  }, config: {host: '127.0.0.1', port: 8080, requestTimeoutMs: 5000,
    maxConcurrentRequests: 20, relayToken: 'R'.repeat(32), adminToken: 'A'.repeat(32)}});
  const response = {headers: {}, setHeader(name, value) { this.headers[name] = value; },
    end(value) { this.body = value; }};
  await instance.server.handler({method: 'GET', url: '/v2/relay', headers: {}}, response);
  assert.equal(response.statusCode, 404);
  assert.equal(called, false);
});

test('server authenticates relay at service boundary and returns byte-preserving response envelope', async () => {
  let forwarded;
  const instance = createServer({http: fakeHttp(), productionService: {
    async readiness() { return {ready: true}; },
    async handleRuntimeRequest(bytes, credential) {
      forwarded = {bytes, credential};
      return Buffer.from([0, 1, 255]);
    },
  }, config: {host: '127.0.0.1', port: 8080, requestTimeoutMs: 5000,
    maxConcurrentRequests: 20, relayToken: 'R'.repeat(32), adminToken: 'A'.repeat(32)}});
  const requestBytes = encodeCanonical({protocol_version: 2,
    suite: 'X25519-Ed25519-HKDF-SHA256-AES256GCM', type: 'session.open',
    software_id: 'test.software', build_id: '11'.repeat(32), final_artifact_hash: '22'.repeat(32),
    request_id: '33'.repeat(32), client_nonce: '44'.repeat(32),
    client_ephemeral_key: Buffer.from('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex').toString('base64')});
  const request = new EventEmitter();
  request.method = 'POST'; request.url = '/v2/relay';
  request.headers = {'content-type': 'application/json', 'x-xovm-relay-token': 'R'.repeat(32)};
  request.destroy = () => {};
  const response = {headers: {}, setHeader(name, value) { this.headers[name] = value; },
    end(value) { this.body = value; }};
  const operation = instance.server.handler(request, response);
  request.emit('data', Buffer.from(JSON.stringify({protocol: 'xovm2_relay', request_b64: requestBytes.toString('base64')})));
  request.emit('end');
  await operation;
  assert.deepEqual(forwarded.bytes, requestBytes);
  assert.equal(forwarded.credential, 'R'.repeat(32));
  assert.deepEqual(Buffer.from(JSON.parse(response.body).response_b64, 'base64'), Buffer.from([0, 1, 255]));
});

test('admin routes require their separate credential and use only fixed operations', async () => {
  let adminRequest;
  const instance = createServer({http: fakeHttp(), productionService: {
    async readiness() { return {ready: true}; },
    async handleAdminRequest(request) { adminRequest = request; return 'validated'; },
  }, config: {host: '127.0.0.1', port: 8080, requestTimeoutMs: 5000,
    maxConcurrentRequests: 20, relayToken: 'R'.repeat(32), adminToken: 'A'.repeat(32)}});
  const request = new EventEmitter();
  request.method = 'POST'; request.url = '/v2/admin/builds/import';
  request.headers = {'content-type': 'application/json', 'x-xovm-admin-token': 'A'.repeat(32)};
  request.destroy = () => {};
  const response = {headers: {}, setHeader(name, value) { this.headers[name] = value; },
    end(value) { this.body = value; }};
  const operation = instance.server.handler(request, response);
  request.emit('data', Buffer.from(JSON.stringify({public_manifest_b64: 'e30=',
    private_registration_b64: 'e30=', verifier_sidecars_b64: 'e30=', final_artifact_hash: '11'.repeat(32)})));
  request.emit('end');
  await operation;
  assert.equal(response.statusCode, 200, response.body);
  assert.equal(adminRequest.operation, 'import');
  assert.equal(response.statusCode, 200);
  assert.equal(response.headers['access-control-allow-origin'], undefined);
});

test('admin route rejects invalid credential before reading a potentially large body', async () => {
  const instance = createServer({http: fakeHttp(), productionService: {
    async readiness() { return {ready: true}; },
    async handleAdminRequest() { throw new Error('must_not_reach_admin_service'); },
  }, config: {host: '127.0.0.1', port: 8080, requestTimeoutMs: 5000,
    maxConcurrentRequests: 20, relayToken: 'R'.repeat(32), adminToken: 'A'.repeat(32)}});
  let resumed = false;
  const request = new EventEmitter();
  request.method = 'POST'; request.url = '/v2/admin/builds/import';
  request.headers = {'content-type': 'application/json', 'x-xovm-admin-token': 'wrong'};
  request.resume = () => { resumed = true; };
  const response = {setHeader() {}, end(value) { this.body = value; }};
  await instance.server.handler(request, response);
  assert.equal(response.statusCode, 401);
  assert.equal(resumed, true);
});

test('trust route exposes bounded public bundle only', async () => {
  const instance = createServer({http: fakeHttp(), productionService: {
    async readiness() { return {ready: true}; },
    async getPublicTrustBundle(softwareId) { return {bytes: Buffer.from('bundle'), bootstrap: {software_id: softwareId}}; },
  }, config: {host: '127.0.0.1', port: 8080, requestTimeoutMs: 5000,
    maxConcurrentRequests: 20, relayToken: 'R'.repeat(32), adminToken: 'A'.repeat(32)}});
  const response = {headers: {}, setHeader(name, value) { this.headers[name] = value; },
    end(value) { this.body = value; }};
  await instance.server.handler({method: 'GET', url: '/v2/trust/test.software', headers: {}}, response);
  assert.equal(response.statusCode, 200);
  assert.equal(response.headers['cache-control'], 'public, max-age=60');
  assert.deepEqual(JSON.parse(response.body), {trust_bundle_b64: Buffer.from('bundle').toString('base64'),
    bootstrap: {software_id: 'test.software'}});
});

test('server rejects compressed relay bodies before invoking the service', async () => {
  let called = false;
  const instance = createServer({http: fakeHttp(), productionService: {
    async readiness() { return {ready: true}; },
    async handleRuntimeRequest() { called = true; },
  }, config: {host: '127.0.0.1', port: 8080, requestTimeoutMs: 5000,
    maxConcurrentRequests: 20, relayToken: 'R'.repeat(32), adminToken: 'A'.repeat(32)}});
  const request = new EventEmitter();
  request.method = 'POST'; request.url = '/v2/relay';
  request.headers = {'content-type': 'application/json', 'content-encoding': 'gzip'};
  request.destroy = () => {};
  const response = {headers: {}, setHeader(name, value) { this.headers[name] = value; },
    end(value) { this.body = value; }};
  await instance.server.handler(request, response);
  assert.equal(response.statusCode, 415);
  assert.equal(called, false);
});
