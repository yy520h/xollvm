import {timingSafeEqual} from 'node:crypto';

import {parseRelayRequest, encodeRelaySuccess, RELAY_REQUEST_ENVELOPE_MAX} from './http_contract.mjs';
import {parseStrictJsonObject} from './strict_json.mjs';
import {RELAY_RESPONSE_ENVELOPE_MAX} from './http_contract.mjs';

const MAX_ADMIN_BODY = 800 * 1024 * 1024;

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function respond(response, status, body) {
  response.statusCode = status;
  response.setHeader('content-type', 'application/json; charset=utf-8');
  response.setHeader('cache-control', 'no-store');
  response.setHeader('x-content-type-options', 'nosniff');
  response.end(body);
}

async function readBody(request, maximum, timeoutMs) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    const timer = setTimeout(() => {
      request.destroy();
      reject(Object.assign(new Error('request_timeout'), {code: 'request_timeout'}));
    }, timeoutMs);
    request.on('data', chunk => {
      size += chunk.length;
      if (size > maximum) {
        clearTimeout(timer);
        request.destroy();
        reject(Object.assign(new Error('request_size_limit'), {code: 'request_size_limit'}));
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => { clearTimeout(timer); resolve(Buffer.concat(chunks, size)); });
    request.on('error', error => { clearTimeout(timer); reject(error); });
  });
}

function fixedConfig(config) {
  if (!config || config.host !== '127.0.0.1' || !Number.isInteger(config.port) ||
      config.port < 1 || config.port > 65535 || !Number.isInteger(config.requestTimeoutMs) ||
      config.requestTimeoutMs < 100 || config.requestTimeoutMs > 120000 ||
      !Number.isInteger(config.maxConcurrentRequests) || config.maxConcurrentRequests < 1 ||
      config.maxConcurrentRequests > 10000) fail('invalid_config');
}

export function createServer({productionService, config, http}) {
  fixedConfig(config);
  if (!productionService || typeof productionService.readiness !== 'function' ||
      !http || typeof http.createServer !== 'function') fail('invalid_config');
  let active = 0;
  const handler = async (request, response) => {
    let path;
    try {
      path = new URL(request.url ?? '/', 'http://loopback').pathname;
    } catch {
      respond(response, 400, JSON.stringify({error: 'invalid_url'}));
      request.resume?.();
      return;
    }
    if (request.method === 'GET' && path === '/healthz') {
      try {
        const status = await productionService.readiness();
        respond(response, status.ready ? 200 : 503, JSON.stringify({ready: status.ready === true}));
      } catch {
        respond(response, 503, JSON.stringify({ready: false}));
      }
      return;
    }
    const trustMatch = /^\/v2\/trust\/([A-Za-z0-9][A-Za-z0-9._-]{0,63})$/.exec(path);
    if (request.method === 'GET' && trustMatch) {
      try {
        const result = await productionService.getPublicTrustBundle(trustMatch[1]);
        const body = Buffer.from(JSON.stringify({trust_bundle_b64: Buffer.from(result.bytes).toString('base64'),
          bootstrap: result.bootstrap}));
        if (body.length > 90000) fail('response_size_limit');
        response.statusCode = 200;
        response.setHeader('content-type', 'application/json; charset=utf-8');
        response.setHeader('cache-control', 'public, max-age=60');
        response.setHeader('x-content-type-options', 'nosniff');
        response.end(body);
      } catch {
        respond(response, 404, JSON.stringify({error: 'not_found'}));
      }
      return;
    }
    const adminMatch = request.method === 'POST' && (
      path === '/v2/admin/builds/import' ? ['import'] :
      /^\/v2\/admin\/builds\/([0-9a-f]{64})\/(revoke|enable)$/.exec(path));
    if (adminMatch) {
      if (typeof request.headers['x-xovm-admin-token'] !== 'string' ||
          typeof config.adminToken !== 'string' ||
          Buffer.byteLength(request.headers['x-xovm-admin-token']) !== Buffer.byteLength(config.adminToken) ||
          !timingSafeEqual(Buffer.from(request.headers['x-xovm-admin-token']), Buffer.from(config.adminToken))) {
        respond(response, 401, JSON.stringify({error: 'unauthorized'}));
        request.resume?.();
        return;
      }
      try {
        const body = await readBody(request, MAX_ADMIN_BODY, config.requestTimeoutMs);
        const input = parseStrictJsonObject(body, MAX_ADMIN_BODY);
        let adminRequest;
        if (adminMatch[0] === 'import') {
          exactEnvelope(input, ['public_manifest_b64', 'private_registration_b64',
            'verifier_sidecars_b64', 'final_artifact_hash']);
          if (!/^[0-9a-f]{64}$/.test(input.final_artifact_hash)) fail('invalid_admin_request');
          adminRequest = {operation: 'import', input: {
            publicManifest: decodeAdminObject(input.public_manifest_b64),
            privateRegistration: decodeAdminObject(input.private_registration_b64),
            verifierSidecars: decodeAdminObject(input.verifier_sidecars_b64),
            finalArtifactHash: input.final_artifact_hash,
          }};
        } else if (adminMatch[2] === 'revoke') {
          exactEnvelope(input, []);
          adminRequest = {operation: 'revoke', buildId: adminMatch[1]};
        } else {
          exactEnvelope(input, ['final_artifact_hash']);
          if (!/^[0-9a-f]{64}$/.test(input.final_artifact_hash)) fail('invalid_admin_request');
          adminRequest = {operation: 'enable', buildId: adminMatch[1],
            finalArtifactHash: input.final_artifact_hash};
        }
        adminRequest.authorization = request.headers['x-xovm-admin-token'];
        await productionService.handleAdminRequest(adminRequest);
        respond(response, 200, JSON.stringify({ok: true}));
      } catch (error) {
        const unauthorized = error?.code === 'unauthorized';
        respond(response, unauthorized ? 401 : 400,
            JSON.stringify({error: unauthorized ? 'unauthorized' : 'admin_failed'}));
      }
      return;
    }
    if (request.method !== 'POST' || path !== '/v2/relay') {
      respond(response, 404, JSON.stringify({error: 'not_found'}));
      return;
    }
    if (request.headers['content-encoding'] !== undefined &&
        request.headers['content-encoding'] !== 'identity') {
      respond(response, 415, JSON.stringify({error: 'unsupported_encoding'}));
      request.resume?.();
      return;
    }
    if (active >= config.maxConcurrentRequests) {
      respond(response, 503, JSON.stringify({error: 'unavailable'}));
      return;
    }
    ++active;
    try {
      const body = await readBody(request, RELAY_REQUEST_ENVELOPE_MAX, config.requestTimeoutMs);
      const {requestBytes} = parseRelayRequest(request.headers, body);
      const result = await productionService.handleRuntimeRequest(requestBytes,
          request.headers['x-xovm-relay-token']);
      const success = encodeRelaySuccess(result);
      if (success.length > RELAY_RESPONSE_ENVELOPE_MAX) fail('response_size_limit');
      respond(response, 200, success);
    } catch (error) {
      const code = ['invalid_content_type', 'invalid_json', 'invalid_schema', 'invalid_protocol',
        'invalid_base64', 'invalid_canonical', 'request_size_limit'].includes(error?.code)
        ? error.code : 'relay_failed';
      respond(response, code === 'request_size_limit' ? 413 : 400,
          JSON.stringify({error: code}));
    } finally {
      --active;
    }
  };
  const server = http.createServer(handler);
  server.requestTimeout = config.requestTimeoutMs;
  server.headersTimeout = Math.min(config.requestTimeoutMs, 10000);
  return Object.freeze({server,
    async listen() {
      const readiness = await productionService.readiness();
      if (readiness.ready !== true) fail('production_adapter_missing');
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(config.port, config.host, resolve);
      });
      return server.address();
    },
    async close() {
      if (server.listening) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    },
  });
}

function exactEnvelope(value, fields) {
  if (Object.getPrototypeOf(value) !== null || Object.keys(value).length !== fields.length ||
      fields.some(field => !Object.hasOwn(value, field))) fail('invalid_admin_request');
}

function decodeAdminObject(value) {
  if (typeof value !== 'string' ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
    fail('invalid_admin_request');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) fail('invalid_admin_request');
  return parseStrictJsonObject(bytes, MAX_ADMIN_BODY);
}

export const serverInternals = Object.freeze({readBody, parseStrictJsonObject, MAX_ADMIN_BODY});
