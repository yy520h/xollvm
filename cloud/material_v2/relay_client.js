import https from 'node:https';

import {MAX_REQUEST, MAX_RESPONSE, parseRequest} from './protocol.mjs';
import {RELAY_RESPONSE_ENVELOPE_MAX} from './http_contract.mjs';
import {parseStrictJsonObject} from './strict_json.mjs';

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function closed(value, fields) {
  if (!value || Object.getPrototypeOf(value) !== null || Object.keys(value).length !== fields.length ||
      fields.some(field => !Object.hasOwn(value, field))) fail('invalid_relay_response');
}

function canonicalBase64(value) {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
    fail('invalid_relay_response');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) fail('invalid_relay_response');
  return bytes;
}

function validateConfig(config) {
  let origin;
  try { origin = new URL(config?.backendOrigin); }
  catch { fail('invalid_relay_config'); }
  if (origin.protocol !== 'https:' || origin.username || origin.password ||
      origin.pathname !== '/' || origin.search || origin.hash ||
      typeof config.relayCredential !== 'string' || config.relayCredential.length < 32 ||
      !Number.isInteger(config.timeoutMs) || config.timeoutMs < 100 || config.timeoutMs > 120000)
    fail('invalid_relay_config');
  return origin;
}

export function forwardXovm2Request(requestBytes, config, transport = https) {
  const origin = validateConfig(config);
  if (!(requestBytes instanceof Uint8Array) || requestBytes.length > MAX_REQUEST) fail('request_size_limit');
  parseRequest(requestBytes);
  const body = Buffer.from(JSON.stringify({protocol: 'xovm2_relay',
    request_b64: Buffer.from(requestBytes).toString('base64')}));
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(Object.assign(new Error('relay_failed'), {code: error.code ?? 'relay_failed'}));
      else resolve(result);
    };
    const timer = setTimeout(() => {
      request.destroy();
      finish(Object.assign(new Error(), {code: 'relay_timeout'}));
    }, config.timeoutMs);
    const request = transport.request({protocol: 'https:', hostname: origin.hostname,
      port: origin.port || 443, method: 'POST', path: '/v2/relay',
      headers: {'content-type': 'application/json; charset=utf-8',
        'accept-encoding': 'identity', 'x-xovm-relay-token': config.relayCredential,
        'content-length': body.length},
      maxHeaderSize: 8192, timeout: config.timeoutMs, rejectUnauthorized: true,
    }, response => {
      if (response.statusCode !== 200 || response.headers.location !== undefined ||
          response.headers['content-encoding'] !== undefined ||
          !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers['content-type'] ?? '')) {
        response.destroy();
        finish(Object.assign(new Error(), {code: 'invalid_relay_response'}));
        return;
      }
      let size = 0;
      const chunks = [];
      response.on('data', chunk => {
        size += chunk.length;
        if (size > RELAY_RESPONSE_ENVELOPE_MAX) {
          response.destroy();
          finish(Object.assign(new Error(), {code: 'response_size_limit'}));
        } else chunks.push(chunk);
      });
      response.on('end', () => {
        try {
          const envelope = parseStrictJsonObject(Buffer.concat(chunks, size), RELAY_RESPONSE_ENVELOPE_MAX);
          closed(envelope, ['protocol', 'response_b64']);
          if (envelope.protocol !== 'xovm2_relay') fail('invalid_relay_response');
          const bytes = canonicalBase64(envelope.response_b64);
          if (bytes.length > MAX_RESPONSE) fail('response_size_limit');
          finish(null, bytes);
        } catch (error) { finish(error); }
      });
      response.on('error', error => finish(error));
    });
    request.setTimeout?.(config.timeoutMs, () => {
      request.destroy();
      finish(Object.assign(new Error(), {code: 'relay_timeout'}));
    });
    request.on('error', error => finish(error));
    request.end(body);
  });
}
