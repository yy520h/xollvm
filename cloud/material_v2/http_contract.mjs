import {MAX_REQUEST, MAX_RESPONSE, parseRequest} from './protocol.mjs';
import {parseStrictJsonObject} from './strict_json.mjs';

export const RELAY_REQUEST_ENVELOPE_MAX = Buffer.byteLength(
    JSON.stringify({protocol: 'xovm2_relay', request_b64: 'A'.repeat(4 * Math.ceil(MAX_REQUEST / 3))}));
export const RELAY_RESPONSE_ENVELOPE_MAX = Buffer.byteLength(
    JSON.stringify({protocol: 'xovm2_relay', response_b64: 'A'.repeat(4 * Math.ceil(MAX_RESPONSE / 3))}));

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function closed(value, fields) {
  if (Object.getPrototypeOf(value) !== null || Object.keys(value).length !== fields.length ||
      fields.some(field => !Object.hasOwn(value, field))) fail('invalid_schema');
}

function contentType(headers) {
  const value = headers?.['content-type'] ?? headers?.get?.('content-type');
  if (typeof value !== 'string' || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(value))
    fail('invalid_content_type');
}

function decodeBase64(value) {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
    fail('invalid_base64');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) fail('invalid_base64');
  return bytes;
}

export function parseRelayRequest(headers, bodyBytes) {
  contentType(headers);
  const envelope = parseStrictJsonObject(bodyBytes, RELAY_REQUEST_ENVELOPE_MAX);
  closed(envelope, ['protocol', 'request_b64']);
  if (envelope.protocol !== 'xovm2_relay') fail('invalid_protocol');
  const requestBytes = decodeBase64(envelope.request_b64);
  parseRequest(requestBytes);
  return {requestBytes};
}

export function encodeRelaySuccess(responseBytes) {
  if (!(responseBytes instanceof Uint8Array) || responseBytes.length > MAX_RESPONSE)
    fail('response_size_limit');
  return Buffer.from(JSON.stringify({protocol: 'xovm2_relay',
    response_b64: Buffer.from(responseBytes).toString('base64')}), 'utf8');
}
