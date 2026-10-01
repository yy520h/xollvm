"use strict";

const crypto = require("crypto");

// Replace these values in the cloud editor. Never copy them into the client.
const CODE_CONFIG = {
  kServer: "5eecdd03a41846a21231b1a8ed283cedb6c704bd385c7d56a6ebf42ec9f20833",
  signingPrivateKey: `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKYtg9+dXA9mqw8j15fMlppe2kvS/MjSyS5qSiVty8N/
-----END PRIVATE KEY-----`,
  keyId: "key-1",
  bucketSeconds: 60,
  validSeconds: 300,
  dispatchWindowSeconds: 60,
  policyVersion: 1,
};

const REQUEST_FIELDS = [
  "protocol", "software_id", "version", "build_id", "device_id", "operation",
  "state", "client_nonce", "request_id", "client_time", "code_manifest", "payload",
];
const RESPONSE_FIELDS = [
  "protocol", "ok", "operation", "request_hash", "device_id_hash", "next_state",
  "vm_value", "server_time", "issued_at", "expires_at", "policy_version", "key_id",
  "window_id", "dispatch_blob",
];

function canonicalize(fields, value) {
  return fields.map((field) => {
    const text = String(value[field]);
    return `${field}:${Buffer.byteLength(text, "utf8")}:${text}\n`;
  }).join("");
}

function canonicalizeRequest(request) {
  return canonicalize(REQUEST_FIELDS, request);
}

function canonicalizeResponse(response) {
  return canonicalize(RESPONSE_FIELDS, response);
}

function validId(value) {
  return typeof value === "string" && /^[0-9a-f]+$/i.test(value) && value.length >= 32 && value.length % 2 === 0;
}

function validRequest(request) {
  return request && request.protocol === "capability_v1" &&
    ["software_id", "version", "build_id", "device_id", "operation", "code_manifest"].every(
      (field) => typeof request[field] === "string" && request[field].length > 0
    ) && validId(request.state) && validId(request.client_nonce) && validId(request.request_id) &&
    Number.isSafeInteger(request.client_time) && request.client_time >= 0 &&
    typeof request.payload === "string";
}

function requestError(request) {
  if (!request || typeof request !== "object" || Array.isArray(request)) return "request_not_object";
  if (request.protocol !== "capability_v1") return "protocol_missing_or_invalid";
  for (const field of ["software_id", "version", "build_id", "device_id", "operation", "code_manifest"]) {
    if (typeof request[field] !== "string" || request[field].length === 0) return `${field}_missing_or_invalid`;
  }
  for (const field of ["state", "client_nonce", "request_id"]) {
    if (!validId(request[field])) return `${field}_missing_or_invalid`;
  }
  if (!Number.isSafeInteger(request.client_time) || request.client_time < 0) return "client_time_missing_or_invalid";
  if (typeof request.payload !== "string") return "payload_missing_or_invalid";
  return "invalid_request";
}

function hmac(key, value) {
  return crypto.createHmac("sha256", key).update(value).digest("hex");
}

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function capability_v1(event, context, callback) {
  const finish = (result) => {
    if (typeof callback === "function") callback(null, result);
    return result;
  };
  let request;
  const body = event && event.body;
  const argumentsValue = event && event.req_arguments;
  try {
    request = typeof body === "string"
      ? JSON.parse(body)
      : body && typeof body === "object"
        ? body
        : typeof argumentsValue === "string"
          ? JSON.parse(argumentsValue)
          : argumentsValue && typeof argumentsValue === "object"
            ? argumentsValue
            : event;
  } catch (_) {
    return finish(JSON.stringify({ ok: false, error: "malformed_request" }));
  }
  if (!validRequest(request)) {
    return finish(JSON.stringify({ ok: false, error: requestError(request) }));
  }

  const serverKey = CODE_CONFIG.kServer;
  const privateKey = CODE_CONFIG.signingPrivateKey;
  const keyId = CODE_CONFIG.keyId;
  if (!serverKey || !privateKey || !keyId ||
      serverKey.startsWith("REPLACE_WITH_") || privateKey.includes("REPLACE_WITH_")) {
    return finish(JSON.stringify({ ok: false, error: "not_configured" }));
  }
  const serverTime = context && Number.isSafeInteger(context.serverTime)
    ? context.serverTime : Math.floor(Date.now() / 1000);
  const requestHash = hash(canonicalizeRequest(request));
  const bucketSize = Number(CODE_CONFIG.bucketSeconds);
  const timeBucket = Math.floor(serverTime / bucketSize);
  const nextState = hmac(serverKey, `state-v1\0${request.state}\0${requestHash}\0${request.client_nonce}\0${timeBucket}\0${request.operation}`);
  const vmValue = hmac(serverKey, `vm-v1\0${nextState}\0${requestHash}\0${request.code_manifest}\0${request.device_id}\0${request.operation}`);
  const windowSize = Number(CODE_CONFIG.dispatchWindowSeconds);
  const windowId = String(Math.floor(serverTime / windowSize));
  const dispatchMessage = [
    "dispatch-v1", request.device_id, String(request.client_tick),
    request.client_nonce, windowId, request.code_manifest, request.operation,
  ].join("\u0000");
  const dispatchBlob = crypto.sign(null, Buffer.from(dispatchMessage), privateKey).toString("base64");
  const response = {
    protocol: 1,
    ok: true,
    operation: request.operation,
    request_hash: requestHash,
    device_id_hash: hash(request.device_id),
    next_state: nextState,
    vm_value: vmValue,
    server_time: serverTime,
    issued_at: serverTime,
    expires_at: serverTime + Number(CODE_CONFIG.validSeconds),
    policy_version: Number(CODE_CONFIG.policyVersion),
    key_id: keyId,
    window_id: windowId,
    dispatch_blob: dispatchBlob,
  };
  response.signature = crypto.sign(null, Buffer.from(canonicalizeResponse(response)), privateKey).toString("base64");
  return finish(JSON.stringify(response));
}

module.exports = {
  capability_v1,
  canonicalizeRequest,
  canonicalizeResponse,
  CODE_CONFIG,
};
