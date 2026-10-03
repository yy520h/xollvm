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
  // 云值驱动 dispatch 的偏移掩码。必须与客户端编译期 VM_DISPATCH_OFFSET_MASK
  // 一致。云端为每个 window 搜索一个 V，使客户端 HMAC(V, window) & mask == 0。
  // 12-bit → 期望约 2^12 次 HMAC（毫秒级）。位宽越大越安全，但云端搜索越贵；
  // 20-bit 会让每 window 搜索 ~2^20 次而超时（后端有执行时限）。
  dispatchOffsetMask: 0xfff,
  policyVersion: 1,
  // 排错用：为 true 时，在错误响应里附带 event 结构摘要（键名/长度），
  // 不含敏感值。定位后端 event 形态后应保持 false。
  debugEvent: false,
};

const REQUEST_FIELDS = [
  "protocol", "software_id", "version", "build_id", "device_id", "operation",
  "state", "client_nonce", "request_id", "client_time", "code_manifest", "payload",
];
const RESPONSE_FIELDS = [
  "protocol", "ok", "operation", "request_hash", "device_id_hash", "next_state",
  "vm_value", "server_time", "issued_at", "expires_at", "policy_version", "key_id",
  "window_id", "dispatch_blob", "dispatch_v",
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

// 每个 window 只搜索一次；服务端可缓存复用。
const dispatchVCache = new Map();

// 搜索一个 32 字节 V，使客户端计算出的 offset 为 0。
// 客户端算法（cloud_value_manager.cpp）：
//   window 以小端 uint64 的 8 字节参与 HMAC-SHA256(V, window_le64)
//   取摘要前 8 字节按小端解释为 uint64，再 & mask
// 这里必须逐字节复现该算法。
function deriveDispatchV(serverKey, windowId, mask) {
  const cacheKey = `${serverKey}\u0000${windowId}\u0000${mask}`;
  const cached = dispatchVCache.get(cacheKey);
  if (cached) return cached;
  const windowBuf = Buffer.alloc(8);
  windowBuf.writeBigUInt64LE(BigInt(windowId));
  const maskBig = BigInt(mask);
  const limit = (Number(maskBig) + 1) * 16;  // 期望 mask+1，留 16x 余量
  for (let i = 0; i < limit; ++i) {
    const candidate = crypto.createHmac("sha256", serverKey)
      .update(`dispatch-v\u0000${windowId}\u0000${i}`).digest();
    const digest = crypto.createHmac("sha256", candidate).update(windowBuf).digest();
    if ((digest.readBigUInt64LE(0) & maskBig) === 0n) {
      if (dispatchVCache.size > 64) dispatchVCache.clear();
      dispatchVCache.set(cacheKey, candidate);
      return candidate;
    }
  }
  return null;
}

// 兼容入口：把后端可能传入的多种 event 形态归一化为业务请求对象。
// 后端"云端部署代码执行"实际传入的形态并不统一，这里做尽可能强的解包：
// - 直接业务 JSON 对象
// - JSON 字符串（可能被多层转义/字符串化：'"{\"protocol\":...}"'）
// - { body } / { req_arguments } / { arguments } / { data } / { event } 包装
// - 上述包装再套字符串、或再套 { Result: ... }（函数测试回显结构）
function looksLikeRequest(v) {
  return v && typeof v === "object" && !Array.isArray(v) &&
    (v.protocol !== undefined ||
     (v.software_id !== undefined && v.operation !== undefined));
}

function normalizeEvent(event) {
  let v = event;
  // 反复解开“字符串里再套 JSON”，最多 8 层，防止畸形数据死循环。
  for (let depth = 0; depth < 8; ++depth) {
    if (typeof v === "string") {
      try {
        v = JSON.parse(v);
        continue;
      } catch (_) {
        return null;
      }
    }
    if (!v || typeof v !== "object" || Array.isArray(v)) return v;
    if (looksLikeRequest(v)) return v;
    const next =
      v.req_arguments !== undefined ? v.req_arguments :
      v.body !== undefined ? v.body :
      v.arguments !== undefined ? v.arguments :
      v.Result !== undefined ? v.Result :
      v.data !== undefined ? v.data :
      v.event !== undefined ? v.event :
      v.payload !== undefined && typeof v.payload === "object" ? v.payload :
      undefined;
    if (next === undefined) return v;   // 没有已知包装字段，原样返回
    v = next;
  }
  return v;
}

// 只用于排错：给出 event 的结构摘要（键名/类型/长度），不含敏感值。
function describeEvent(event) {
  const seen = [];
  const walk = (v, path, depth) => {
    if (seen.length > 40 || depth > 4) return;
    if (typeof v === "string") {
      seen.push(`${path}: string(len=${v.length})`);
      return;
    }
    if (v === null) { seen.push(`${path}: null`); return; }
    if (typeof v !== "object") { seen.push(`${path}: ${typeof v}`); return; }
    if (Array.isArray(v)) { seen.push(`${path}: array(len=${v.length})`); return; }
    for (const k of Object.keys(v)) walk(v[k], path ? `${path}.${k}` : k, depth + 1);
  };
  walk(event, "", 0);
  return seen.join(" | ");
}

function buildCapabilityResponse(event, context) {
  let request;
  try {
    request = normalizeEvent(event);
  } catch (_) {
    const out = { ok: false, error: "malformed_request" };
    if (CODE_CONFIG.debugEvent) out.event_shape = describeEvent(event);
    return JSON.stringify(out);
  }
  if (!validRequest(request)) {
    const out = { ok: false, error: requestError(request) };
    if (CODE_CONFIG.debugEvent) {
      out.request_type = typeof request;
      out.request_keys = request && typeof request === "object"
        ? Object.keys(request).slice(0, 32) : [];
      out.event_shape = describeEvent(event);
    }
    return JSON.stringify(out);
  }

  const serverKey = CODE_CONFIG.kServer;
  const privateKey = CODE_CONFIG.signingPrivateKey;
  const keyId = CODE_CONFIG.keyId;
  if (!serverKey || !privateKey || !keyId ||
      serverKey.startsWith("REPLACE_WITH_") || privateKey.includes("REPLACE_WITH_")) {
    return JSON.stringify({ ok: false, error: "not_configured" });
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
  const dispatchV = deriveDispatchV(serverKey, windowId,
    Number(CODE_CONFIG.dispatchOffsetMask));
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
    dispatch_v: dispatchV ? dispatchV.toString("base64") : "",
  };
  response.signature = crypto.sign(null, Buffer.from(canonicalizeResponse(response)), privateKey).toString("base64");
  return JSON.stringify(response);
}

// 云端部署代码执行的入口约定：exports.<函数名> = async (event, context) => {...}
// 执行路径形如 "capability_v1.capability_v1"，后端返回该字符串给客户端。
exports.capability_v1 = async (event, context) => {
  return buildCapabilityResponse(event, context);
};

// 兼容旧式 (event, context, callback) / module.exports 引用（本地单测用）。
function capability_v1(event, context, callback) {
  const result = buildCapabilityResponse(event, context);
  if (typeof callback === "function") callback(null, result);
  return result;
}

module.exports = {
  capability_v1,
  buildCapabilityResponse,
  normalizeEvent,
  canonicalizeRequest,
  canonicalizeResponse,
  CODE_CONFIG,
};
