"use strict";

const assert = require("assert");
const crypto = require("crypto");
const {
  capability_v1,
  canonicalizeResponse,
  CODE_CONFIG,
} = require("./capability_v1");

const keyPair = crypto.generateKeyPairSync("ed25519");
const privateKey = keyPair.privateKey.export({ type: "pkcs8", format: "pem" });
const publicKey = keyPair.publicKey;
const fixedTime = 1700000000;
// 生产默认掩码已是 12 bit（0xfff），与客户端 VM_DISPATCH_OFFSET_MASK 一致。
CODE_CONFIG.dispatchOffsetMask = 0xfff;

// 复现客户端 cloud_value_manager.cpp 的 offset 算法：
// first 8 bytes of HMAC-SHA256(V, little-endian uint64 window)，小端解释后 & mask。
function clientOffset(v, windowId, mask) {
  const win = Buffer.alloc(8);
  win.writeBigUInt64LE(BigInt(windowId));
  const digest = crypto.createHmac("sha256", v).update(win).digest();
  return digest.readBigUInt64LE(0) & BigInt(mask);
}
const baseRequest = {
  protocol: "capability_v1",
  software_id: "demo",
  version: "1",
  build_id: "build-a",
  device_id: "device-a",
  operation: "decrypt",
  state: "00112233445566778899aabbccddeeff",
  client_nonce: "ffeeddccbbaa99887766554433221100",
  request_id: "0123456789abcdef0123456789abcdef",
  client_time: fixedTime,
  code_manifest: "manifest-a",
  payload: "payload",
};

function invoke(request) {
  CODE_CONFIG.kServer = "server-test-secret";
  CODE_CONFIG.signingPrivateKey = privateKey;
  CODE_CONFIG.keyId = "test-key-1";
  return JSON.parse(
    capability_v1(
      { body: JSON.stringify(request) },
      { serverTime: fixedTime }
    )
  );
}

function invokeDirectEvent(request) {
  CODE_CONFIG.kServer = "server-test-secret";
  CODE_CONFIG.signingPrivateKey = privateKey;
  CODE_CONFIG.keyId = "test-key-1";
  return JSON.parse(capability_v1(request, { serverTime: fixedTime }));
}

function invokeWrappedEvent(event) {
  CODE_CONFIG.kServer = "server-test-secret";
  CODE_CONFIG.signingPrivateKey = privateKey;
  CODE_CONFIG.keyId = "test-key-1";
  return JSON.parse(capability_v1(event, { serverTime: fixedTime }));
}

function invokeWithCallback(request) {
  let callbackResult;
  capability_v1(
    { body: JSON.stringify(request) },
    { serverTime: fixedTime },
    (error, result) => {
      callbackResult = { error, result };
    }
  );
  return callbackResult;
}

const callbackExpected = invoke(baseRequest);
const callbackResult = invokeWithCallback(baseRequest);
assert.strictEqual(callbackResult.error, null);
assert.deepStrictEqual(JSON.parse(callbackResult.result), callbackExpected);
assert.strictEqual(invokeDirectEvent(baseRequest).ok, true);
assert.strictEqual(invokeDirectEvent({ req_arguments: JSON.stringify(baseRequest) }).ok, true);
assert.strictEqual(invokeDirectEvent({ req_arguments: baseRequest }).ok, true);
assert.strictEqual(invokeWrappedEvent({ req_arguments: JSON.stringify(baseRequest) }).ok, true);
assert.deepStrictEqual(invokeDirectEvent({ ...baseRequest, protocol: undefined }), {
  ok: false,
  error: "protocol_missing_or_invalid",
});

assert.deepStrictEqual(invoke(baseRequest), invoke(baseRequest));

for (const field of ["state", "client_nonce", "operation", "build_id", "code_manifest"]) {
  const changed = { ...baseRequest, [field]: `${baseRequest[field]}-changed` };
  assert.notStrictEqual(invoke(baseRequest).vm_value, invoke(changed).vm_value, field);
}

const malformed = invoke({ ...baseRequest, request_id: "short" });
assert.strictEqual(malformed.ok, false);
assert.strictEqual(Object.prototype.hasOwnProperty.call(malformed, "vm_value"), false);
assert.strictEqual(Object.prototype.hasOwnProperty.call(malformed, "signature"), false);

const response = invoke(baseRequest);
const signed = { ...response };
delete signed.signature;
const canonical = Buffer.from(canonicalizeResponse(signed));
assert.strictEqual(
  crypto.verify(null, canonical, publicKey, Buffer.from(response.signature, "base64")),
  true
);

function testDispatchBlobPresent() {
  const serverTime = 1000;
  const event = {
    protocol: "capability_v1",
    software_id: "s", version: "1.0.0", build_id: "b",
    device_id: "hw-device-1", operation: "vm_dispatch",
    state: "00".repeat(16), client_nonce: "11".repeat(16),
    request_id: "22".repeat(16), client_time: serverTime,
    client_tick: 424242, code_manifest: "sha256-manifest", payload: "p",
  };
  CODE_CONFIG.kServer = "server-test-secret";
  CODE_CONFIG.signingPrivateKey = privateKey;
  CODE_CONFIG.keyId = "test-key-1";
  const response = JSON.parse(capability_v1(event, { serverTime }));
  if (typeof response.dispatch_blob !== "string" || response.dispatch_blob.length === 0) {
    throw new Error("dispatch_blob missing");
  }
  if (typeof response.window_id !== "string") {
    throw new Error("window_id missing");
  }
  assert.strictEqual(response.ok, true);
  assert.strictEqual(
    response.window_id,
    String(Math.floor(serverTime / Number(CODE_CONFIG.dispatchWindowSeconds)))
  );
  assert.strictEqual(CODE_CONFIG.dispatchWindowSeconds, 60);
  assert.notStrictEqual(
    Number(CODE_CONFIG.dispatchWindowSeconds),
    Number(CODE_CONFIG.validSeconds),
    "dispatch window must be distinct from capability validity"
  );

  // dispatch_v：32 字节云值，客户端算法下 offset 必须为 0（合法值）
  if (typeof response.dispatch_v !== "string" || response.dispatch_v.length === 0) {
    throw new Error("dispatch_v missing");
  }
  const decodedV = Buffer.from(response.dispatch_v, "base64");
  assert.strictEqual(decodedV.length, 32, "dispatch_v must decode to 32 bytes");
  const mask = Number(CODE_CONFIG.dispatchOffsetMask);
  assert.strictEqual(
    clientOffset(decodedV, response.window_id, mask),
    0n,
    "dispatch_v must make client offset zero"
  );

  const signed = { ...response };
  delete signed.signature;
  assert.strictEqual(
    crypto.verify(null, Buffer.from(canonicalizeResponse(signed)), publicKey, Buffer.from(response.signature, "base64")),
    true
  );
  for (const field of ["window_id", "dispatch_blob"]) {
    const tampered = { ...signed, [field]: `${signed[field]}-tampered` };
    assert.strictEqual(
      crypto.verify(null, Buffer.from(canonicalizeResponse(tampered)), publicKey, Buffer.from(response.signature, "base64")),
      false,
      `signature must cover ${field}`
    );
  }
}
testDispatchBlobPresent();

console.log("capability_v1 tests passed");
