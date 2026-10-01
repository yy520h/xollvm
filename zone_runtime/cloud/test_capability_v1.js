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

console.log("capability_v1 tests passed");
