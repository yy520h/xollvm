import assert from 'node:assert/strict';
import {generateKeyPairSync, sign} from 'node:crypto';
import test from 'node:test';

import {decodeCanonical} from '../codec.mjs';
import {verifyTrustBundle} from '../protocol.mjs';
import {createTrustBundleProvider} from '../trust_bundle.mjs';

const now = {lower_ms: '1000', upper_ms: '1001'};

function fixture(overrides = {}) {
  const root = generateKeyPairSync('ed25519');
  const signing = generateKeyPairSync('ed25519');
  const rootPublic = root.publicKey.export({format: 'der', type: 'spki'}).subarray(-32);
  const signingPublic = signing.publicKey.export({format: 'der', type: 'spki'}).subarray(-32);
  const keyProvider = {
    async publicMetadata(softwareId) {
      return {
        software_id: softwareId,
        root_key_id: 'root-test',
        root_public_key: rootPublic,
        trust_epoch: '4',
        counter_epoch: '55'.repeat(32),
        bundle_valid_until_ms: '9000',
        keys: [{key_id: 'sign-test', public_key: signingPublic,
          not_before_ms: '900', signing_until_ms: '8000', not_after_ms: '8500', status: 'active'}],
      };
    },
    async signRoot(bytes) { return sign(null, bytes, root.privateKey); },
  };
  return {rootPublic, keyProvider, clock: {trustedNowMs: () => now},
    buildRepository: {async hasSoftware(id) { return id === 'test.software'; }}, overrides};
}

test('public trust bundle is signed and contains no private key fields', async () => {
  const options = fixture();
  const provider = createTrustBundleProvider(options);
  const {bytes, bootstrap} = await provider.getPublicTrustBundle('test.software');
  const installed = verifyTrustBundle(bytes, {root_key_id: 'root-test',
    root_public_key: options.rootPublic, software_id: 'test.software', trusted_time: now});
  assert.ok(installed);
  assert.equal(bootstrap.root_key_id, 'root-test');
  assert.equal(bootstrap.root_public_key, options.rootPublic.toString('base64'));
  assert.equal(Buffer.from(bytes).toString('ascii').includes('private_key'), false);
});

test('trust bundle provider rejects unknown software and invalid trusted time', async () => {
  const options = fixture();
  const provider = createTrustBundleProvider(options);
  await assert.rejects(provider.getPublicTrustBundle('other.software'), {code: 'build_unavailable'});
  const badClock = createTrustBundleProvider({...options,
    clock: {trustedNowMs: () => ({lower_ms: '9001', upper_ms: '9002'})}});
  await assert.rejects(badClock.getPublicTrustBundle('test.software'), {code: 'untrusted_time'});
});

test('trust bundle provider requires monotonic positive trust epoch and bounded key validity', async () => {
  const options = fixture();
  const badProvider = createTrustBundleProvider({...options, keyProvider: {
    async publicMetadata(id) {
      const value = await options.keyProvider.publicMetadata(id);
      return {...value, trust_epoch: '0'};
    },
  }});
  await assert.rejects(badProvider.getPublicTrustBundle('test.software'), {code: 'invalid_trust_bundle'});
});
