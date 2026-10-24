import assert from 'node:assert/strict';
import {
  createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes,
} from 'node:crypto';
import test from 'node:test';

import {encodeCanonical} from '../codec.mjs';
import {requestHash, SUITE} from '../protocol.mjs';
import {
  ReferenceAuthProvider, ReferenceMemoryStore, enableBuildRequestHash,
  productionStatus, registerBuildRequestHash, revokeBuildRequestHash, startProductionService,
} from '../store.mjs';
import {handleSession, issueMaterial} from '../service.mjs';
import {fixtureRegion, registrationFixture, rehashRegion} from './material_fixture.mjs';

const X25519_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const COUNTER_EPOCH = 'c1'.repeat(32);
const FINAL_HASH = 'fa'.repeat(32);
const NOW = 1000000n;
const AUTH_DEFAULTS = Object.freeze({
  issuer_id: 'test-issuer', subject_id: 'test-subject', software_id: 'test.software',
  device_binding: 'd1'.repeat(32), valid_until_ms: '1800000',
});

function makeRandom(seed = 1) {
  let value = seed;
  return size => {
    const result = Buffer.alloc(size);
    for (let index = 0; index < size; ++index) result[index] = value++ & 0xff;
    return result;
  };
}

function clientKey(seed) {
  const raw = Buffer.alloc(32, seed);
  const privateKey = createPrivateKey({
    key: Buffer.concat([X25519_PKCS8, raw]), format: 'der', type: 'pkcs8',
  });
  return {
    privateKey,
    publicKey: createPublicKey(privateKey).export({format: 'der', type: 'spki'}).subarray(-32),
  };
}

function requestFactory(manifest) {
  let serial = 1;
  return (type, extra = {}, reuse = {}) => {
    const current = serial++;
    const key = reuse.key ?? clientKey(current);
    const requestId = reuse.request_id ?? Buffer.alloc(32, current + 30).toString('hex');
    const nonce = reuse.client_nonce ?? Buffer.alloc(32, current + 90).toString('hex');
    const value = {
      protocol_version: 2,
      suite: SUITE,
      type,
      software_id: manifest.software_id,
      build_id: manifest.build_id,
      final_artifact_hash: FINAL_HASH,
      request_id: requestId,
      client_nonce: nonce,
      client_ephemeral_key: key.publicKey.toString('base64'),
      ...extra,
    };
    return {value, bytes: encodeCanonical(value), key};
  };
}

function response(bytes) {
  return JSON.parse(Buffer.from(bytes).toString('ascii'));
}

async function setup(options = {}) {
  const first = fixtureRegion('test/first', 'lease');
  const second = fixtureRegion('test/second', 'session');
  const registration = registrationFixture([first, second]);
  const signing = generateKeyPairSync('ed25519');
  const events = [];
  const store = new ReferenceMemoryStore({
    counter_epoch: COUNTER_EPOCH,
    signing_key: {
      key_id: 'reference-signing', private_key: signing.privateKey,
      public_key: signing.publicKey.export({format: 'der', type: 'spki'}).subarray(-32),
      trust_epoch: '1', not_before_ms: '900000', signing_until_ms: '1900000',
      not_after_ms: '2000000', bundle_valid_until_ms: '2000000',
    },
    probe: event => events.push(event),
    ...options,
  });
  const provider = new ReferenceAuthProvider(store, AUTH_DEFAULTS);
  const clock = {trustedNowMs: () => ({lower_ms: NOW.toString(), upper_ms: NOW.toString()})};
  const registerHash = registerBuildRequestHash(registration.manifest,
    registration.registration, registration.verifiers);
  await store.registerBuild(registration.manifest, registration.registration,
      registration.verifiers, provider.authenticate(registerHash, ['build.publish']));
  const enableHash = enableBuildRequestHash(registration.manifest.build_id, FINAL_HASH);
  await store.enableBuild(registration.manifest.build_id, FINAL_HASH,
    provider.authenticate(enableHash, ['build.publish']));
  const makeRequest = requestFactory(registration.manifest);
  const authFor = (entry, scopes = ['session.control', 'material.issue']) =>
    provider.authenticate(requestHash(entry.bytes), scopes);
  const open = makeRequest('session.open');
  const openBytes = await handleSession(open.bytes, authFor(open), store, clock, makeRandom(10));
  const opened = response(openBytes).transcript;
  return {first, second, registration, store, provider, clock, events, makeRequest,
    authFor, opened, revokeBuild: () => store.revokeBuild(registration.manifest.build_id,
      provider.authenticate(revokeBuildRequestHash(registration.manifest.build_id),
        ['build.revoke']))};
}

function issueRequest(state, region, extra = {}, reuse = {}) {
  return state.makeRequest('material.issue', {
    session_id: state.opened.session_id,
    counter_epoch: state.opened.counter_epoch,
    region_id: region.region.region_id,
    engine_abi_hash: region.region.engine_abi_hash,
    mode: region.region.mode,
    previous_generation: '0',
    ...extra,
  }, reuse);
}

test('registration recomputes identities and privately reloads exact verifier sidecars', async () => {
  const state = await setup();
  assert.deepEqual(state.events.filter(event => event.kind === 'build_state')
      .map(event => event.state), ['pending', 'validated', 'enabled']);
  const view = await state.store.referenceInspectBuild(state.registration.manifest.build_id);
  assert.equal(view.state, 'enabled');
  assert.equal(JSON.stringify(view).includes('canonical_bc'), false);
  assert.equal(JSON.stringify(state.registration.manifest).includes('verifier'), false);

  const corruptSidecars = new Map(state.registration.verifiers);
  const corruptBytes = Buffer.from(corruptSidecars.get(state.first.region.region_id));
  corruptBytes[0] ^= 1;
  corruptSidecars.set(state.first.region.region_id, corruptBytes);
  await assert.rejects(state.store.registerBuild(state.registration.manifest,
    state.registration.registration, corruptSidecars,
    state.provider.authenticate(registerBuildRequestHash(state.registration.manifest,
      state.registration.registration, corruptSidecars), ['build.publish'])),
  {code: 'invalid_verifier_descriptor'});

  const changed = structuredClone(state.registration.registration);
  changed.regions[0].canonical_bc = Buffer.from([1]).toString('base64');
  rehashRegion(changed.regions[0]);
  const other = new ReferenceMemoryStore({counter_epoch: COUNTER_EPOCH,
    signing_key: state.store.referenceSigningKeyForTest()});
  const otherProvider = new ReferenceAuthProvider(other, AUTH_DEFAULTS);
  await assert.rejects(other.registerBuild(state.registration.manifest, changed,
    state.registration.verifiers, otherProvider.authenticate(registerBuildRequestHash(
      state.registration.manifest, changed, state.registration.verifiers), ['build.publish'])));

  const request = issueRequest(state, state.first);
  await state.store.referenceCorruptVerifierForTest(
      state.registration.manifest.build_id, state.first.region.region_id);
  await assert.rejects(issueMaterial(request.bytes, state.authFor(request), state.store,
    state.clock, makeRandom(20)), {code: 'invalid_verifier_descriptor'});
  assert.equal((await state.store.referenceStats()).published_generations, 0);
});

test('build administration requires content-bound publisher and revoker capabilities', async () => {
  const region = fixtureRegion('test/admin', 'lease');
  const registration = registrationFixture([region]);
  const signing = generateKeyPairSync('ed25519');
  const store = new ReferenceMemoryStore({counter_epoch: COUNTER_EPOCH, signing_key: {
    key_id: 'reference-signing', private_key: signing.privateKey,
    public_key: signing.publicKey.export({format: 'der', type: 'spki'}).subarray(-32),
    trust_epoch: '1', not_before_ms: '900000', signing_until_ms: '1900000',
    not_after_ms: '2000000', bundle_valid_until_ms: '2000000',
  }});
  const provider = new ReferenceAuthProvider(store, AUTH_DEFAULTS);
  await assert.rejects(store.registerBuild(registration.manifest, registration.registration,
    registration.verifiers), {code: 'unauthorized'});
  const digest = registerBuildRequestHash(registration.manifest, registration.registration,
    registration.verifiers);
  await assert.rejects(store.registerBuild(registration.manifest, registration.registration,
    registration.verifiers, provider.authenticate(digest, ['material.issue'])),
  {code: 'unauthorized'});
  await store.registerBuild(registration.manifest, registration.registration,
    registration.verifiers, provider.authenticate(digest, ['build.publish']));
  await assert.rejects(store.enableBuild(registration.manifest.build_id, FINAL_HASH,
    provider.authenticate(enableBuildRequestHash(registration.manifest.build_id,
      'fb'.repeat(32)), ['build.publish'])), {code: 'unauthorized'});
  await store.enableBuild(registration.manifest.build_id, FINAL_HASH,
    provider.authenticate(enableBuildRequestHash(registration.manifest.build_id, FINAL_HASH),
      ['build.publish']));
  await assert.rejects(store.revokeBuild(registration.manifest.build_id,
    provider.authenticate(revokeBuildRequestHash('00'.repeat(32)), ['build.revoke'])),
  {code: 'unauthorized'});
});

test('same request returns identical committed bytes and conflicting hash allocates nothing', async () => {
  const state = await setup();
  const request = issueRequest(state, state.first);
  const auth = state.authFor(request);
  const first = await issueMaterial(request.bytes, auth, state.store, state.clock, makeRandom(30));
  const retry = await issueMaterial(request.bytes, state.authFor(request), state.store,
      state.clock, makeRandom(200));
  assert.deepEqual(retry, first);
  const conflict = issueRequest(state, state.first, {}, {request_id: request.value.request_id});
  await assert.rejects(issueMaterial(conflict.bytes, state.authFor(conflict), state.store,
    state.clock, makeRandom(40)), {code: 'request_conflict'});
  assert.equal((await state.store.referenceStats()).published_generations, 1);
});

test('concurrent response-loss retries commit one generation and return identical bytes', async () => {
  const state = await setup();
  const request = issueRequest(state, state.first);
  const [first, retry] = await Promise.all([
    issueMaterial(request.bytes, state.authFor(request), state.store,
      state.clock, makeRandom(41)),
    issueMaterial(request.bytes, state.authFor(request), state.store,
      state.clock, makeRandom(42)),
  ]);
  assert.deepEqual(retry, first);
  assert.equal((await state.store.referenceStats()).published_generations, 1);
});

test('concurrent renew and issues allocate monotonic per-region generations', async () => {
  const state = await setup();
  const first = issueRequest(state, state.first);
  const second = issueRequest(state, state.first);
  const otherRegion = issueRequest(state, state.second);
  const renew = state.makeRequest('session.renew', {
    session_id: state.opened.session_id, counter_epoch: state.opened.counter_epoch,
    previous_counter: state.opened.counter,
  });
  const results = await Promise.all([
    issueMaterial(first.bytes, state.authFor(first), state.store, state.clock, makeRandom(50)),
    issueMaterial(second.bytes, state.authFor(second), state.store, state.clock, makeRandom(60)),
    issueMaterial(otherRegion.bytes, state.authFor(otherRegion), state.store, state.clock, makeRandom(70)),
    handleSession(renew.bytes, state.authFor(renew), state.store, state.clock, makeRandom(80)),
  ]);
  assert.deepEqual(results.slice(0, 2).map(item => response(item).transcript.binding.generation).sort(),
    ['1', '2']);
  assert.equal(response(results[2]).transcript.binding.generation, '1');
  assert.notEqual(response(results[3]).transcript.counter, state.opened.counter);
});

test('session open retries a random session id collision without replacing the old session', async () => {
  const state = await setup();
  const next = state.makeRequest('session.open');
  const collision = Buffer.from(state.opened.session_id, 'hex');
  let calls = 0;
  const bytes = await handleSession(next.bytes, state.authFor(next), state.store, state.clock,
    size => ++calls === 1 ? collision : Buffer.alloc(size, 0x42));
  const opened = response(bytes).transcript;
  assert.notEqual(opened.session_id, state.opened.session_id);
  assert.equal(opened.session_id, '42'.repeat(32));
  const oldRequest = issueRequest(state, state.first);
  const oldBytes = await issueMaterial(oldRequest.bytes, state.authFor(oldRequest), state.store,
    state.clock, makeRandom(89));
  assert.equal(response(oldBytes).transcript.session_id, state.opened.session_id);
});

test('revocation linearizes against new issuance and cached response delivery', async () => {
  const state = await setup();
  const before = issueRequest(state, state.first);
  const bytes = await issueMaterial(before.bytes, state.authFor(before), state.store,
      state.clock, makeRandom(90));
  assert.equal(response(bytes).transcript.binding.generation, '1');
  await state.revokeBuild();
  const after = issueRequest(state, state.first, {previous_generation: '1'});
  await assert.rejects(issueMaterial(after.bytes, state.authFor(after), state.store,
    state.clock, makeRandom(100)), {code: 'build_unavailable'});
  await assert.rejects(issueMaterial(before.bytes, state.authFor(before), state.store,
    state.clock, makeRandom(110)), {code: 'build_unavailable'});
  assert.equal((await state.store.referenceStats()).published_generations, 1);
});

test('issue and revoke races have one serial order and never publish after revoke', async () => {
  {
    const state = await setup();
    const request = issueRequest(state, state.first);
    const [issued] = await Promise.all([
      issueMaterial(request.bytes, state.authFor(request), state.store,
        state.clock, makeRandom(111)),
      state.revokeBuild(),
    ]);
    assert.equal(response(issued).transcript.binding.generation, '1');
    assert.equal((await state.store.referenceStats()).published_generations, 1);
  }
  {
    const state = await setup();
    const request = issueRequest(state, state.first);
    const revoked = state.revokeBuild();
    const issued = issueMaterial(request.bytes, state.authFor(request), state.store,
      state.clock, makeRandom(112));
    await revoked;
    await assert.rejects(issued, {code: 'build_unavailable'});
    assert.equal((await state.store.referenceStats()).published_generations, 0);
  }
});

test('closed session cannot retrieve a previously committed material response', async () => {
  const state = await setup();
  const request = issueRequest(state, state.first);
  await issueMaterial(request.bytes, state.authFor(request), state.store,
    state.clock, makeRandom(113));
  const close = state.makeRequest('session.close', {
    session_id: state.opened.session_id, counter_epoch: state.opened.counter_epoch,
    previous_counter: state.opened.counter,
  });
  await handleSession(close.bytes, state.authFor(close), state.store,
    state.clock, makeRandom(114));
  await assert.rejects(issueMaterial(request.bytes, state.authFor(request), state.store,
    state.clock, makeRandom(115)), {code: 'session_closed'});
  assert.equal((await state.store.referenceStats()).published_generations, 1);
});

test('expired authorization cannot retrieve a previously committed response', async () => {
  const state = await setup();
  const request = issueRequest(state, state.first);
  await issueMaterial(request.bytes, state.authFor(request), state.store,
    state.clock, makeRandom(116));
  const expiredClock = {trustedNowMs: () => ({lower_ms: '1800000', upper_ms: '1800000'})};
  await assert.rejects(issueMaterial(request.bytes, state.authFor(request), state.store,
    expiredClock, makeRandom(117)), {code: 'unauthorized'});
  assert.equal((await state.store.referenceStats()).published_generations, 1);
});

test('closed session cannot retrieve a previously committed renew response', async () => {
  const state = await setup();
  const renew = state.makeRequest('session.renew', {
    session_id: state.opened.session_id, counter_epoch: state.opened.counter_epoch,
    previous_counter: state.opened.counter,
  });
  await handleSession(renew.bytes, state.authFor(renew), state.store,
    state.clock, makeRandom(118));
  const close = state.makeRequest('session.close', {
    session_id: state.opened.session_id, counter_epoch: state.opened.counter_epoch,
    previous_counter: state.opened.counter,
  });
  await handleSession(close.bytes, state.authFor(close), state.store,
    state.clock, makeRandom(119));
  await assert.rejects(handleSession(renew.bytes, state.authFor(renew), state.store,
    state.clock, makeRandom(120)), {code: 'session_closed'});
});

test('nonce and ephemeral reuse fences span sessions but exact retries remain valid', async () => {
  const state = await setup();
  const first = issueRequest(state, state.first);
  await issueMaterial(first.bytes, state.authFor(first), state.store, state.clock, makeRandom(120));
  const nextOpen = state.makeRequest('session.open');
  const nextOpenBytes = await handleSession(nextOpen.bytes, state.authFor(nextOpen), state.store,
    state.clock, makeRandom(121));
  const secondSession = response(nextOpenBytes).transcript;
  for (const reuse of [
    {client_nonce: first.value.client_nonce},
    {key: first.key},
  ]) {
    const next = state.makeRequest('material.issue', {
      session_id: secondSession.session_id,
      counter_epoch: secondSession.counter_epoch,
      region_id: state.first.region.region_id,
      engine_abi_hash: state.first.region.engine_abi_hash,
      mode: state.first.region.mode,
      previous_generation: '0',
    }, reuse);
    await assert.rejects(issueMaterial(next.bytes, state.authFor(next), state.store,
      state.clock, makeRandom(130)), {code: 'invalid_key'});
  }
  assert.equal((await state.store.referenceStats()).published_generations, 1);
});

test('server nonce and ephemeral reuse rejects the second logical response atomically', async () => {
  const state = await setup();
  const repeatedRandom = size => Buffer.alloc(size, 1);
  const first = issueRequest(state, state.first);
  const second = issueRequest(state, state.first);
  await issueMaterial(first.bytes, state.authFor(first), state.store,
    state.clock, repeatedRandom);
  await assert.rejects(issueMaterial(second.bytes, state.authFor(second), state.store,
    state.clock, repeatedRandom), {code: 'invalid_key'});
  assert.equal((await state.store.referenceStats()).published_generations, 1);
});

test('overflow and signing failure roll back generation counter and reply atomically', async () => {
  {
    const state = await setup();
    await state.store.referenceSetGenerationForTest(state.opened.session_id,
      state.first.region.region_id, 0xffffffffffffffffn);
    const request = issueRequest(state, state.first,
      {previous_generation: '18446744073709551615'});
    await assert.rejects(issueMaterial(request.bytes, state.authFor(request), state.store,
      state.clock, makeRandom(140)), {code: 'counter_exhausted'});
    assert.equal((await state.store.referenceStats()).published_replies, 1);
  }
  {
    const state = await setup();
    await state.store.referenceSetCounterForTest(state.opened.counter_epoch,
      state.registration.manifest.software_id, state.registration.manifest.build_id,
      state.first.region.region_id, 0xffffffffffffffffn);
    const request = issueRequest(state, state.first);
    await assert.rejects(issueMaterial(request.bytes, state.authFor(request), state.store,
      state.clock, makeRandom(150)), {code: 'counter_exhausted'});
    assert.equal((await state.store.referenceStats()).published_generations, 0);
  }
  {
    const state = await setup();
    state.store.referenceFailNextSignForTest();
    const failed = issueRequest(state, state.first);
    await assert.rejects(issueMaterial(failed.bytes, state.authFor(failed), state.store,
      state.clock, makeRandom(160)), {code: 'key_unavailable'});
    const recovered = issueRequest(state, state.first);
    const bytes = await issueMaterial(recovered.bytes, state.authFor(recovered), state.store,
      state.clock, makeRandom(170));
    assert.equal(response(bytes).transcript.binding.generation, '1');
  }
  {
    const state = await setup();
    state.store.referenceFailNextCommitForTest();
    const failed = issueRequest(state, state.first);
    await assert.rejects(issueMaterial(failed.bytes, state.authFor(failed), state.store,
      state.clock, makeRandom(171)), {code: 'store_unavailable'});
    const recovered = issueRequest(state, state.first);
    const bytes = await issueMaterial(recovered.bytes, state.authFor(recovered), state.store,
      state.clock, makeRandom(172));
    assert.equal(response(bytes).transcript.binding.generation, '1');
    assert.equal((await state.store.referenceStats()).published_generations, 1);
  }
});

test('trusted time is rechecked before commit and expiry rolls the transaction back', async () => {
  const state = await setup();
  let calls = 0;
  const expiringClock = {trustedNowMs: () => {
    ++calls;
    return calls === 1
      ? {lower_ms: NOW.toString(), upper_ms: NOW.toString()}
      : {lower_ms: '1800000', upper_ms: '1800000'};
  }};
  const request = issueRequest(state, state.first);
  await assert.rejects(issueMaterial(request.bytes, state.authFor(request), state.store,
    expiringClock, makeRandom(173)), {code: 'authority_unavailable'});
  assert.ok(calls >= 2);
  assert.equal((await state.store.referenceStats()).published_generations, 0);
});

test('authorization failure and operation policy publish no generation', async () => {
  const state = await setup();
  const request = issueRequest(state, state.first);
  await state.provider.revoke();
  await assert.rejects(issueMaterial(request.bytes, state.authFor(request), state.store,
    state.clock, makeRandom(180)), {code: 'unauthorized'});
  assert.equal((await state.store.referenceStats()).published_generations, 0);

  const operation = issueRequest(state, state.first, {mode: 'operation'});
  await assert.rejects(issueMaterial(operation.bytes, state.authFor(operation), state.store,
    state.clock, makeRandom(190)), {code: 'operation_not_implemented'});
  assert.equal((await state.store.referenceStats()).published_generations, 0);
});

test('operation policy may be registered but is never issued as session or lease material', async () => {
  const operation = fixtureRegion('test/operation', 'operation');
  const registration = registrationFixture([operation]);
  const signing = generateKeyPairSync('ed25519');
  const store = new ReferenceMemoryStore({
    counter_epoch: COUNTER_EPOCH,
    signing_key: {
      key_id: 'reference-signing', private_key: signing.privateKey,
      public_key: signing.publicKey.export({format: 'der', type: 'spki'}).subarray(-32),
      trust_epoch: '1', not_before_ms: '900000', signing_until_ms: '1900000',
      not_after_ms: '2000000', bundle_valid_until_ms: '2000000',
    },
  });
  const provider = new ReferenceAuthProvider(store, AUTH_DEFAULTS);
  await store.registerBuild(registration.manifest, registration.registration,
    registration.verifiers, provider.authenticate(registerBuildRequestHash(registration.manifest,
      registration.registration, registration.verifiers), ['build.publish']));
  await store.enableBuild(registration.manifest.build_id, FINAL_HASH,
    provider.authenticate(enableBuildRequestHash(registration.manifest.build_id, FINAL_HASH),
      ['build.publish']));
  assert.equal((await store.referenceInspectBuild(registration.manifest.build_id)).state,
    'enabled');
});

test('production startup remains blocked even when reference adapters self-report capabilities', async () => {
  const state = await setup();
  assert.equal(productionStatus().status, 'BLOCKED');
  assert.equal(productionStatus().code, 'production_adapter_missing');
  await assert.rejects(startProductionService({
    store: state.store, auth_provider: state.provider, clock: state.clock,
    key_provider: state.store,
  }), {code: 'production_adapter_missing'});
});
