import assert from 'node:assert/strict';
import test from 'node:test';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

import {createProductionService} from '../production.mjs';

test('production entry point passes JavaScript syntax validation', () => {
  const result = spawnSync(process.execPath,
    ['--check', fileURLToPath(new URL('../main.mjs', import.meta.url))], {encoding: 'utf8'});
  assert.equal(result.status, 0, result.stderr);
});

test('production construction fails closed when adapters are absent', async () => {
  await assert.rejects(createProductionService({}), {code: 'production_adapter_missing'});
});

test('production construction refuses reference-only or incomplete stores', async () => {
  for (const store of [
    {reference_only: true, capabilities: () => ({durability: false})},
    {capabilities: () => ({durability: true, cross_instance_serializability: false})},
    {capabilities: () => ({durability: true, cross_instance_serializability: true})},
  ]) {
    await assert.rejects(createProductionService({pool: {}, store,
      authorization: {}, clock: {}, keyProvider: {}, anonymousPolicy: {}}),
    {code: 'production_adapter_missing'});
  }
});

test('production construction requires independent relay and administrator credentials', async () => {
  await assert.rejects(createProductionService({pool: {}, store: {}, authorization: {}, clock: {},
    keyProvider: {}, anonymousPolicy: {}, relayToken: 'same', adminToken: 'same'}),
  {code: 'production_adapter_missing'});
});

test('production runtime handler denies anonymous builds before minting an authorization grant', async () => {
  let minted = false;
  const store = {
    capabilities: async () => ({durability: true, cross_instance_serializability: true,
      trusted_time: true, production_key_provider: true}),
    selfCheck: async () => ({ready: true}),
  };
  const service = await createProductionService({
    pool: {connect: async () => ({release() {}})},
    store,
    authorization: {authenticateRelayCredential() { minted = true; }},
    clock: {trustedNowMs: () => ({lower_ms: '1000', upper_ms: '1000'})},
    keyProvider: {},
    anonymousPolicy: {authorize: async () => ({allowed: false})},
    adminRepository: {async importBuild() {}, async enableBuild() {}, async revokeBuild() {}},
    relayToken: 'R'.repeat(32), adminToken: 'A'.repeat(32), randomBytes: size => Buffer.alloc(size, 1),
  });
  const bytes = Buffer.from(JSON.stringify({protocol_version: 2}));
  await assert.rejects(service.handleRuntimeRequest(bytes, 'R'.repeat(32)));
  assert.equal(minted, false);
});
