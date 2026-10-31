import assert from 'node:assert/strict';
import test from 'node:test';

import {createAdminHandler} from '../admin.mjs';

function repository(overrides = {}) {
  return {async importBuild() {}, async enableBuild() {}, async revokeBuild() {}, ...overrides};
}

test('admin handler rejects missing or runtime credentials before repository access', async () => {
  let called = false;
  const handler = createAdminHandler({token: 'A'.repeat(32), repository: repository({
    async importBuild() { called = true; },
  })});
  await assert.rejects(handler({authorization: 'B'.repeat(32), operation: 'import'}), {code: 'unauthorized'});
  assert.equal(called, false);
});

test('admin handler routes closed import input to repository only after authentication', async () => {
  let received;
  const handler = createAdminHandler({token: 'A'.repeat(32), repository: repository({
    async importBuild(input) { received = input; return 'validated'; },
  })});
  const input = {publicManifest: {build_id: 'b'}, privateRegistration: {build_id: 'b'},
    verifierSidecars: new Map(), finalArtifactHash: 'f'.repeat(64)};
  assert.equal(await handler({authorization: 'A'.repeat(32), operation: 'import', input}), 'validated');
  assert.equal(received, input);
});

test('admin handler rejects unknown operations and malformed import shape', async () => {
  const handler = createAdminHandler({token: 'A'.repeat(32), repository: repository({
    async importBuild() { throw new Error('should_not_be_called'); },
  })});
  await assert.rejects(handler({authorization: 'A'.repeat(32), operation: 'publish'}),
      {code: 'invalid_admin_request'});
  await assert.rejects(handler({authorization: 'A'.repeat(32), operation: 'import', input: {}}),
      {code: 'invalid_admin_request'});
});
