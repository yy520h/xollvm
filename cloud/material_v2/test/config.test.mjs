import assert from 'node:assert/strict';
import test from 'node:test';

import {parseConfig} from '../config.mjs';

const required = {
  DATABASE_URL: 'postgres://material:pass@localhost/material',
  XOVM_RELAY_TOKEN: 'R'.repeat(32),
  XOVM_ADMIN_TOKEN: 'A'.repeat(32),
  XOVM_TRUSTED_TIME_PROVIDER: 'test-time',
  XOVM_SIGNING_KEY_PROVIDER: 'test-keys',
  XOVM_ANONYMOUS_POLICY_PROVIDER: 'test-policy',
  XOVM_TRUST_ROOT_PROVIDER: 'test-root',
};

test('configuration accepts required providers and bounded loopback server settings', () => {
  const config = parseConfig({...required, PORT: '8181'});
  assert.equal(config.host, '127.0.0.1');
  assert.equal(config.port, 8181);
  assert.equal(config.relayToken, required.XOVM_RELAY_TOKEN);
  assert.equal(config.adminToken, required.XOVM_ADMIN_TOKEN);
});

test('configuration fails closed for missing providers, weak secrets, or shared credentials', () => {
  for (const env of [
    {...required, DATABASE_URL: ''},
    {...required, XOVM_RELAY_TOKEN: 'short'},
    {...required, XOVM_ADMIN_TOKEN: required.XOVM_RELAY_TOKEN},
    Object.fromEntries(Object.entries(required).filter(([name]) => name !== 'XOVM_SIGNING_KEY_PROVIDER')),
  ]) assert.throws(() => parseConfig(env), {code: 'invalid_config'});
});

test('configuration rejects unsafe bind address and invalid timeout or size bounds', () => {
  for (const env of [
    {...required, HOST: '0.0.0.0'},
    {...required, REQUEST_TIMEOUT_MS: '20'},
    {...required, MAX_CONCURRENT_REQUESTS: '0'},
    {...required, PORT: '70000'},
  ]) assert.throws(() => parseConfig(env), {code: 'invalid_config'});
});
