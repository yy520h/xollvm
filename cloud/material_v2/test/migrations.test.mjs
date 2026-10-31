import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import test from 'node:test';

import {applyMigrations} from '../migrations.mjs';

const migration = {version: 1, sql: 'CREATE TABLE builds (build_id text);'};

function poolFor(existing = []) {
  const calls = [];
  return {
    calls,
    async connect() {
      return {
        async query(sql, params) {
          calls.push({sql, params});
          if (sql.startsWith('SELECT version, checksum')) return {rows: existing};
          return {rows: []};
        },
        release() { calls.push({sql: 'RELEASE'}); },
      };
    },
  };
}

test('migration runner records SHA-256 and applies a new migration atomically', async () => {
  const pool = poolFor();
  await applyMigrations(pool, [migration]);
  const insert = pool.calls.find(call => call.sql.startsWith('INSERT INTO schema_migrations'));
  assert.equal(insert.params[0], 1);
  assert.deepEqual(insert.params[1], createHash('sha256').update(migration.sql).digest());
  assert.ok(pool.calls.some(call => call.sql === 'BEGIN ISOLATION LEVEL SERIALIZABLE'));
  assert.ok(pool.calls.some(call => call.sql === 'COMMIT'));
});

test('migration runner rejects changed migration checksum', async () => {
  const pool = poolFor([{version: 1, checksum: Buffer.alloc(32)}]);
  await assert.rejects(applyMigrations(pool, [migration]), {code: 'migration_checksum_mismatch'});
});

test('migration runner rejects gaps and duplicate versions', async () => {
  await assert.rejects(applyMigrations(poolFor(), [{version: 2, sql: 'select 1'}]),
      {code: 'invalid_migrations'});
  await assert.rejects(applyMigrations(poolFor(), [migration, migration]),
      {code: 'invalid_migrations'});
});
