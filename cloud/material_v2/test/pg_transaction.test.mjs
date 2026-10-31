import assert from 'node:assert/strict';
import test from 'node:test';

import {serializableTransaction} from '../pg_transaction.mjs';

function fakePool(handler) {
  const calls = [];
  return {
    calls,
    async connect() {
      return {
        async query(sql) {
          calls.push(sql);
          return handler(sql, calls);
        },
        release() { calls.push('RELEASE'); },
      };
    },
  };
}

test('serializable transaction commits and releases the pooled client', async () => {
  const pool = fakePool(() => ({rows: []}));
  assert.equal(await serializableTransaction(pool, async client => {
    await client.query('SELECT 1');
    return 'ok';
  }), 'ok');
  assert.deepEqual(pool.calls, ['BEGIN ISOLATION LEVEL SERIALIZABLE', 'SELECT 1', 'COMMIT', 'RELEASE']);
});

test('serializable transaction rolls back application failures', async () => {
  const pool = fakePool(() => ({rows: []}));
  await assert.rejects(serializableTransaction(pool, async () => { throw new Error('denied'); }),
      /denied/);
  assert.deepEqual(pool.calls, ['BEGIN ISOLATION LEVEL SERIALIZABLE', 'ROLLBACK', 'RELEASE']);
});

test('serializable transaction retries only SQLSTATE 40001 within its bound', async () => {
  let attempt = 0;
  const pool = fakePool(sql => {
    if (sql === 'COMMIT' && attempt++ < 2) throw Object.assign(new Error('serialization'), {code: '40001'});
    return {rows: []};
  });
  assert.equal(await serializableTransaction(pool, async () => 'committed', {maxRetries: 2}), 'committed');
  assert.equal(pool.calls.filter(call => call === 'BEGIN ISOLATION LEVEL SERIALIZABLE').length, 3);
});

test('serializable transaction does not retry uniqueness or exhausted conflicts', async () => {
  let uniqueAttempts = 0;
  const uniquePool = fakePool(sql => {
    if (sql === 'COMMIT') { ++uniqueAttempts; throw Object.assign(new Error('unique'), {code: '23505'}); }
    return {rows: []};
  });
  await assert.rejects(serializableTransaction(uniquePool, async () => 'no'), error => error.code === '23505');
  assert.equal(uniqueAttempts, 1);

  const exhaustedPool = fakePool(sql => {
    if (sql === 'COMMIT') throw Object.assign(new Error('serialization'), {code: '40001'});
    return {rows: []};
  });
  await assert.rejects(serializableTransaction(exhaustedPool, async () => 'no', {maxRetries: 1}),
      error => error.code === '40001');
  assert.equal(exhaustedPool.calls.filter(call => call === 'BEGIN ISOLATION LEVEL SERIALIZABLE').length, 2);
});
