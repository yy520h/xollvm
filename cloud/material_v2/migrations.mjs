import {createHash} from 'node:crypto';

import {serializableTransaction} from './pg_transaction.mjs';

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

export async function applyMigrations(pool, migrations) {
  if (!Array.isArray(migrations) || migrations.some((migration, index) =>
      migration?.version !== index + 1 || typeof migration.sql !== 'string') ||
      new Set(migrations.map(migration => migration.version)).size !== migrations.length)
    fail('invalid_migrations');
  return serializableTransaction(pool, async client => {
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      version integer PRIMARY KEY,
      checksum bytea NOT NULL CHECK (octet_length(checksum) = 32),
      applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
    )`);
    const current = await client.query('SELECT version, checksum FROM schema_migrations ORDER BY version');
    if (current.rows.length > migrations.length) fail('migration_history_mismatch');
    for (let index = 0; index < current.rows.length; ++index) {
      const migration = migrations[index];
      const expected = createHash('sha256').update(migration.sql).digest();
      const row = current.rows[index];
      if (Number(row.version) !== migration.version || !Buffer.from(row.checksum).equals(expected))
        fail('migration_checksum_mismatch');
    }
    for (let index = current.rows.length; index < migrations.length; ++index) {
      const migration = migrations[index];
      const checksum = createHash('sha256').update(migration.sql).digest();
      await client.query(migration.sql);
      await client.query('INSERT INTO schema_migrations(version, checksum) VALUES ($1, $2)',
          [migration.version, checksum]);
    }
  });
}
