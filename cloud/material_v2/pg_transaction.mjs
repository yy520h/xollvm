export async function serializableTransaction(pool, callback, options = {}) {
  const maxRetries = options.maxRetries ?? 3;
  if (!pool || typeof pool.connect !== 'function' || typeof callback !== 'function' ||
      !Number.isInteger(maxRetries) || maxRetries < 0 || maxRetries > 10)
    throw Object.assign(new Error('invalid_transaction'), {code: 'invalid_transaction'});

  for (let attempt = 0; ; ++attempt) {
    const client = await pool.connect();
    let open = false;
    try {
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      open = true;
      const result = await callback(client);
      await client.query('COMMIT');
      open = false;
      return result;
    } catch (error) {
      if (open) {
        try { await client.query('ROLLBACK'); }
        catch { /* Preserve the transaction failure. */ }
      }
      if (error?.code !== '40001' || attempt >= maxRetries) throw error;
    } finally {
      client.release();
    }
  }
}
