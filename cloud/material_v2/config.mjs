const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function fail() {
  const error = new Error('invalid_config');
  error.code = 'invalid_config';
  throw error;
}

function integer(value, fallback, minimum, maximum) {
  if (value === undefined) return fallback;
  if (!/^(0|[1-9][0-9]*)$/.test(value)) fail();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) fail();
  return parsed;
}

export function parseConfig(env = process.env) {
  const databaseUrl = env.DATABASE_URL;
  const relayToken = env.XOVM_RELAY_TOKEN;
  const adminToken = env.XOVM_ADMIN_TOKEN;
  const providerNames = ['XOVM_TRUSTED_TIME_PROVIDER', 'XOVM_SIGNING_KEY_PROVIDER',
    'XOVM_ANONYMOUS_POLICY_PROVIDER', 'XOVM_TRUST_ROOT_PROVIDER'];
  if (typeof databaseUrl !== 'string' || !databaseUrl.startsWith('postgres://') &&
      !databaseUrl.startsWith('postgresql://') || typeof relayToken !== 'string' ||
      relayToken.length < 32 || typeof adminToken !== 'string' || adminToken.length < 32 ||
      relayToken === adminToken || providerNames.some(name => !IDENTIFIER.test(env[name] ?? '')) ||
      (env.HOST !== undefined && env.HOST !== '127.0.0.1')) fail();
  return Object.freeze({
    databaseUrl,
    host: '127.0.0.1',
    port: integer(env.PORT, 8080, 1, 65535),
    requestTimeoutMs: integer(env.REQUEST_TIMEOUT_MS, 10000, 100, 120000),
    maxConcurrentRequests: integer(env.MAX_CONCURRENT_REQUESTS, 128, 1, 10000),
    relayToken,
    adminToken,
    providers: Object.freeze({
      trustedTime: env.XOVM_TRUSTED_TIME_PROVIDER,
      signingKey: env.XOVM_SIGNING_KEY_PROVIDER,
      anonymousPolicy: env.XOVM_ANONYMOUS_POLICY_PROVIDER,
      trustRoot: env.XOVM_TRUST_ROOT_PROVIDER,
    }),
  });
}
