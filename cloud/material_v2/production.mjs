import {timingSafeEqual} from 'node:crypto';

import {handleSession, issueMaterial} from './service.mjs';
import {parseRequest, requestHash} from './protocol.mjs';
import {createAdminHandler} from './admin.mjs';

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function equalSecret(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string') return false;
  const left = Buffer.from(actual);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

export async function createProductionService(options = {}) {
  const {pool, store, authorization, clock, keyProvider, anonymousPolicy,
    relayToken, adminToken} = options;
  const missing = !pool || typeof pool.connect !== 'function' || !store ||
    store.reference_only === true || typeof store.capabilities !== 'function' ||
    !authorization || typeof authorization.authenticateRelayCredential !== 'function' ||
    !clock || typeof clock.trustedNowMs !== 'function' || !keyProvider ||
    !anonymousPolicy || typeof anonymousPolicy.authorize !== 'function' ||
    typeof relayToken !== 'string' || relayToken.length < 32 ||
    typeof adminToken !== 'string' || adminToken.length < 32 || relayToken === adminToken;
  if (missing) fail('production_adapter_missing');
  const capabilities = await store.capabilities();
  if (capabilities.durability !== true || capabilities.cross_instance_serializability !== true ||
      capabilities.trusted_time !== true || capabilities.production_key_provider !== true ||
      typeof store.selfCheck !== 'function' || (await store.selfCheck()).ready !== true)
    fail('production_adapter_missing');
  const admin = createAdminHandler({token: adminToken, repository: options.adminRepository});

  const authenticate = async (header, requestBytes, requiredScope, q) => {
    if (!equalSecret(header, relayToken)) fail('unauthorized');
    const policy = await anonymousPolicy.authorize({
      build_id: q.build_id,
      software_id: q.software_id,
      region_id: q.region_id,
      mode: q.mode,
      type: q.type,
      request_hash: requestHash(requestBytes),
    });
    if (!policy?.allowed || policy.build_state !== 'enabled' ||
        policy.software_id !== q.software_id ||
        (q.region_id && !policy.region_ids?.includes(q.region_id)) ||
        (q.mode && !policy.modes?.includes(q.mode)) ||
        !Number.isSafeInteger(policy.valid_from_ms) || !Number.isSafeInteger(policy.valid_until_ms) ||
        policy.valid_until_ms <= policy.valid_from_ms ||
        !Number.isSafeInteger(policy.request_budget_remaining) || policy.request_budget_remaining <= 0)
      fail('unauthorized');
    const now = clock.trustedNowMs();
    const lower = BigInt(now.lower_ms);
    const upper = BigInt(now.upper_ms);
    const validUntil = BigInt(policy.valid_until_ms);
    if (upper < lower || upper - lower > 5000n || upper >= validUntil) fail('unauthorized');
    return authorization.authenticateRelayCredential({
      issuer_id: 'xovm2-relay',
      subject_id: `anon:${q.build_id}`,
      software_id: q.software_id,
      device_binding: '00'.repeat(32),
      valid_from_ms: String(policy.valid_from_ms),
      valid_until_ms: String(policy.valid_until_ms),
      scopes: [requiredScope],
      request_hash: requestHash(requestBytes),
    });
  };

  return Object.freeze({
    async handleRuntimeRequest(requestBytes, relayCredential) {
      const q = parseRequest(requestBytes);
      const scope = q.type === 'material.issue' ? 'material.issue' : 'session.control';
      const auth = await authenticate(relayCredential, requestBytes, scope, q);
      return q.type === 'material.issue'
        ? issueMaterial(requestBytes, auth, store, clock, options.randomBytes)
        : handleSession(requestBytes, auth, store, clock, options.randomBytes);
    },
    async handleAdminRequest(request, operation) {
      return admin(request, operation);
    },
    async getPublicTrustBundle(softwareId) {
      if (typeof options.trustBundleProvider?.getPublicTrustBundle !== 'function')
        fail('production_adapter_missing');
      return options.trustBundleProvider.getPublicTrustBundle(softwareId);
    },
    async readiness() {
      const status = await store.selfCheck();
      return {ready: status.ready === true};
    },
    async close() { await pool.end?.(); },
  });
}
