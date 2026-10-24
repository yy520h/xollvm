import {createHash, sign} from 'node:crypto';

import {fail} from './codec.mjs';
import {verifyRegisteredRegion} from './package.mjs';
import {
  encodeRegistrationCanonical, MATERIAL_CODEC_PROFILE,
} from '../../tools/cloud-material/export.mjs';
import {frame} from '../../tools/cloud-material/format.mjs';

const HASH = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const GRANTS = new WeakMap();
let nextProviderId = 1;

export class ServiceError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function serviceFail(code) {
  throw new ServiceError(code);
}

function clone(value) {
  return structuredClone(value);
}

function cloneState(state) {
  const result = clone(state);
  for (const build of result.builds.values()) {
    build.verifiers = new Map([...build.verifiers].map(([key, bytes]) =>
      [key, Buffer.from(bytes)]));
  }
  for (const reply of result.replies.values()) reply.response = Buffer.from(reply.response);
  return result;
}

function closed(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some(field => !Object.hasOwn(value, field)))
    serviceFail('invalid_registration');
}

function hash(value) {
  if (typeof value !== 'string' || !HASH.test(value)) serviceFail('invalid_registration');
}

function validateManifest(manifest, registration) {
  closed(manifest, ['format_version', 'protocol_version', 'vm_format_version', 'target_triple',
    'software_id', 'regions', 'build_id']);
  closed(registration, ['format_version', 'build_id', 'regions']);
  if (manifest.format_version !== 1 || manifest.protocol_version !== 2 ||
      manifest.vm_format_version !== 1 || manifest.target_triple !== 'aarch64-linux-android26' ||
      registration.format_version !== 1 || !ID.test(manifest.software_id) ||
      registration.build_id !== manifest.build_id || !Array.isArray(manifest.regions) ||
      !Array.isArray(registration.regions) || !manifest.regions.length ||
      manifest.regions.length !== registration.regions.length || manifest.regions.length > 4096)
    serviceFail('invalid_registration');
  const core = clone(manifest);
  delete core.build_id;
  const buildId = createHash('sha256').update(frame('XOVM2/build-id',
      encodeRegistrationCanonical(core, MATERIAL_CODEC_PROFILE.publicManifest))).digest('hex');
  if (buildId !== manifest.build_id) serviceFail('build_id_mismatch');
  let previous = '';
  for (let index = 0; index < manifest.regions.length; ++index) {
    const current = manifest.regions[index];
    closed(current, ['region_id', 'region_content_hash', 'region_name', 'mode',
      'engine_abi_hash', 'call_abi_hash', 'layout_hash']);
    for (const field of ['region_id', 'region_content_hash', 'engine_abi_hash',
      'call_abi_hash', 'layout_hash']) hash(current[field]);
    if (current.region_id <= previous) serviceFail('invalid_registration');
    previous = current.region_id;
    const privateRegion = registration.regions[index];
    for (const field of Object.keys(current))
      if (privateRegion?.[field] !== current[field]) serviceFail('registration_pair_mismatch');
  }
}

function sidecarsFor(registration, verifierSidecars) {
  if (!(verifierSidecars instanceof Map) || verifierSidecars.size !== registration.regions.length)
    serviceFail('invalid_verifier_descriptor');
  const result = new Map();
  for (const region of registration.regions) {
    const bytes = verifierSidecars.get(region.region_id);
    if (!(bytes instanceof Uint8Array) || bytes.length > 65536)
      serviceFail('invalid_verifier_descriptor');
    try { verifyRegisteredRegion(region, bytes); }
    catch (error) { throw new ServiceError(error.code ?? 'invalid_registration'); }
    result.set(region.region_id, Buffer.from(bytes));
  }
  return result;
}

function authorityKey(providerId) {
  return `provider:${providerId}`;
}

function grantState(auth) {
  const state = auth && typeof auth === 'object' ? GRANTS.get(auth) : undefined;
  if (!state) serviceFail('unauthorized');
  return state;
}

function digestFrame(label, ...parts) {
  return createHash('sha256').update(frame(label, ...parts)).digest('hex');
}

function canonicalDigest(value) {
  const digest = createHash('sha256');
  const write = current => {
    if (typeof current === 'string') {
      if (/[^\x20-\x7e]/.test(current)) serviceFail('invalid_registration');
      digest.update(JSON.stringify(current), 'ascii');
    } else if (typeof current === 'number') {
      if (!Number.isInteger(current) || Object.is(current, -0) || current < 0 ||
          current > 0xffffffff) serviceFail('invalid_registration');
      digest.update(String(current), 'ascii');
    } else if (typeof current === 'boolean') {
      digest.update(current ? 'true' : 'false', 'ascii');
    } else if (Array.isArray(current)) {
      digest.update('[', 'ascii');
      for (let index = 0; index < current.length; ++index) {
        if (index) digest.update(',', 'ascii');
        if (!Object.hasOwn(current, index)) serviceFail('invalid_registration');
        write(current[index]);
      }
      digest.update(']', 'ascii');
    } else if (current && typeof current === 'object' &&
        (Object.getPrototypeOf(current) === Object.prototype ||
         Object.getPrototypeOf(current) === null) && !Object.getOwnPropertySymbols(current).length) {
      digest.update('{', 'ascii');
      const keys = Object.keys(current).sort();
      for (let index = 0; index < keys.length; ++index) {
        const key = keys[index];
        if (!/^[a-z][a-z0-9_]{0,63}$/.test(key)) serviceFail('invalid_registration');
        if (index) digest.update(',', 'ascii');
        digest.update(`"${key}":`, 'ascii');
        write(current[key]);
      }
      digest.update('}', 'ascii');
    } else serviceFail('invalid_registration');
  };
  write(value);
  return digest.digest();
}

function verifierCommitments(verifierSidecars) {
  if (!(verifierSidecars instanceof Map)) serviceFail('invalid_verifier_descriptor');
  return [...verifierSidecars].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([regionId, bytes]) => {
        hash(regionId);
        if (!(bytes instanceof Uint8Array) || bytes.length > 65536)
          serviceFail('invalid_verifier_descriptor');
        return Buffer.from(`${regionId}:${createHash('sha256').update(bytes).digest('hex')}`, 'ascii');
      });
}

export function registerBuildRequestHash(publicManifest, privateRegistration, verifierSidecars) {
  return digestFrame('XOVM2/build-register', canonicalDigest(publicManifest),
      canonicalDigest(privateRegistration),
      ...verifierCommitments(verifierSidecars));
}

export function enableBuildRequestHash(buildId, finalArtifactHash) {
  hash(buildId);
  hash(finalArtifactHash);
  return digestFrame('XOVM2/build-enable', Buffer.from(buildId, 'ascii'),
      Buffer.from(finalArtifactHash, 'ascii'));
}

export function revokeBuildRequestHash(buildId) {
  hash(buildId);
  return digestFrame('XOVM2/build-revoke', Buffer.from(buildId, 'ascii'));
}

function requireGrant(draft, auth, requestHash, requiredScope) {
  const grant = grantState(auth);
  const authority = draft.authorities.get(authorityKey(grant.providerId));
  if (!authority || authority.revoked || grant.revoked || !grant.lease_valid ||
      authority.revision !== grant.authorization_revision ||
      grant.request_hash !== requestHash || !grant.scopes.has(requiredScope))
    serviceFail('unauthorized');
  return grant;
}

export class ReferenceAuthProvider {
  #store;
  #providerId;
  #defaults;

  constructor(store, defaults) {
    if (!(store instanceof ReferenceMemoryStore)) serviceFail('reference_store_required');
    this.#store = store;
    this.#providerId = nextProviderId++;
    this.#defaults = Object.freeze({...defaults});
    if (!ID.test(defaults.issuer_id) || !ID.test(defaults.subject_id) ||
        !ID.test(defaults.software_id) || !HASH.test(defaults.device_binding))
      serviceFail('invalid_reference_auth');
    store.referenceInstallAuthority(this.#providerId, this.#defaults);
  }

  authenticate(requestHash, scopes = ['session.control', 'material.issue']) {
    hash(requestHash);
    const current = this.#store.referenceAuthoritySnapshot(this.#providerId);
    const capability = Object.freeze(Object.create(null));
    GRANTS.set(capability, Object.freeze({
      providerId: this.#providerId,
      issuer_id: this.#defaults.issuer_id,
      subject_id: this.#defaults.subject_id,
      software_id: this.#defaults.software_id,
      device_binding: this.#defaults.device_binding,
      valid_until_ms: this.#defaults.valid_until_ms,
      authorization_revision: current.revision,
      lease_valid: !current.revoked,
      revoked: current.revoked,
      request_hash: requestHash,
      scopes: new Set(scopes),
    }));
    return capability;
  }

  async revoke() {
    await this.#store.referenceRevokeAuthority(this.#providerId);
  }
}

export class ReferenceMemoryStore {
  #state;
  #tail = Promise.resolve();
  #signingKey;
  #probe;
  #failNextSign = false;
  #failNextCommit = false;

  constructor(options = {}) {
    if (!HASH.test(options.counter_epoch ?? '')) serviceFail('invalid_counter_epoch');
    const signingKey = options.signing_key;
    if (!signingKey?.private_key || !(signingKey.public_key instanceof Uint8Array) ||
        signingKey.public_key.length !== 32 || !ID.test(signingKey.key_id ?? ''))
      serviceFail('invalid_signing_key');
    this.#signingKey = {...signingKey, public_key: Buffer.from(signingKey.public_key)};
    this.#probe = options.probe;
    this.#state = {
      counterEpoch: options.counter_epoch,
      builds: new Map(), sessions: new Map(), replies: new Map(),
      requestTombstones: new Map(), claims: new Map(), generations: new Map(),
      counters: new Map(), authorities: new Map(),
    };
    Object.defineProperty(this, 'reference_only', {value: true, enumerable: true});
  }

  capabilities() {
    return Object.freeze({reference_only: true, cross_instance_serializability: false,
      durability: false, trusted_time: false, production_key_provider: false});
  }

  async selfCheck() {
    return this.capabilities();
  }

  referenceInstallAuthority(providerId, defaults) {
    this.#state.authorities.set(authorityKey(providerId), {
      revision: '1', revoked: false, defaults: clone(defaults),
    });
  }

  referenceAuthoritySnapshot(providerId) {
    const current = this.#state.authorities.get(authorityKey(providerId));
    if (!current) serviceFail('unauthorized');
    return clone(current);
  }

  async referenceRevokeAuthority(providerId) {
    await this.#exclusive(async draft => {
      const current = draft.authorities.get(authorityKey(providerId));
      if (!current) serviceFail('unauthorized');
      current.revoked = true;
      current.revision = (BigInt(current.revision) + 1n).toString();
    });
  }

  async #exclusive(callback) {
    let release;
    const previous = this.#tail;
    this.#tail = new Promise(resolve => { release = resolve; });
    await previous;
    try {
      const draft = cloneState(this.#state);
      const result = await callback(draft);
      if (this.#failNextCommit) {
        this.#failNextCommit = false;
        serviceFail('store_unavailable');
      }
      this.#state = draft;
      return result;
    } finally {
      release();
    }
  }

  async registerBuild(publicManifest, privateRegistration, verifierSidecars, auth) {
    const requestDigest = registerBuildRequestHash(
        publicManifest, privateRegistration, verifierSidecars);
    return this.#exclusive(async draft => {
      const trusted = requireGrant(draft, auth, requestDigest, 'build.publish');
      if (trusted.software_id !== publicManifest?.software_id) serviceFail('unauthorized');
      validateManifest(publicManifest, privateRegistration);
      const verifiedSidecars = sidecarsFor(privateRegistration, verifierSidecars);
      const prior = draft.builds.get(publicManifest.build_id);
      const identity = requestDigest;
      if (prior) {
        if (prior.identity !== identity) serviceFail('build_conflict');
        return prior.state;
      }
      const pending = {
        identity, revision: '1', state: 'pending', manifest: clone(publicManifest),
        registration: clone(privateRegistration), verifiers: new Map(),
        finalArtifactHash: undefined,
      };
      draft.builds.set(publicManifest.build_id, pending);
      this.#probe?.({kind: 'build_state', state: 'pending', build_id: publicManifest.build_id});
      pending.verifiers = verifiedSidecars;
      pending.state = 'validated';
      pending.revision = '2';
      this.#probe?.({kind: 'build_state', state: 'validated', build_id: publicManifest.build_id});
      return pending.state;
    });
  }

  async enableBuild(buildId, finalArtifactHash, auth) {
    hash(buildId);
    hash(finalArtifactHash);
    const requestDigest = enableBuildRequestHash(buildId, finalArtifactHash);
    return this.#exclusive(async draft => {
      const build = draft.builds.get(buildId);
      const trusted = requireGrant(draft, auth, requestDigest, 'build.publish');
      if (trusted.software_id !== build?.manifest.software_id) serviceFail('unauthorized');
      if (!build || build.state !== 'validated') {
        if (build?.state === 'enabled' && build.finalArtifactHash === finalArtifactHash) return 'enabled';
        serviceFail('build_unavailable');
      }
      build.state = 'enabled';
      build.finalArtifactHash = finalArtifactHash;
      build.revision = (BigInt(build.revision) + 1n).toString();
      this.#probe?.({kind: 'build_state', state: 'enabled', build_id: buildId});
      return build.state;
    });
  }

  async revokeBuild(buildId, auth) {
    hash(buildId);
    const requestDigest = revokeBuildRequestHash(buildId);
    return this.#exclusive(async draft => {
      const build = draft.builds.get(buildId);
      const trusted = requireGrant(draft, auth, requestDigest, 'build.revoke');
      if (trusted.software_id !== build?.manifest.software_id) serviceFail('unauthorized');
      if (!build || build.state === 'revoked') serviceFail('build_unavailable');
      build.state = 'revoked';
      build.revision = (BigInt(build.revision) + 1n).toString();
      this.#probe?.({kind: 'build_state', state: 'revoked', build_id: buildId});
    });
  }

  async transaction(buildId, regionId, sessionId, callback) {
    if (typeof callback !== 'function') serviceFail('invalid_transaction');
    return this.#exclusive(async draft => {
      let reserved;
      let authFacts;
      const tx = {
        requireAuth: (auth, requestHash, requiredScope) => {
          const grant = requireGrant(draft, auth, requestHash, requiredScope);
          authFacts = grant;
          return Object.freeze({...grant, scopes: undefined});
        },
        authFacts: () => {
          if (!authFacts) serviceFail('unauthorized');
          return authFacts;
        },
        getBuild: () => draft.builds.get(buildId),
        getRegion: () => {
          const build = draft.builds.get(buildId);
          if (!build || regionId === null) return undefined;
          const index = build.registration.regions.findIndex(region => region.region_id === regionId);
          if (index < 0) return undefined;
          const region = clone(build.registration.regions[index]);
          const verifier = Buffer.from(build.verifiers.get(regionId) ?? []);
          return {region, verifier};
        },
        getSession: () => sessionId === null ? undefined : draft.sessions.get(sessionId),
        hasSession: currentSessionId => draft.sessions.has(currentSessionId),
        saveSession: session => { draft.sessions.set(session.session_id, clone(session)); },
        closeSession: currentSessionId => {
          const session = draft.sessions.get(currentSessionId);
          if (!session) serviceFail('session_closed');
          session.status = 'closed';
        },
        getReply: authRequestKey => {
          const reply = draft.replies.get(authRequestKey);
          if (reply) return {...reply, response: Buffer.from(reply.response), status: 'committed'};
          const tombstone = draft.requestTombstones.get(authRequestKey);
          return tombstone ? {...tombstone, status: 'retired'} : undefined;
        },
        reserveRequest: (authRequestKey, digest, scope) => {
          const reply = draft.replies.get(authRequestKey) ?? draft.requestTombstones.get(authRequestKey);
          if (reply) {
            if (reply.requestHash !== digest) serviceFail('request_conflict');
            if (draft.requestTombstones.has(authRequestKey)) serviceFail('request_retired');
            return {...reply, response: Buffer.from(reply.response), status: 'committed'};
          }
          reserved = {authRequestKey, requestHash: digest, scope};
          return undefined;
        },
        claimClientEphemeral: (authBuildScope, clientNonce, clientPublicKey, digest) => {
          let claims = draft.claims.get(authBuildScope);
          if (!claims) {
            claims = {nonces: new Map(), keys: new Map(), serverNonces: new Map(),
              serverKeys: new Map()};
            draft.claims.set(authBuildScope, claims);
          }
          for (const [map, value] of [[claims.nonces, clientNonce], [claims.keys, clientPublicKey]]) {
            const prior = map.get(value);
            if (prior && prior !== digest) serviceFail('invalid_key');
            map.set(value, digest);
          }
        },
        claimServerEphemeral: (authBuildScope, serverNonce, serverPublicKey, digest) => {
          const claims = draft.claims.get(authBuildScope);
          if (!claims) serviceFail('invalid_transaction');
          for (const [map, value] of [[claims.serverNonces, serverNonce],
            [claims.serverKeys, serverPublicKey]]) {
            const prior = map.get(value);
            if (prior && prior !== digest) serviceFail('invalid_key');
            map.set(value, digest);
          }
        },
        nextGeneration: (currentSessionId, currentRegionId) => {
          const key = `${currentSessionId}:${currentRegionId}`;
          const current = draft.generations.get(key) ?? 0n;
          if (current === 0xffffffffffffffffn) serviceFail('counter_exhausted');
          const next = current + 1n;
          draft.generations.set(key, next);
          return next;
        },
        currentGeneration: (currentSessionId, currentRegionId) =>
          draft.generations.get(`${currentSessionId}:${currentRegionId}`) ?? 0n,
        nextCounter: (counterEpoch, softwareId, currentBuildId, stream) => {
          const key = `${counterEpoch}:${softwareId}:${currentBuildId}:${stream}`;
          const current = draft.counters.get(key) ?? 0n;
          if (current === 0xffffffffffffffffn) serviceFail('counter_exhausted');
          const next = current + 1n;
          draft.counters.set(key, next);
          return next;
        },
        saveReply: (authRequestKey, digest, responseBytes, metadata = {}) => {
          if (!reserved || reserved.authRequestKey !== authRequestKey || reserved.requestHash !== digest ||
              !(responseBytes instanceof Uint8Array)) serviceFail('invalid_transaction');
          draft.replies.set(authRequestKey, {
            requestHash: digest, scope: reserved.scope, response: Buffer.from(responseBytes),
            ...metadata,
          });
        },
        setBuildState: (expectedRevision, nextState, releasePair) => {
          const build = draft.builds.get(buildId);
          if (!build || build.revision !== expectedRevision) serviceFail('transaction_conflict');
          build.state = nextState;
          build.finalArtifactHash = releasePair?.final_artifact_hash;
          build.revision = (BigInt(build.revision) + 1n).toString();
        },
      };
      return callback(tx);
    });
  }

  async signEd25519(keyId, bytes) {
    if (keyId !== this.#signingKey.key_id || !(bytes instanceof Uint8Array))
      serviceFail('key_unavailable');
    if (this.#failNextSign) {
      this.#failNextSign = false;
      serviceFail('key_unavailable');
    }
    const signature = sign(null, Buffer.from(bytes), this.#signingKey.private_key);
    if (signature.length !== 64) serviceFail('key_unavailable');
    return signature;
  }

  signingMetadata() {
    const {private_key, ...metadata} = this.#signingKey;
    return {...clone(metadata), counter_epoch: this.#state.counterEpoch};
  }

  referenceCounterEpochForService() {
    return this.#state.counterEpoch;
  }

  referenceSigningKeyForTest() {
    return {...this.#signingKey, public_key: Buffer.from(this.#signingKey.public_key)};
  }

  referenceFailNextSignForTest() {
    this.#failNextSign = true;
  }

  referenceFailNextCommitForTest() {
    this.#failNextCommit = true;
  }

  async referenceInspectBuild(buildId) {
    const build = this.#state.builds.get(buildId);
    if (!build) return undefined;
    return {state: build.state, revision: build.revision,
      final_artifact_hash: build.finalArtifactHash};
  }

  async referenceCorruptVerifierForTest(buildId, regionId) {
    await this.#exclusive(async draft => {
      const build = draft.builds.get(buildId);
      if (!build?.verifiers.has(regionId)) serviceFail('build_unavailable');
      const bytes = Buffer.from(build.verifiers.get(regionId));
      bytes[0] ^= 1;
      build.verifiers.set(regionId, bytes);
    });
  }

  async referenceSetGenerationForTest(sessionId, regionId, value) {
    await this.#exclusive(async draft => {
      draft.generations.set(`${sessionId}:${regionId}`, BigInt(value));
    });
  }

  async referenceSetCounterForTest(counterEpoch, softwareId, buildId, stream, value) {
    await this.#exclusive(async draft => {
      draft.counters.set(`${counterEpoch}:${softwareId}:${buildId}:${stream}`, BigInt(value));
    });
  }

  async referenceStats() {
    let publishedGenerations = 0;
    for (const generation of this.#state.generations.values())
      publishedGenerations += Number(generation);
    return {published_generations: publishedGenerations,
      published_replies: this.#state.replies.size};
  }
}

export function productionStatus() {
  return Object.freeze({status: 'BLOCKED', code: 'production_adapter_missing',
    missing: Object.freeze(['trusted_host_authorization', 'cross_instance_serializable_transactions',
      'durability', 'trusted_time', 'production_key_provider'])});
}

export async function startProductionService() {
  serviceFail('production_adapter_missing');
}

export const storeInternals = Object.freeze({serviceFail});
