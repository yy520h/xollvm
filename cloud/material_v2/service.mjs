import {
  createCipheriv, createHash, createPrivateKey, createPublicKey, diffieHellman, hkdfSync,
} from 'node:crypto';

import {encodeCanonical, readU64} from './codec.mjs';
import {makePackage, validatePackagePairing, verifyRegisteredRegion} from './package.mjs';
import {
  encodeEnvelopeCanonical, parseRequest, requestHash, SUITE, validateX25519Public,
} from './protocol.mjs';
import {storeInternals} from './store.mjs';
import {frame} from '../../tools/cloud-material/format.mjs';

const X25519_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const MAX_U64 = 0xffffffffffffffffn;
const {serviceFail} = storeInternals;

function randomExact(randomBytes, size) {
  if (typeof randomBytes !== 'function') serviceFail('key_unavailable');
  let result;
  try { result = randomBytes(size); }
  catch { serviceFail('key_unavailable'); }
  if (!(result instanceof Uint8Array) || result.length !== size) serviceFail('key_unavailable');
  result = Buffer.from(result);
  if (result.every(byte => byte === 0)) serviceFail('key_unavailable');
  return result;
}

function checkedAdd(left, right) {
  const result = left + right;
  if (result > MAX_U64) serviceFail('counter_exhausted');
  return result;
}

function now(clock) {
  let interval;
  try { interval = clock.trustedNowMs(); }
  catch { serviceFail('authority_unavailable'); }
  const lower = readU64(interval?.lower_ms);
  const upper = readU64(interval?.upper_ms);
  if (upper < lower || upper - lower > 5000n) serviceFail('authority_unavailable');
  return {lower, upper};
}

function authRequestKey(auth, requestId) {
  return `${auth.issuer_id}:${auth.subject_id}:${auth.software_id}:${auth.device_binding}:${requestId}`;
}

function authBuildScope(auth, buildId) {
  return `${auth.issuer_id}:${auth.subject_id}:${auth.software_id}:${auth.device_binding}:${buildId}`;
}

function checkBuild(build, q, auth) {
  if (!build || build.state !== 'enabled' || build.finalArtifactHash !== q.final_artifact_hash)
    serviceFail('build_unavailable');
  if (build.manifest.software_id !== q.software_id || auth.software_id !== q.software_id)
    serviceFail('unauthorized');
}

function checkAuthTime(auth, issuedAt) {
  if (issuedAt >= readU64(auth.valid_until_ms)) serviceFail('unauthorized');
}

function checkSessionIdentity(session, q, auth) {
  if (!session || session.build_id !== q.build_id ||
      session.final_artifact_hash !== q.final_artifact_hash ||
      session.software_id !== auth.software_id || session.issuer_id !== auth.issuer_id ||
      session.subject_id !== auth.subject_id || session.device_binding !== auth.device_binding)
    serviceFail('unauthorized');
  if (session.counter_epoch !== q.counter_epoch) serviceFail('counter_epoch_mismatch');
}

function checkSession(session, q, auth, issuedAt) {
  if (!session || session.status !== 'active') serviceFail('session_closed');
  checkSessionIdentity(session, q, auth);
  if (issuedAt >= BigInt(session.session_valid_until_ms)) serviceFail('session_closed');
}

function responseWindow(issuedAt, auth, sessionUntil, signing, requested = 120000n) {
  const authUntil = readU64(auth.valid_until_ms);
  const keyUntil = readU64(signing.not_after_ms);
  const bundleUntil = readU64(signing.bundle_valid_until_ms);
  const remaining = [requested, authUntil - issuedAt, sessionUntil - issuedAt,
    keyUntil - issuedAt, bundleUntil - issuedAt];
  if (remaining.some(value => value <= 0n)) serviceFail('key_unavailable');
  const value = remaining.reduce((left, right) => left < right ? left : right);
  return Number(value);
}

function recheckCommitTime(clock, auth, session, signing) {
  const current = now(clock).upper;
  if (current >= readU64(auth.valid_until_ms) ||
      current >= readU64(session.session_valid_until_ms) ||
      current >= readU64(signing.signing_until_ms) ||
      current >= readU64(signing.bundle_valid_until_ms))
    serviceFail('authority_unavailable');
}

async function sealPayload({q, digest, payload, binding, session, counter, auth,
  clockInterval, store, randomBytes, acceptForMs, tx}) {
  const signing = store.signingMetadata();
  const issuedAt = clockInterval.upper;
  if (clockInterval.lower < readU64(signing.not_before_ms) ||
      issuedAt >= readU64(signing.signing_until_ms)) serviceFail('key_unavailable');
  const ephemeralPrivate = randomExact(randomBytes, 32);
  const serverNonce = randomExact(randomBytes, 32);
  let privateKey;
  let shared;
  let key;
  let iv;
  try {
    try {
      privateKey = createPrivateKey({key: Buffer.concat([X25519_PKCS8, ephemeralPrivate]),
        format: 'der', type: 'pkcs8'});
    } catch { serviceFail('key_unavailable'); }
    const serverPublic = createPublicKey(privateKey).export({format: 'der', type: 'spki'}).subarray(-32);
    tx.claimServerEphemeral(authBuildScope(auth, q.build_id), serverNonce.toString('hex'),
        serverPublic.toString('base64'), digest);
    const payloadBytes = encodeCanonical(payload);
    const transcript = {
      protocol_version: 2,
      suite: SUITE,
      type: q.type,
      software_id: q.software_id,
      build_id: q.build_id,
      final_artifact_hash: q.final_artifact_hash,
      request_id: q.request_id,
      request_hash: digest,
      client_nonce: q.client_nonce,
      client_ephemeral_key: q.client_ephemeral_key,
      server_nonce: serverNonce.toString('hex'),
      server_ephemeral_key: serverPublic.toString('base64'),
      server_key_id: signing.key_id,
      trust_epoch: signing.trust_epoch,
      session_id: session.session_id,
      counter_epoch: session.counter_epoch,
      counter: counter.toString(),
      issued_at_ms: issuedAt.toString(),
      auth_valid_until_ms: auth.valid_until_ms,
      session_valid_until_ms: session.session_valid_until_ms,
      accept_for_ms: acceptForMs,
      payload_hash: createHash('sha256').update(payloadBytes).digest('hex'),
      binding,
    };
    const transcriptBytes = encodeCanonical(transcript);
    const transcriptHash = createHash('sha256').update(
        frame('XOVM2/transcript', transcriptBytes)).digest();
    const peerBytes = validateX25519Public(Buffer.from(q.client_ephemeral_key, 'base64'));
    let peer;
    try {
      peer = createPublicKey({key: Buffer.concat([
        Buffer.from('302a300506032b656e032100', 'hex'), peerBytes]), format: 'der', type: 'spki'});
      shared = diffieHellman({privateKey, publicKey: peer});
    } catch { serviceFail('invalid_key'); }
    if (shared.length !== 32 || shared.every(byte => byte === 0)) serviceFail('invalid_key');
    key = Buffer.from(hkdfSync('sha256', shared, transcriptHash,
        frame('XOVM2/response-key', transcriptHash), 32));
    iv = Buffer.from(hkdfSync('sha256', shared, transcriptHash,
        frame('XOVM2/response-iv', transcriptHash), 12));
    const cipher = createCipheriv('aes-256-gcm', key, iv, {authTagLength: 16});
    cipher.setAAD(frame('XOVM2/aad', transcriptBytes));
    const ciphertext = Buffer.concat([cipher.update(payloadBytes), cipher.final()]);
    const tag = cipher.getAuthTag();
    const signature = await store.signEd25519(signing.key_id,
        frame('XOVM2/signature', transcriptBytes, ciphertext, tag));
    return encodeEnvelopeCanonical({transcript, ciphertext: ciphertext.toString('base64'),
      tag: tag.toString('base64'), signature: Buffer.from(signature).toString('base64')});
  } finally {
    ephemeralPrivate.fill(0);
    shared?.fill(0);
    key?.fill(0);
    iv?.fill(0);
  }
}

export async function issueMaterial(requestBytes, auth, store, clock, randomBytes) {
  const q = parseRequest(requestBytes);
  if (q.type !== 'material.issue') serviceFail('invalid_request_type');
  if (q.mode === 'operation') serviceFail('operation_not_implemented');
  const digest = requestHash(requestBytes);
  const clockInterval = now(clock);
  return store.transaction(q.build_id, q.region_id, q.session_id, async tx => {
    const trusted = tx.requireAuth(auth, digest, 'material.issue');
    checkAuthTime(trusted, clockInterval.upper);
    const build = tx.getBuild();
    checkBuild(build, q, trusted);
    const session = tx.getSession();
    checkSession(session, q, trusted, clockInterval.upper);
    const stored = tx.getRegion();
    if (!stored) serviceFail('build_unavailable');
    if (stored.region.mode === 'operation') serviceFail('operation_not_implemented');
    if (stored.region.mode !== q.mode || stored.region.engine_abi_hash !== q.engine_abi_hash)
      serviceFail('policy_mismatch');
    let capability;
    try { capability = verifyRegisteredRegion(stored.region, stored.verifier); }
    catch (error) { throw error; }
    const requestKey = authRequestKey(trusted, q.request_id);
    const cached = tx.reserveRequest(requestKey, digest, q.type);
    if (cached) return Buffer.from(cached.response);
    tx.claimClientEphemeral(authBuildScope(trusted, q.build_id), q.client_nonce,
        q.client_ephemeral_key, digest);
    const currentGeneration = tx.currentGeneration(q.session_id, q.region_id);
    const previousGeneration = readU64(q.previous_generation);
    if (previousGeneration > currentGeneration) serviceFail('generation_ahead');
    const generation = tx.nextGeneration(q.session_id, q.region_id);
    const counter = tx.nextCounter(q.counter_epoch, q.software_id, q.build_id, q.region_id);
    const signing = store.signingMetadata();
    const acceptForMs = responseWindow(clockInterval.upper, trusted,
        BigInt(session.session_valid_until_ms), signing);
    const leaseMs = q.mode === 'lease' ? acceptForMs : 0;
    const packageBinding = {
      build_id: q.build_id,
      region_id: q.region_id,
      session_id: q.session_id,
      generation: generation.toString(),
      request_hash: digest,
      mode: q.mode,
      lease_ms: leaseMs,
      engine_abi_hash: q.engine_abi_hash,
    };
    let executionPackage;
    try {
      executionPackage = makePackage(capability, packageBinding, randomBytes);
      validatePackagePairing(capability, executionPackage, packageBinding);
    } catch (error) {
      if (error?.code) throw error;
      serviceFail('key_unavailable');
    }
    const response = await sealPayload({q, digest, payload: executionPackage,
      binding: executionPackage.binding, session, counter, auth: trusted,
      clockInterval, store, randomBytes, acceptForMs, tx});
    recheckCommitTime(clock, trusted, session, signing);
    tx.saveReply(requestKey, digest, response, {generation: generation.toString(),
      counter: counter.toString(), auth_valid_until_ms: trusted.valid_until_ms});
    return response;
  });
}

export async function handleSession(requestBytes, auth, store, clock, randomBytes) {
  const q = parseRequest(requestBytes);
  if (!['session.open', 'session.renew', 'session.close'].includes(q.type))
    serviceFail('invalid_request_type');
  const digest = requestHash(requestBytes);
  const clockInterval = now(clock);
  return store.transaction(q.build_id, null, q.type === 'session.open' ? null : q.session_id,
      async tx => {
        const trusted = tx.requireAuth(auth, digest, 'session.control');
        checkAuthTime(trusted, clockInterval.upper);
        const build = tx.getBuild();
        checkBuild(build, q, trusted);
        let session = tx.getSession();
        if (q.type === 'session.renew') checkSession(session, q, trusted, clockInterval.upper);
        if (q.type === 'session.close') checkSessionIdentity(session, q, trusted);
        const requestKey = authRequestKey(trusted, q.request_id);
        const cached = tx.reserveRequest(requestKey, digest, q.type);
        if (cached) return Buffer.from(cached.response);
        if (q.type === 'session.close' && session.status !== 'active')
          serviceFail('session_closed');
        tx.claimClientEphemeral(authBuildScope(trusted, q.build_id), q.client_nonce,
            q.client_ephemeral_key, digest);
        if (q.type === 'session.open') {
          let sessionId;
          for (let attempt = 0; attempt < 16; ++attempt) {
            const candidate = randomExact(randomBytes, 32).toString('hex');
            if (!tx.hasSession(candidate)) {
              sessionId = candidate;
              break;
            }
          }
          if (!sessionId) serviceFail('key_unavailable');
          const authUntil = readU64(trusted.valid_until_ms);
          const sessionUntil = [checkedAdd(clockInterval.upper, 86400000n), authUntil]
              .reduce((left, right) => left < right ? left : right);
          if (sessionUntil <= clockInterval.upper) serviceFail('unauthorized');
          session = {
            session_id: sessionId,
            counter_epoch: store.signingMetadata().counter_epoch ?? build.counter_epoch,
            issuer_id: trusted.issuer_id,
            subject_id: trusted.subject_id,
            software_id: trusted.software_id,
            device_binding: trusted.device_binding,
            build_id: q.build_id,
            final_artifact_hash: q.final_artifact_hash,
            session_valid_until_ms: sessionUntil.toString(),
            status: 'active',
            control_counter: '0',
          };
          // Reference store owns the configured epoch; signing metadata mirrors it below.
          session.counter_epoch = store.referenceCounterEpochForService();
        } else {
          if (q.type === 'session.close') checkSession(session, q, trusted, clockInterval.upper);
          if (readU64(q.previous_counter) > readU64(session.control_counter))
            serviceFail('request_conflict');
        }
        const counter = tx.nextCounter(session.counter_epoch, q.software_id, q.build_id, 'control');
        let controlValidForMs;
        if (q.type === 'session.close') {
          session.status = 'closed';
          session.session_valid_until_ms = clockInterval.upper.toString();
          controlValidForMs = 0;
        } else {
          const authUntil = readU64(trusted.valid_until_ms);
          const until = [checkedAdd(clockInterval.upper, 86400000n), authUntil]
              .reduce((left, right) => left < right ? left : right);
          session.session_valid_until_ms = until.toString();
          controlValidForMs = Number(until - clockInterval.upper);
        }
        session.control_counter = counter.toString();
        tx.saveSession(session);
        const controlBinding = {session_id: session.session_id, request_hash: digest,
          control_valid_for_ms: controlValidForMs};
        const payload = {format_version: 1, session_id: session.session_id,
          counter_epoch: session.counter_epoch, control_valid_for_ms: controlValidForMs,
          session_valid_until_ms: session.session_valid_until_ms};
        const signing = store.signingMetadata();
        const acceptForMs = responseWindow(clockInterval.upper, trusted,
            q.type === 'session.close' ? checkedAdd(clockInterval.upper, 120000n) :
              BigInt(session.session_valid_until_ms), signing,
            BigInt(q.type === 'session.close' ? 120000 : Math.min(controlValidForMs, 120000)));
        const response = await sealPayload({q, digest, payload, binding: controlBinding,
          session, counter, auth: trusted, clockInterval, store, randomBytes, acceptForMs, tx});
        if (q.type !== 'session.close') recheckCommitTime(clock, trusted, session, signing);
        tx.saveReply(requestKey, digest, response, {counter: counter.toString(),
          auth_valid_until_ms: trusted.valid_until_ms});
        return response;
      });
}
