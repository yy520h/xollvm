import {encodeCanonical, readU64} from './codec.mjs';
import {fail} from './codec.mjs';
import {frame} from '../../tools/cloud-material/format.mjs';

function id(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value))
    fail('invalid_trust_bundle');
}

export function createTrustBundleProvider({keyProvider, clock, buildRepository}) {
  if (!keyProvider || typeof keyProvider.publicMetadata !== 'function' ||
      !clock || typeof clock.trustedNowMs !== 'function' || !buildRepository ||
      typeof buildRepository.hasSoftware !== 'function') fail('production_adapter_missing');
  return Object.freeze({
    async getPublicTrustBundle(softwareId) {
      id(softwareId);
      if (!(await buildRepository.hasSoftware(softwareId))) fail('build_unavailable');
      let trustedTime;
      let metadata;
      try {
        trustedTime = clock.trustedNowMs();
        metadata = await keyProvider.publicMetadata(softwareId);
      } catch { fail('authority_unavailable'); }
      const lower = readU64(trustedTime?.lower_ms);
      const upper = readU64(trustedTime?.upper_ms);
      if (upper < lower || upper - lower > 5000n) fail('untrusted_time');
      if (metadata?.software_id !== softwareId || !metadata.root_key_id ||
          !(metadata.root_public_key instanceof Uint8Array) || metadata.root_public_key.length !== 32 ||
          !Array.isArray(metadata.keys) || metadata.keys.length < 1 || metadata.keys.length > 64)
        fail('invalid_trust_bundle');
      const epoch = readU64(metadata.trust_epoch);
      if (epoch === 0n) fail('invalid_trust_bundle');
      const issued = lower;
      const validUntil = readU64(metadata.bundle_valid_until_ms);
      if (issued >= validUntil) fail('untrusted_time');
      const keys = metadata.keys.map(key => {
        id(key.key_id);
        if (!(key.public_key instanceof Uint8Array) || key.public_key.length !== 32 ||
            !['active', 'retired', 'revoked'].includes(key.status)) fail('invalid_trust_bundle');
        const notBefore = readU64(key.not_before_ms);
        const signingUntil = readU64(key.signing_until_ms);
        const notAfter = readU64(key.not_after_ms);
        if (!(notBefore < signingUntil && signingUntil <= notAfter)) fail('invalid_trust_bundle');
        return {key_id: key.key_id, public_key: Buffer.from(key.public_key).toString('base64'),
          not_before_ms: String(key.not_before_ms), signing_until_ms: String(key.signing_until_ms),
          not_after_ms: String(key.not_after_ms), status: key.status};
      }).sort((left, right) => left.key_id.localeCompare(right.key_id));
      for (let index = 1; index < keys.length; ++index)
        if (keys[index - 1].key_id === keys[index].key_id) fail('invalid_trust_bundle');
      const body = {format_version: 1, protocol_version: 2, software_id: softwareId,
        root_key_id: metadata.root_key_id, trust_epoch: String(epoch),
        counter_epoch: metadata.counter_epoch, issued_at_ms: String(issued),
        valid_until_ms: String(validUntil), keys};
      if (!/^[0-9a-f]{64}$/.test(body.counter_epoch)) fail('invalid_trust_bundle');
      const signature = await keyProvider.signRoot(frame('XOVM2/trust-bundle', encodeCanonical(body)));
      if (!(signature instanceof Uint8Array) || signature.length !== 64) fail('key_unavailable');
      const bytes = encodeCanonical({body, signature: Buffer.from(signature).toString('base64')});
      if (bytes.length > 65536) fail('invalid_trust_bundle');
      return {bytes, bootstrap: {software_id: softwareId, root_key_id: metadata.root_key_id,
        root_public_key: Buffer.from(metadata.root_public_key).toString('base64')}};
    },
  });
}
