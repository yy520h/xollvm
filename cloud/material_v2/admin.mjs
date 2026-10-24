import {timingSafeEqual} from 'node:crypto';

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function secretMatches(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string') return false;
  const left = Buffer.from(actual);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

function closed(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some(field => !Object.hasOwn(value, field)))
    fail('invalid_admin_request');
}

export function createAdminHandler({token, repository}) {
  if (typeof token !== 'string' || token.length < 32 || !repository ||
      typeof repository.importBuild !== 'function' || typeof repository.enableBuild !== 'function' ||
      typeof repository.revokeBuild !== 'function') fail('production_adapter_missing');
  return async request => {
    if (!secretMatches(request?.authorization, token)) fail('unauthorized');
    if (request.operation === 'import') {
      closed(request, ['authorization', 'operation', 'input']);
      closed(request.input, ['publicManifest', 'privateRegistration', 'verifierSidecars',
        'finalArtifactHash']);
      return repository.importBuild(request.input);
    }
    if (request.operation === 'enable') {
      closed(request, ['authorization', 'operation', 'buildId', 'finalArtifactHash']);
      return repository.enableBuild(request.buildId, request.finalArtifactHash);
    }
    if (request.operation === 'revoke') {
      closed(request, ['authorization', 'operation', 'buildId']);
      return repository.revokeBuild(request.buildId);
    }
    fail('invalid_admin_request');
  };
}
