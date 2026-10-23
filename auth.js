// Checks a WorkOS AuthKit access token: an RS256 JWT signed by one of the
// keys WorkOS publishes for our client id. Done with Node's own crypto
// rather than `jose`, since it is one algorithm and four claims, and the
// relay stays at one dependency.
'use strict';
const crypto = require('crypto');

const MAX_TOKEN = 8192;
// A few seconds of slack, so a relay whose clock drifted does not refuse a
// token minted a moment ago.
const SKEW = 5;
// An unknown kid is either a key WorkOS just rotated in or garbage. The
// cooldown keeps garbage from turning every connect into a fetch.
const REFETCH_COOLDOWN_MS = 10000;
const MAX_AGE_MS = 60 * 60 * 1000;

class AuthError extends Error {
  // `retry` is true when the token may be fine and the relay could not
  // check it (WorkOS unreachable), so the PC should try again later rather
  // than sign in again.
  constructor(message, retry = false) {
    super(message);
    this.retry = retry;
  }
}

function jwksUrl(clientId) {
  return `https://api.workos.com/sso/jwks/${encodeURIComponent(clientId)}`;
}

// A real AuthKit access token, checked on 2026-10-24, carries the per
// client user_management issuer. WORKOS_ISSUER overrides it for a custom
// auth domain.
function defaultIssuers(clientId) {
  return [`https://api.workos.com/user_management/${clientId}`];
}

function b64json(part) {
  try {
    return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

async function fetchJwksHttp(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) throw new Error(`jwks ${res.status}`);
  return res.json();
}

// options: clientId, issuers, fetchJwks(url) -> { keys }, now() -> ms.
function createVerifier(options) {
  const clientId = options.clientId;
  const issuers = new Set(options.issuers || defaultIssuers(clientId));
  const fetchJwks = options.fetchJwks || fetchJwksHttp;
  const now = options.now || Date.now;
  const url = options.jwksUrl || jwksUrl(clientId);

  let keys = new Map();
  let fetchedAt = -Infinity;
  let pending = null;

  function load() {
    if (!pending) {
      pending = (async () => {
        try {
          const set = await fetchJwks(url);
          const next = new Map();
          for (const jwk of (set && set.keys) || []) {
            if (jwk.kty !== 'RSA' || typeof jwk.kid !== 'string') continue;
            if (jwk.use && jwk.use !== 'sig') continue;
            if (jwk.alg && jwk.alg !== 'RS256') continue;
            try {
              next.set(jwk.kid, crypto.createPublicKey({ key: jwk, format: 'jwk' }));
            } catch {
              // One malformed key must not cost us the others.
            }
          }
          keys = next;
          fetchedAt = now();
        } finally {
          pending = null;
        }
      })();
    }
    return pending;
  }

  async function keyFor(kid) {
    const stale = now() - fetchedAt > MAX_AGE_MS;
    const cooling = now() - fetchedAt <= REFETCH_COOLDOWN_MS;
    if (stale || (!keys.has(kid) && !cooling)) {
      try {
        await load();
      } catch {
        // Keys we already hold still verify while WorkOS is unreachable.
        if (!keys.has(kid)) throw new AuthError('cannot reach WorkOS', true);
      }
    }
    const key = keys.get(kid);
    // Inside the cooldown the kid may be a key rotated in a moment ago, so
    // the PC is told to try again rather than to sign in again.
    if (!key) throw new AuthError('unknown signing key', !stale && cooling);
    return key;
  }

  // Resolves to the token's claims, or rejects with an AuthError.
  return async function verify(token) {
    if (!clientId) throw new AuthError('sign in is not set up on this relay', true);
    if (typeof token !== 'string' || token.length > MAX_TOKEN) throw new AuthError('malformed token');
    const parts = token.split('.');
    if (parts.length !== 3) throw new AuthError('malformed token');
    const header = b64json(parts[0]);
    const claims = b64json(parts[1]);
    if (!header || !claims || typeof claims !== 'object') throw new AuthError('malformed token');
    // Pinned, so a token cannot pick a weaker algorithm or "none".
    if (header.alg !== 'RS256') throw new AuthError('wrong algorithm');
    if (typeof header.kid !== 'string') throw new AuthError('no key id');
    const key = await keyFor(header.kid);
    const signed = Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii');
    const sig = Buffer.from(parts[2], 'base64url');
    if (!crypto.verify('sha256', signed, key, sig)) throw new AuthError('bad signature');

    const t = now() / 1000;
    if (typeof claims.exp !== 'number') throw new AuthError('no expiry');
    if (t > claims.exp + SKEW) throw new AuthError('token expired');
    if (typeof claims.nbf === 'number' && t + SKEW < claims.nbf) throw new AuthError('token not yet valid');
    if (!issuers.has(claims.iss)) throw new AuthError('wrong issuer');
    if (claims.client_id !== undefined && claims.client_id !== clientId) throw new AuthError('wrong client');
    if (typeof claims.sub !== 'string' || !claims.sub) throw new AuthError('no subject');
    return claims;
  };
}

module.exports = { AuthError, createVerifier, jwksUrl, defaultIssuers };
