// The phone key's derivation against a vector worked out apart from this
// code, with Python's cryptography package, so the PC side can pin the
// same bytes and the two cannot drift apart unnoticed.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

globalThis.crypto ??= crypto.webcrypto;
const PK = require('../public/phonekey.js');

const V = {
  phoneD: '01'.repeat(32),
  brotherD: '02'.repeat(32),
  phonePub: 'BG_wO5SSQc4drdQ1GeaWDgqFtBppoFwygQOqK84VlMoWPE91OlW_AdxT9sCwx-7ni0DG_30lqW4igrmJzvccFEo',
  brotherPub: 'BFUPRxAD89-Xw99QaseX9nIfsaH7e49vg9IkSYplyI4kE2CT1wEuUJpzcVy9CwCjzA_0tcAbP_oZarH7MnA2uOY',
  phoneId: 'AAECAwQFBgc',
  relayId: '00112233445566778899aabbccddeeff',
  key: '4fad95513bcb5e4265148da11fc8c732983016307bc317733e4ed2a145d72d67',
};

// WebCrypto takes a fixed private scalar only as a JWK, with its point.
async function privateKey(dHex, pub) {
  const p = PK.fromB64url(pub);
  const b = (u) => PK.toB64url(u);
  const jwk = { kty: 'EC', crv: 'P-256', d: b(Buffer.from(dHex, 'hex')), x: b(p.subarray(1, 33)), y: b(p.subarray(33)) };
  return crypto.webcrypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
}

const hex = (u) => Buffer.from(u).toString('hex');

test('the phone derives the pinned key', async () => {
  const k = await PK.derive(await privateKey(V.phoneD, V.phonePub), V.phonePub, V.brotherPub, V.phoneId, V.relayId);
  assert.strictEqual(hex(k), V.key);
});

test('the brother derives the same key from its side', async () => {
  // The parts keep the phone's key first whichever side derives, so the
  // brother's own ECDH gives the same bytes only through the same framing.
  const brother = await privateKey(V.brotherD, V.brotherPub);
  const pub = await crypto.webcrypto.subtle.importKey('raw', PK.fromB64url(V.phonePub), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.webcrypto.subtle.deriveBits({ name: 'ECDH', public: pub }, brother, 256));
  const enc = new TextEncoder();
  const data = PK.framed(PK.LABEL, [shared, PK.fromB64url(V.phonePub), PK.fromB64url(V.brotherPub), enc.encode(V.phoneId), enc.encode(V.relayId)]);
  assert.strictEqual(crypto.createHash('sha256').update(data).digest('hex'), V.key);
});

test('framing is the label, then each part length prefixed big endian', () => {
  const out = PK.framed('ab', [Uint8Array.of(7), new Uint8Array(0)]);
  assert.strictEqual(hex(out), '6162' + '00000001' + '07' + '00000000');
});

test('b64url round trips without padding', () => {
  const u = Uint8Array.from({ length: 33 }, (_, i) => i * 7);
  const s = PK.toB64url(u);
  assert.ok(!/[=+/]/.test(s));
  assert.deepStrictEqual(PK.fromB64url(s), u);
});
