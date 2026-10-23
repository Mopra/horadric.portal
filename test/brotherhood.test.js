'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const WebSocket = require('ws');
const R = require('../relay');
const { createVerifier, AuthError, jwksUrl } = require('../auth');
const { createRelay, CLOSE_BAD_TOKEN, CLOSE_AUTH_DOWN } = require('../server');

const CLIENT = 'client_test';
const ISS = 'https://api.workos.com';

function keyPair(kid) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' } };
}

function sign(key, claims, header = {}) {
  const b = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const h = b({ alg: 'RS256', typ: 'JWT', kid: key.kid, ...header });
  const p = b(claims);
  const sig = crypto.sign('sha256', Buffer.from(`${h}.${p}`), key.privateKey).toString('base64url');
  return `${h}.${p}.${sig}`;
}

const nowS = () => Math.floor(Date.now() / 1000);
const claimsFor = (sub, extra = {}) => ({ sub, iss: ISS, client_id: CLIENT, sid: 's', iat: nowS(), exp: nowS() + 300, ...extra });

const keyA = keyPair('kA');
const keyB = keyPair('kB');

function jwksSource(initial) {
  const src = { keys: initial, fetches: 0, urls: [] };
  src.fetch = async (url) => {
    src.fetches++;
    src.urls.push(url);
    return { keys: src.keys.map((k) => k.jwk) };
  };
  return src;
}

async function rejects(p, message, retry = false) {
  await assert.rejects(p, (e) => e instanceof AuthError && e.message === message && e.retry === retry);
}

test('a valid token gives its claims, fetched from the client id JWKS', async () => {
  const src = jwksSource([keyA]);
  const verify = createVerifier({ clientId: CLIENT, fetchJwks: src.fetch });
  const claims = await verify(sign(keyA, claimsFor('user_1')));
  assert.strictEqual(claims.sub, 'user_1');
  assert.deepStrictEqual(src.urls, ['https://api.workos.com/sso/jwks/client_test']);
  await verify(sign(keyA, claimsFor('user_1')));
  assert.strictEqual(src.fetches, 1, 'keys are cached');
  assert.strictEqual(jwksUrl('a/b'), 'https://api.workos.com/sso/jwks/a%2Fb');
});

test('expired, wrong issuer, wrong client, forged and none tokens are refused', async () => {
  const src = jwksSource([keyA]);
  const verify = createVerifier({ clientId: CLIENT, fetchJwks: src.fetch });
  await rejects(verify(sign(keyA, claimsFor('u', { exp: nowS() - 60 }))), 'token expired');
  await rejects(verify(sign(keyA, claimsFor('u', { iss: 'https://evil.example' }))), 'wrong issuer');
  await rejects(verify(sign(keyA, claimsFor('u', { client_id: 'client_other' }))), 'wrong client');
  await rejects(verify(sign(keyA, claimsFor('u', { exp: undefined }))), 'no expiry');
  await rejects(verify(sign(keyA, claimsFor(''))), 'no subject');
  // Signed with B's private key but claiming A's kid.
  await rejects(verify(sign({ ...keyB, kid: 'kA' }, claimsFor('u'))), 'bad signature');
  await rejects(verify(sign(keyA, claimsFor('u'), { alg: 'none' })), 'wrong algorithm');
  await rejects(verify(sign(keyA, claimsFor('u'), { alg: 'HS256' })), 'wrong algorithm');
  await rejects(verify('not.a.jwt'), 'malformed token');
  await rejects(verify('x'.repeat(9000)), 'malformed token');
  // The trailing slash form and the per client form are both WorkOS's own.
  await verify(sign(keyA, claimsFor('u', { iss: 'https://api.workos.com/' })));
  await verify(sign(keyA, claimsFor('u', { iss: `https://api.workos.com/user_management/${CLIENT}` })));
});

test('an unknown kid refetches the keys, but not more than once per cooldown', async () => {
  let t = 1_000_000_000_000;
  const src = jwksSource([keyA]);
  const verify = createVerifier({ clientId: CLIENT, fetchJwks: src.fetch, now: () => t });
  const claims = { ...claimsFor('u'), iat: t / 1000, exp: t / 1000 + 300 };
  await verify(sign(keyA, claims));
  assert.strictEqual(src.fetches, 1);
  // WorkOS rotates B in.
  src.keys = [keyA, keyB];
  await rejects(verify(sign(keyB, claims)), 'unknown signing key', true);
  assert.strictEqual(src.fetches, 1, 'within the cooldown, no fetch, and the PC is told to retry');
  t += 11000;
  const got = await verify(sign(keyB, { ...claims, exp: t / 1000 + 300 }));
  assert.strictEqual(got.sub, 'u');
  assert.strictEqual(src.fetches, 2);
  // A kid still unknown after a fresh fetch is refused for good.
  t += 11000;
  await rejects(verify(sign(keyPair('kZ'), { ...claims, exp: t / 1000 + 300 })), 'unknown signing key');
  assert.strictEqual(src.fetches, 3);
});

test('WorkOS unreachable or no client id says try again, not sign in again', async () => {
  const down = createVerifier({ clientId: CLIENT, fetchJwks: async () => { throw new Error('down'); } });
  await rejects(down(sign(keyA, claimsFor('u'))), 'cannot reach WorkOS', true);
  const unset = createVerifier({ clientId: undefined, fetchJwks: async () => ({ keys: [] }) });
  await rejects(unset(sign(keyA, claimsFor('u'))), 'sign in is not set up on this relay', true);
});

test('names are cleaned and brothers exclude the PC itself', () => {
  assert.strictEqual(R.cleanName('Laptop\u0007\n'), 'Laptop');
  assert.strictEqual(R.cleanName(null), 'PC');
  assert.strictEqual(R.cleanName('   '), 'PC');
  assert.strictEqual([...R.cleanName('x'.repeat(100))].length, R.MAX_NAME);
  const pcs = [
    { id: 'b', name: 'B' },
    { id: 'a', name: 'A' },
    { id: 'c', name: 'C' },
  ];
  assert.deepStrictEqual(R.brothersOf(pcs, 'b'), [
    { id: 'a', name: 'A' },
    { id: 'c', name: 'C' },
  ]);
});

test('control messages from a PC are parsed, anything else dropped', () => {
  const id = 'a'.repeat(32);
  assert.deepStrictEqual(R.parseControl(Buffer.from('{"ping":1}')), { ping: true });
  assert.deepStrictEqual(R.parseControl(Buffer.from(`{"join":{"to":"${id}"}}`)), { join: id });
  assert.deepStrictEqual(R.parseControl(Buffer.from('{"close":7}')), { close: 7 });
  assert.strictEqual(R.parseControl(Buffer.from('{"join":{"to":"nope"}}')), null);
  assert.strictEqual(R.parseControl(Buffer.from('{"close":0}')), null);
  assert.strictEqual(R.parseControl(Buffer.from('{"close":4294967295}')), null);
  assert.strictEqual(R.parseControl(Buffer.from('nope')), null);
});

// The sockets, against a relay on a free port with a local JWKS.

async function relay() {
  const src = jwksSource([keyA]);
  const server = createRelay({ verify: createVerifier({ clientId: CLIENT, fetchJwks: src.fetch }) });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  const base = `ws://127.0.0.1:${server.address().port}`;
  return { base, close: () => new Promise((ok) => server.close(ok)) };
}

// A client that queues what it receives, so a test can wait for the next one.
function connect(url) {
  const ws = new WebSocket(url);
  const queue = [];
  const waiting = [];
  ws.on('message', (data, isBinary) => {
    const m = isBinary ? Buffer.from(data) : JSON.parse(data.toString());
    const w = waiting.shift();
    if (w) w(m);
    else queue.push(m);
  });
  ws.next = () =>
    new Promise((ok, fail) => {
      if (queue.length) return ok(queue.shift());
      const timer = setTimeout(() => fail(new Error('nothing came')), 2000);
      waiting.push((m) => {
        clearTimeout(timer);
        ok(m);
      });
    });
  ws.closed = new Promise((ok) => ws.on('close', (code, reason) => ok({ code, reason: reason.toString() })));
  ws.opened = new Promise((ok, fail) => {
    ws.on('open', ok);
    ws.on('error', fail);
  });
  return ws;
}

const pcUrl = (base, secret, token, name) =>
  `${base}/pc?secret=${secret}` + (token ? `&token=${token}` : '') + (name ? `&name=${encodeURIComponent(name)}` : '');

const secrets = { one: 's'.repeat(20) + '1', two: 's'.repeat(20) + '2', three: 's'.repeat(20) + '3' };

test('an expired or foreign token is refused with 4401, the PC it would replace stays', async () => {
  const r = await relay();
  try {
    const good = connect(pcUrl(r.base, secrets.one, sign(keyA, claimsFor('user_1')), 'Desk'));
    assert.deepStrictEqual(await good.next(), { brothers: [] });
    const expired = connect(pcUrl(r.base, secrets.one, sign(keyA, claimsFor('user_1', { exp: nowS() - 60 }))));
    assert.deepStrictEqual(await expired.closed, { code: CLOSE_BAD_TOKEN, reason: 'token expired' });
    const foreign = connect(pcUrl(r.base, secrets.two, sign(keyA, claimsFor('user_1', { iss: 'https://evil.example' }))));
    assert.deepStrictEqual(await foreign.closed, { code: CLOSE_BAD_TOKEN, reason: 'wrong issuer' });
    assert.strictEqual(good.readyState, WebSocket.OPEN);
    good.close();
  } finally {
    await r.close();
  }
  assert.strictEqual(CLOSE_AUTH_DOWN, 4503);
});

test('a v2 PC without a token is served as before and sees no brothers', async () => {
  const r = await relay();
  try {
    const pc = connect(pcUrl(r.base, secrets.one));
    await pc.opened;
    const phone = connect(`${r.base}/phone?id=${R.pcId(secrets.one)}`);
    assert.deepStrictEqual(await phone.next(), { relay: 'online' });
    const open = await pc.next();
    assert.ok(Number.isInteger(open.open), 'the first thing a v2 PC hears is the phone');
    pc.send(R.frame(open.open, Buffer.from('hi')));
    assert.strictEqual((await phone.next()).toString(), 'hi');
    phone.send(Buffer.from('yo'));
    const f = R.unframe(await pc.next());
    assert.strictEqual(f.ch, open.open);
    assert.strictEqual(f.payload.toString(), 'yo');
    pc.send('{"ping":1}');
    assert.deepStrictEqual(await pc.next(), { pong: 1 });
    // A join from a PC that is not signed in goes nowhere.
    pc.send(JSON.stringify({ join: { to: R.pcId(secrets.two) } }));
    assert.deepStrictEqual(await pc.next(), { error: 'not signed in', to: R.pcId(secrets.two) });
    pc.close();
    phone.close();
  } finally {
    await r.close();
  }
});

test('brothers of one user see each other, other users do not', async () => {
  const r = await relay();
  try {
    const one = connect(pcUrl(r.base, secrets.one, sign(keyA, claimsFor('user_1')), 'Desk'));
    assert.deepStrictEqual(await one.next(), { brothers: [] });
    const two = connect(pcUrl(r.base, secrets.two, sign(keyA, claimsFor('user_1')), 'Laptop ø'));
    assert.deepStrictEqual(await two.next(), { brothers: [{ id: R.pcId(secrets.one), name: 'Desk' }] });
    assert.deepStrictEqual(await one.next(), { brothers: [{ id: R.pcId(secrets.two), name: 'Laptop ø' }] });

    const other = connect(pcUrl(r.base, secrets.three, sign(keyA, claimsFor('user_2')), 'Theirs'));
    assert.deepStrictEqual(await other.next(), { brothers: [] });
    // Joining across users is refused like a PC that is not there.
    other.send(JSON.stringify({ join: { to: R.pcId(secrets.one) } }));
    assert.deepStrictEqual(await other.next(), { error: 'no such brother', to: R.pcId(secrets.one) });

    two.close();
    assert.deepStrictEqual(await one.next(), { brothers: [] });
    one.close();
    other.close();
  } finally {
    await r.close();
  }
});

test('a join opens a channel between two brothers and frames pass both ways', async () => {
  const r = await relay();
  try {
    const one = connect(pcUrl(r.base, secrets.one, sign(keyA, claimsFor('user_1')), 'Desk'));
    await one.next();
    // A phone of Desk holds a channel, so the brother channel must differ.
    const phone = connect(`${r.base}/phone?id=${R.pcId(secrets.one)}`);
    await phone.next();
    const phoneCh = (await one.next()).open;
    const two = connect(pcUrl(r.base, secrets.two, sign(keyA, claimsFor('user_1')), 'Laptop'));
    await two.next();
    await one.next();

    two.send(JSON.stringify({ join: { to: R.pcId(secrets.one) } }));
    const asked = await one.next();
    assert.strictEqual(asked.name, 'Laptop');
    assert.strictEqual(asked.id, R.pcId(secrets.two));
    assert.ok(Number.isInteger(asked.join) && asked.join !== phoneCh);
    const link = await two.next();
    assert.deepStrictEqual(link, { link: link.link, id: R.pcId(secrets.one), name: 'Desk' });

    two.send(R.frame(link.link, Buffer.from('my key')));
    let f = R.unframe(await one.next());
    assert.deepStrictEqual([f.ch, f.payload.toString()], [asked.join, 'my key']);
    one.send(R.frame(asked.join, Buffer.from('mine')));
    f = R.unframe(await two.next());
    assert.deepStrictEqual([f.ch, f.payload.toString()], [link.link, 'mine']);

    // Broadcast from Desk reaches its phone, never its brother.
    one.send(R.frame(R.BROADCAST, Buffer.from('all phones')));
    assert.strictEqual((await phone.next()).toString(), 'all phones');

    // Either side closes the channel and the other hears it.
    one.send(JSON.stringify({ close: asked.join }));
    assert.deepStrictEqual(await two.next(), { close: link.link });
    two.send(R.frame(link.link, Buffer.from('late')));

    // A brother that goes closes its open channels too.
    two.send(JSON.stringify({ join: { to: R.pcId(secrets.one) } }));
    const again = await one.next();
    await two.next();
    two.close();
    assert.deepStrictEqual(await one.next(), { close: again.join });
    assert.deepStrictEqual(await one.next(), { brothers: [] });
    one.close();
    phone.close();
  } finally {
    await r.close();
  }
});
