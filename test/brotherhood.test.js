'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const WebSocket = require('ws');
const R = require('../relay');
const { createVerifier, createVerifiers, AuthError, jwksUrl } = require('../auth');
const { createRelay, CLOSE_BAD_TOKEN, CLOSE_AUTH_DOWN, CLOSE_TOO_MANY } = require('../server');

const CLIENT = 'client_test';
const ISS = `https://api.workos.com/user_management/${CLIENT}`;

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
  // Only the per client issuer a real token carries, not the bare host.
  await rejects(verify(sign(keyA, claimsFor('u', { iss: 'https://api.workos.com' }))), 'wrong issuer');
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
  // A fresh token fits, though it is longer than any other control.
  const token = 'x'.repeat(8192);
  assert.deepStrictEqual(R.parseControl(Buffer.from(JSON.stringify({ token }))), { token });
  assert.strictEqual(R.parseControl(Buffer.from('{"token":""}')), null);
  assert.strictEqual(R.parseControl(Buffer.from('{"token":7}')), null);
  assert.strictEqual(R.parseControl(Buffer.from(JSON.stringify({ token: 'x'.repeat(10000) }))), null);
});

test('a socket that can refresh closes at exp plus grace, one that cannot not before QUERY_UNTIL', () => {
  const exp = 1_790_000_000;
  assert.strictEqual(R.closeAt(exp, true), exp * 1000 + R.EXPIRY_GRACE);
  assert.strictEqual(R.EXPIRY_GRACE, 120_000);
  assert.strictEqual(R.closeAt(exp, false), R.QUERY_UNTIL);
  // Past QUERY_UNTIL the same rule holds for both.
  const late = R.QUERY_UNTIL / 1000 + 3600;
  assert.strictEqual(R.closeAt(late, false), R.closeAt(late, true));
});

test('users not seen for 90 days are forgotten, and past the cap the ones seen longest ago', () => {
  const day = 24 * 3600 * 1000;
  const t = 1000 * day;
  const ids = () => new Map([['a'.repeat(32), { at: 0, n: 0 }]]);
  const seen = new Map();
  const last = new Map();
  for (const [sub, at] of [['stale', t - 91 * day], ['stale but on', t - 200 * day], ['recent', t - 89 * day]]) {
    seen.set(sub, ids());
    last.set(sub, at);
  }
  assert.strictEqual(R.pruneSeen(seen, last, t, new Set(['stale but on'])), 1);
  assert.deepStrictEqual([...seen.keys()].sort(), ['recent', 'stale but on']);
  assert.ok(!last.has('stale'));

  seen.clear();
  last.clear();
  for (let i = 0; i < R.MAX_USERS + 5; i++) {
    seen.set(`u${i}`, ids());
    last.set(`u${i}`, t - i * 1000);
  }
  // The oldest one is connected, so it stays and the five next oldest go.
  const oldest = `u${R.MAX_USERS + 4}`;
  assert.strictEqual(R.pruneSeen(seen, last, t, new Set([oldest])), 5);
  assert.strictEqual(seen.size, R.MAX_USERS);
  assert.ok(seen.has(oldest) && seen.has('u0') && !seen.has(`u${R.MAX_USERS + 3}`) && !seen.has(`u${R.MAX_USERS - 1}`));
  assert.strictEqual(last.size, R.MAX_USERS);
});

// The sockets, against a relay on a free port with a local JWKS.

async function relay(options = {}) {
  const src = jwksSource([keyA]);
  const server = createRelay({ verify: createVerifier({ clientId: CLIENT, fetchJwks: src.fetch }), ...options });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  const base = `ws://127.0.0.1:${server.address().port}`;
  return { base, close: () => new Promise((ok) => server.close(ok)) };
}

// A client that queues what it receives, so a test can wait for the next one.
function connect(url, headers = {}) {
  // A PC's dial is its address and its headers; a phone's is an address.
  if (typeof url === 'object') ({ url, headers } = url);
  const ws = new WebSocket(url, { headers });
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
  ws.queueLength = () => queue.length;
  ws.closed = new Promise((ok) => ws.on('close', (code, reason) => ok({ code, reason: reason.toString() })));
  ws.opened = new Promise((ok, fail) => {
    ws.on('open', ok);
    ws.on('error', fail);
  });
  return ws;
}

// How Horadric 0.33 and on dial /pc: the secret and token in headers.
const pcUrl = (base, secret, token, name) => ({
  url: `${base}/pc` + (name ? `?name=${encodeURIComponent(name)}` : ''),
  headers: { 'X-Horadric-Secret': secret, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
});

// How 0.32 and older dial it, all in the query string.
const oldPcUrl = (base, secret, token, name) =>
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

test('two clients: each token is checked against its own client', async () => {
  const src = jwksSource([keyA]);
  const verify = createVerifiers(['client_prod', CLIENT], { fetchJwks: src.fetch });
  const claims = await verify(sign(keyA, claimsFor('u', {})));
  assert.strictEqual(claims.sub, 'u');
  const prod = { iss: 'https://api.workos.com/user_management/client_prod', client_id: 'client_prod' };
  assert.strictEqual((await verify(sign(keyA, claimsFor('p', prod)))).sub, 'p');
  await assert.rejects(verify(sign(keyA, claimsFor('x', { client_id: 'client_other' }))), /wrong client/);
  // A token naming one client but issued for the other is refused.
  await assert.rejects(verify(sign(keyA, claimsFor('y', { client_id: 'client_prod' }))), /wrong issuer/);
});

test('credentials come from headers, and from the query only until it is retired', () => {
  const q = new URLSearchParams('secret=qs&token=qt');
  const before = R.QUERY_UNTIL - 1;
  assert.deepStrictEqual(R.credentials({ 'x-horadric-secret': 'hs', authorization: 'Bearer ht' }, q, before), {
    secret: 'hs',
    token: 'ht',
    query: false,
  });
  // A header secret wins outright: the query is not read beside it.
  assert.deepStrictEqual(R.credentials({ 'x-horadric-secret': 'hs' }, q, before), { secret: 'hs', token: null, query: false });
  assert.strictEqual(R.credentials({ 'x-horadric-secret': 'hs', authorization: 'Basic x' }, q, before).token, null);
  assert.strictEqual(R.credentials({ 'x-horadric-secret': 'hs', authorization: 'Bearer a b' }, q, before).token, null);
  assert.deepStrictEqual(R.credentials({}, q, before), { secret: 'qs', token: 'qt', query: true });
  assert.deepStrictEqual(R.credentials({}, q, R.QUERY_UNTIL), { secret: null, token: null, query: false });
  assert.ok(R.QUERY_UNTIL > Date.parse('2026-12-01'));
});

test('the address is the one of the socket unless the proxy in front is trusted', () => {
  const h = { 'x-real-ip': '203.0.113.9', 'x-forwarded-for': '1.1.1.1, 198.51.100.7' };
  assert.strictEqual(R.clientIp(h, '10.0.0.2', false), '10.0.0.2');
  assert.strictEqual(R.clientIp(h, '10.0.0.2', true), '203.0.113.9');
  assert.strictEqual(R.clientIp({ 'x-forwarded-for': '1.1.1.1, 198.51.100.7' }, '10.0.0.2', true), '198.51.100.7');
  assert.strictEqual(R.clientIp({}, '10.0.0.2', true), '10.0.0.2');
});

test('a PC of 0.32 or older still connects by its query string, until the day it is retired', async () => {
  let r = await relay();
  try {
    const old = connect(oldPcUrl(r.base, secrets.one, sign(keyA, claimsFor('user_1')), 'Old'));
    assert.deepStrictEqual(await old.next(), { brothers: [] });
    const now = connect(pcUrl(r.base, secrets.two, sign(keyA, claimsFor('user_1')), 'New'));
    assert.deepStrictEqual(await now.next(), { brothers: [{ id: R.pcId(secrets.one), name: 'Old' }] });
    old.close();
    now.close();
  } finally {
    await r.close();
  }
  r = await relay({ now: () => R.QUERY_UNTIL });
  try {
    const old = connect(oldPcUrl(r.base, secrets.one, sign(keyA, claimsFor('user_1')), 'Old'));
    await assert.rejects(old.opened, /400/);
    const now = connect(pcUrl(r.base, secrets.two, sign(keyA, claimsFor('user_1')), 'New'));
    assert.deepStrictEqual(await now.next(), { brothers: [] });
    now.close();
  } finally {
    await r.close();
  }
});

test('one user may connect only so many machines, and one address only so many PCs', async () => {
  const r = await relay();
  const open = [];
  try {
    for (let i = 0; i < R.MAX_PCS_PER_USER; i++) {
      const pc = connect(pcUrl(r.base, `user-machine-secret-${i}`, sign(keyA, claimsFor('user_1')), `M${i}`));
      await pc.next();
      open.push(pc);
    }
    const over = connect(pcUrl(r.base, 'user-machine-secret-over', sign(keyA, claimsFor('user_1')), 'Over'));
    assert.deepStrictEqual(await over.closed, { code: CLOSE_TOO_MANY, reason: 'too many machines' });
    // One already there reconnects, and another user is not held back.
    const again = connect(pcUrl(r.base, 'user-machine-secret-0', sign(keyA, claimsFor('user_1')), 'M0'));
    assert.strictEqual((await again.next()).brothers.length, R.MAX_PCS_PER_USER - 1);
    open.push(again);
    const other = connect(pcUrl(r.base, secrets.three, sign(keyA, claimsFor('user_2')), 'Theirs'));
    assert.deepStrictEqual(await other.next(), { brothers: [] });
    open.push(other);
    // Every PC so far came from 127.0.0.1: the rest of its share.
    while (open.filter((w) => w.readyState === WebSocket.OPEN).length < R.MAX_PCS_PER_IP) {
      const pc = connect(pcUrl(r.base, `v2-secret-${open.length}-padding`));
      await pc.opened;
      open.push(pc);
    }
    const refused = connect(pcUrl(r.base, 'v2-secret-one-too-many'));
    await assert.rejects(refused.opened, /429/);
    // A PC that goes gives its place back.
    const gone = open.pop();
    gone.close();
    await gone.closed;
    const back = connect(pcUrl(r.base, 'v2-secret-in-its-place'));
    await back.opened;
    open.push(back);
  } finally {
    for (const w of open) w.close();
    await r.close();
  }
});

test('the ids the relay remembers per user stay bounded, and the oldest and connected are kept', () => {
  const seen = new Map();
  const connected = new Set(['c1', 'c2']);
  R.firstSeen(seen, 'oldest', 1, connected);
  R.firstSeen(seen, 'c1', 2, connected);
  R.firstSeen(seen, 'c2', 3, connected);
  for (let i = 0; i < 500; i++) R.firstSeen(seen, `burst-${i}`, 10 + i, connected);
  assert.strictEqual(seen.size, R.MAX_SEEN_PER_USER);
  for (const id of ['oldest', 'c1', 'c2']) assert.ok(seen.has(id), id);
  // A known id keeps its first time.
  assert.strictEqual(R.firstSeen(seen, 'oldest', 9999, connected).at, 1);
});

test('at the cap the id seen first wins, ties broken by order of recording', () => {
  const seen = new Map();
  const connected = new Set();
  for (let i = 0; i < R.MAX_PCS_PER_USER; i++) {
    R.firstSeen(seen, `m${i}`, 5, connected);
    connected.add(`m${i}`);
  }
  assert.deepStrictEqual(R.admit(seen, connected, 'm3'), { ok: true, evict: null });
  R.firstSeen(seen, 'late', 5, connected);
  assert.deepStrictEqual(R.admit(seen, connected, 'late'), { ok: false, evict: null });
  const early = new Map([['early', { at: 1, n: 0 }], ...seen]);
  assert.deepStrictEqual(R.admit(early, connected, 'early'), { ok: true, evict: `m${R.MAX_PCS_PER_USER - 1}` });
});

// A clock that moves one second per reading, so first-seen order is plain.
function ticking() {
  let t = 1_700_000_000_000;
  return () => (t += 1000);
}

const pingPong = async (pc) => {
  pc.send('{"ping":1}');
  assert.deepStrictEqual(await pc.next(), { pong: 1 });
};

test('a burst of new secrets on a stolen login never displaces a machine the relay knew before', async () => {
  const r = await relay({ now: ticking() });
  const open = [];
  try {
    for (let i = 0; i < R.MAX_PCS_PER_USER; i++) {
      const pc = connect(pcUrl(r.base, `real-machine-secret-${i}`, sign(keyA, claimsFor('user_1')), `M${i}`));
      await pc.next();
      open.push(pc);
    }
    const real = open.slice();
    // Rounds, so the burst stays under the cap one address has.
    for (let round = 0; round < 4; round++) {
      const attackers = [];
      for (let i = 0; i < 10; i++) {
        attackers.push(connect(pcUrl(r.base, crypto.randomBytes(24).toString('hex'), sign(keyA, claimsFor('user_1')), 'Evil')));
      }
      for (const a of attackers) assert.deepStrictEqual(await a.closed, { code: CLOSE_TOO_MANY, reason: 'too many machines' });
    }
    for (const pc of real) {
      assert.strictEqual(pc.readyState, WebSocket.OPEN);
      while (pc.queueLength()) await pc.next();
      await pingPong(pc);
    }
  } finally {
    for (const w of open) w.close();
    await r.close();
  }
});

test('a machine known before the ones holding the slots gets in, and the youngest gives way', async () => {
  const r = await relay({ now: ticking() });
  const open = [];
  try {
    const old = connect(pcUrl(r.base, 'old-machine-secret', sign(keyA, claimsFor('user_1')), 'Old'));
    await old.next();
    old.close();
    await old.closed;
    for (let i = 0; i < R.MAX_PCS_PER_USER; i++) {
      const pc = connect(pcUrl(r.base, `newer-machine-secret-${i}`, sign(keyA, claimsFor('user_1')), `N${i}`));
      await pc.next();
      open.push(pc);
    }
    const youngest = open[open.length - 1];
    const back = connect(pcUrl(r.base, 'old-machine-secret', sign(keyA, claimsFor('user_1')), 'Old'));
    open.push(back);
    assert.deepStrictEqual(await youngest.closed, { code: CLOSE_TOO_MANY, reason: 'too many machines' });
    const { brothers } = await back.next();
    assert.strictEqual(brothers.length, R.MAX_PCS_PER_USER - 1);
    assert.ok(!brothers.some((b) => b.id === R.pcId(`newer-machine-secret-${R.MAX_PCS_PER_USER - 1}`)));
    // The one that gave way is now the newest and stays out.
    const retry = connect(pcUrl(r.base, `newer-machine-secret-${R.MAX_PCS_PER_USER - 1}`, sign(keyA, claimsFor('user_1')), 'N'));
    assert.deepStrictEqual(await retry.closed, { code: CLOSE_TOO_MANY, reason: 'too many machines' });
    // And a machine new to the relay is refused while every slot is older.
    const fresh = connect(pcUrl(r.base, 'brand-new-machine-secret', sign(keyA, claimsFor('user_1')), 'Fresh'));
    assert.deepStrictEqual(await fresh.closed, { code: CLOSE_TOO_MANY, reason: 'too many machines' });
  } finally {
    for (const w of open) w.close();
    await r.close();
  }
});

// A fresh directory for one test's state file.
const stateDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'portal-state-'));

const until = async (cond) => {
  for (let i = 0; i < 200 && !cond(); i++) await new Promise((ok) => setTimeout(ok, 10));
  assert.ok(cond(), 'never happened');
};

test('the first-seen map survives its file, and a broken entry or an overfull user does not', () => {
  const a = 'a'.repeat(32);
  const b = 'b'.repeat(32);
  const seen = new Map([['user_1', new Map([[a, { at: 5, n: 0 }], [b, { at: 7, n: 1 }]])], ['user_2', new Map()]]);
  const back = R.seenFromJson(R.seenToJson(seen, new Map([['user_1', 900]])));
  assert.deepStrictEqual([...back.seen.keys()], ['user_1']);
  assert.deepStrictEqual(back.seen.get('user_1'), seen.get('user_1'));
  assert.deepStrictEqual([...back.last], [['user_1', 900]]);
  const many = Array.from({ length: 100 }, (_, i) => [i.toString(16).padStart(32, '0'), 1000 - i, i]);
  // A v1 file, as 59d1947 wrote it, has no last seen: its newest id kept counts.
  const doc = { v: 1, users: { u: [...many, ['nope', 1, 0], [a, 'x', 0]], v: 'not a list' } };
  const v1 = R.seenFromJson(JSON.stringify(doc));
  assert.strictEqual(v1.last.get('u'), 1000 - 99 + R.MAX_SEEN_PER_USER - 1);
  const got = v1.seen.get('u');
  assert.strictEqual(got.size, R.MAX_SEEN_PER_USER);
  // The oldest are the ones kept.
  assert.ok(got.has(many[99][0]) && !got.has(many[0][0]));
  assert.throws(() => R.seenFromJson('{"v":3,"users":{}}'));
  assert.throws(() => R.seenFromJson('{"v":2}'));
  assert.throws(() => R.seenFromJson('not json'));
  assert.ok(!R.tooBig(Buffer.alloc(R.MAX_FRAME)) && R.tooBig(Buffer.alloc(R.MAX_FRAME + 1)));
});

test('after a restart a machine known before still beats a burst of new secrets', async () => {
  const dir = stateDir();
  const stateFile = path.join(dir, 'first-seen.json');
  const clock = ticking();
  let r = await relay({ now: clock, stateFile, saveAfter: 20 });
  const open = [];
  try {
    const old = connect(pcUrl(r.base, 'old-machine-secret', sign(keyA, claimsFor('user_1')), 'Old'));
    await old.next();
    // Written once the burst settles, by temp file and rename.
    await until(() => fs.existsSync(stateFile));
    assert.deepStrictEqual(fs.readdirSync(dir), ['first-seen.json']);
    old.close();
    await old.closed;
  } finally {
    await r.close();
  }
  r = await relay({ now: clock, stateFile, saveAfter: 20 });
  try {
    for (let i = 0; i < R.MAX_PCS_PER_USER; i++) {
      const pc = connect(pcUrl(r.base, crypto.randomBytes(24).toString('hex'), sign(keyA, claimsFor('user_1')), 'Evil'));
      await pc.next();
      open.push(pc);
    }
    const back = connect(pcUrl(r.base, 'old-machine-secret', sign(keyA, claimsFor('user_1')), 'Old'));
    open.push(back);
    assert.deepStrictEqual(await open[R.MAX_PCS_PER_USER - 1].closed, { code: CLOSE_TOO_MANY, reason: 'too many machines' });
    assert.strictEqual((await back.next()).brothers.length, R.MAX_PCS_PER_USER - 1);
  } finally {
    for (const w of open) w.close();
    await r.close();
  }
  // Closing wrote what the second run learnt, at once.
  assert.strictEqual(R.seenFromJson(fs.readFileSync(stateFile, 'utf8')).seen.get('user_1').size, R.MAX_PCS_PER_USER + 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a missing or broken state file starts the relay empty', async () => {
  const dir = stateDir();
  const broken = path.join(dir, 'broken.json');
  fs.writeFileSync(broken, '{ half a file');
  for (const stateFile of [path.join(dir, 'missing.json'), broken, dir]) {
    const r = await relay({ stateFile });
    try {
      const pc = connect(pcUrl(r.base, secrets.one, sign(keyA, claimsFor('user_1')), 'Desk'));
      assert.deepStrictEqual(await pc.next(), { brothers: [] });
      pc.close();
    } finally {
      await r.close();
    }
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a frame over the limit is dropped in every direction, and no socket closes', async () => {
  const r = await relay();
  try {
    const one = connect(pcUrl(r.base, secrets.one, sign(keyA, claimsFor('user_1')), 'Desk'));
    await one.next();
    const phone = connect(`${r.base}/phone?id=${R.pcId(secrets.one)}`);
    await phone.next();
    const phoneCh = (await one.next()).open;
    const two = connect(pcUrl(r.base, secrets.two, sign(keyA, claimsFor('user_1')), 'Laptop'));
    await two.next();
    await one.next();
    two.send(JSON.stringify({ join: { to: R.pcId(secrets.one) } }));
    const asked = await one.next();
    const link = await two.next();

    const big = Buffer.alloc(R.MAX_FRAME + 1, 1);
    // Brother to brother, then a small one that must still pass.
    two.send(R.frame(link.link, big));
    two.send(R.frame(link.link, Buffer.from('after')));
    assert.strictEqual(R.unframe(await one.next()).payload.toString(), 'after');
    // PC to phone, on its channel and by broadcast.
    one.send(R.frame(phoneCh, big));
    one.send(R.frame(R.BROADCAST, big));
    one.send(R.frame(phoneCh, Buffer.from('small')));
    assert.strictEqual((await phone.next()).toString(), 'small');
    // Phone to PC.
    phone.send(big);
    phone.send(Buffer.from('tiny'));
    assert.strictEqual(R.unframe(await one.next()).payload.toString(), 'tiny');
    // Exactly the limit still passes.
    one.send(R.frame(phoneCh, Buffer.alloc(R.MAX_FRAME, 2)));
    assert.strictEqual((await phone.next()).length, R.MAX_FRAME);
    for (const w of [one, two, phone]) assert.strictEqual(w.readyState, WebSocket.OPEN);
    assert.strictEqual(one.queueLength() + two.queueLength() + phone.queueLength(), 0);

    // Past the hard cap the socket may close, so memory stays bounded.
    two.send(Buffer.alloc(R.HARD_FRAME + 8));
    assert.strictEqual((await two.closed).code, 1009);
    one.close();
    phone.close();
  } finally {
    await r.close();
  }
});

// A relay clock a test moves by hand.
function handClock() {
  const c = { t: Date.now() };
  c.now = () => c.t;
  return c;
}

const later = (ms) => new Promise((ok) => setTimeout(ok, ms));

// How Horadric dials /pc when it can hand over a fresh token in band.
const refreshingPcUrl = (...a) => {
  const d = pcUrl(...a);
  d.headers['X-Horadric-Refresh'] = '1';
  return d;
};

test('a fresh token on the open socket moves its expiry; refused, foreign and later keep it', async () => {
  const clock = handClock();
  const real = createVerifier({ clientId: CLIENT, fetchJwks: jwksSource([keyA]).fetch });
  let down = false;
  const verify = (t) => (down ? Promise.reject(new AuthError('cannot reach WorkOS', true)) : real(t));
  const r = await relay({ now: clock.now, verify, expiryEvery: 10 });
  try {
    const exp = nowS() + 300;
    const pc = connect(refreshingPcUrl(r.base, secrets.one, sign(keyA, claimsFor('user_1', { exp })), 'Desk'));
    assert.deepStrictEqual(await pc.next(), { brothers: [] });
    const phone = connect(`${r.base}/phone?id=${R.pcId(secrets.one)}`);
    await phone.next();
    const ch = (await pc.next()).open;
    const brother = connect(pcUrl(r.base, secrets.two, sign(keyA, claimsFor('user_1')), 'Laptop'));
    await brother.next();
    await pc.next();

    const fresh = nowS() + 900;
    pc.send(JSON.stringify({ token: sign(keyA, claimsFor('user_1', { exp: fresh })) }));
    assert.deepStrictEqual(await pc.next(), { token: 'ok', exp: fresh });
    pc.send(JSON.stringify({ token: sign(keyA, claimsFor('user_2')) }));
    assert.deepStrictEqual(await pc.next(), { token: 'refused', why: 'another user' });
    pc.send(JSON.stringify({ token: sign(keyA, claimsFor('user_1', { exp: nowS() - 60 })) }));
    assert.deepStrictEqual(await pc.next(), { token: 'refused', why: 'token expired' });
    pc.send(JSON.stringify({ token: 'not.a.jwt' }));
    assert.deepStrictEqual(await pc.next(), { token: 'refused', why: 'malformed token' });
    down = true;
    pc.send(JSON.stringify({ token: sign(keyA, claimsFor('user_1')) }));
    assert.deepStrictEqual(await pc.next(), { token: 'later' });
    down = false;

    // None of it reached the phone or the brother.
    pc.send(R.frame(ch, Buffer.from('after')));
    assert.strictEqual((await phone.next()).toString(), 'after');
    await pingPong(brother);
    assert.strictEqual(brother.queueLength() + phone.queueLength(), 0);

    // The first token's deadline has passed, the fresh one's has not.
    clock.t = exp * 1000 + R.EXPIRY_GRACE + 60_000;
    await later(60);
    await pingPong(pc);
    clock.t = fresh * 1000 + R.EXPIRY_GRACE - 1000;
    await later(60);
    await pingPong(pc);
    clock.t = fresh * 1000 + R.EXPIRY_GRACE + 1000;
    assert.deepStrictEqual(await pc.closed, { code: CLOSE_BAD_TOKEN, reason: 'token expired' });
    assert.deepStrictEqual(await phone.next(), { relay: 'offline' });
    assert.deepStrictEqual(await brother.next(), { brothers: [] });
    phone.close();
    brother.close();
  } finally {
    await r.close();
  }
});

test('a socket that cannot refresh stays until QUERY_UNTIL, a v2 PC always, and its token frames go nowhere', async () => {
  const clock = handClock();
  const r = await relay({ now: clock.now, expiryEvery: 10 });
  try {
    const old = connect(oldPcUrl(r.base, secrets.one, sign(keyA, claimsFor('user_1')), 'Old'));
    assert.deepStrictEqual(await old.next(), { brothers: [] });
    const v2 = connect(pcUrl(r.base, secrets.two));
    await v2.opened;
    const phone = connect(`${r.base}/phone?id=${R.pcId(secrets.two)}`);
    await phone.next();
    const ch = (await v2.next()).open;
    // A v2 PC has no token to replace: no answer, and nothing passed on.
    v2.send(JSON.stringify({ token: sign(keyA, claimsFor('user_1')) }));
    await pingPong(v2);
    v2.send(R.frame(ch, Buffer.from('after')));
    assert.strictEqual((await phone.next()).toString(), 'after');

    clock.t = nowS() * 1000 + 3600_000;
    await later(60);
    await pingPong(old);
    clock.t = R.QUERY_UNTIL + 1;
    assert.deepStrictEqual(await old.closed, { code: CLOSE_BAD_TOKEN, reason: 'token expired' });
    await pingPong(v2);
    v2.close();
    phone.close();
  } finally {
    await r.close();
  }
});

test('the state file goes through a fresh temp file, and holds only so many users', async () => {
  const dir = stateDir();
  const stateFile = path.join(dir, 'first-seen.json');
  // Left by a crash, readable by all.
  fs.writeFileSync(`${stateFile}.tmp`, 'stale', { mode: 0o644 });
  const r = await relay({ now: ticking(), stateFile, saveAfter: 10, maxUsers: 2 });
  try {
    for (const user of ['user_1', 'user_2', 'user_3']) {
      const pc = connect(pcUrl(r.base, secrets.one, sign(keyA, claimsFor(user)), 'Desk'));
      await pc.next();
      pc.close();
      await pc.closed;
      await later(50);
    }
  } finally {
    await r.close();
  }
  assert.deepStrictEqual(fs.readdirSync(dir), ['first-seen.json']);
  if (process.platform !== 'win32') assert.strictEqual(fs.statSync(stateFile).mode & 0o777, 0o600);
  const { seen } = R.seenFromJson(fs.readFileSync(stateFile, 'utf8'));
  assert.deepStrictEqual([...seen.keys()].sort(), ['user_2', 'user_3']);
  fs.rmSync(dir, { recursive: true, force: true });
});
