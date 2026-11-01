// Pairing v4 (docs/PORTAL.md): the relay's /signin and /ask against a
// WorkOS of our own, and the handshake's derivations against the vector
// the PC side pins too.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
const WebSocket = require('ws');
const R = require('../relay');
const { createVerifier, AuthError } = require('../auth');
const { createRelay } = require('../server');

globalThis.crypto ??= crypto.webcrypto;
const Ask = require('../public/ask.js');

const CLIENT = 'client_test';
const ISS = `https://api.workos.com/user_management/${CLIENT}`;
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const JWK = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
const nowS = () => Math.floor(Date.now() / 1000);

function sign(sub) {
  const b = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const h = b({ alg: 'RS256', typ: 'JWT', kid: 'k1' });
  const p = b({ sub, iss: ISS, client_id: CLIENT, sid: 's', iat: nowS(), exp: nowS() + 300 });
  return `${h}.${p}.${crypto.sign('sha256', Buffer.from(`${h}.${p}`), privateKey).toString('base64url')}`;
}

// WorkOS as the relay sees it: a code "good:<user>" signs that user in,
// anything else is refused. Every body posted is kept.
function fakeWorkos() {
  const w = { posts: [] };
  w.fetch = async (url, body) => {
    w.posts.push({ url, body });
    const m = /^good:(.+)$/.exec(body.code);
    if (!m) throw new AuthError('Invalid authorization code');
    return { access_token: sign(m[1]), refresh_token: 'r', user: { id: m[1], email: `${m[1]}@example.com` } };
  };
  return w;
}

async function relay(options = {}) {
  const workos = fakeWorkos();
  const verify = createVerifier({ clientId: CLIENT, fetchJwks: async () => ({ keys: [JWK] }) });
  const server = createRelay({ verify, workosFetch: workos.fetch, pageClient: 'client_page', origin: 'https://portal.example', ...options });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  const port = server.address().port;
  return { port, base: `ws://127.0.0.1:${port}`, workos, close: () => new Promise((ok) => server.close(ok)) };
}

// A socket that queues what comes, text parsed and binary as a Buffer.
function connect(url, headers = {}) {
  const ws = new WebSocket(url, { headers });
  const queue = [];
  const waiting = [];
  ws.on('message', (data, isBinary) => {
    const m = isBinary ? Buffer.from(data) : JSON.parse(data.toString());
    // A PC hears of every brother that comes; these tests are not about that.
    if (ws.skipBrothers && m.brothers) return;
    const w = waiting.shift();
    if (w) w(m);
    else queue.push(m);
  });
  ws.next = (ms = 2000) =>
    new Promise((ok, fail) => {
      if (queue.length) return ok(queue.shift());
      const timer = setTimeout(() => fail(new Error('nothing came')), ms);
      waiting.push((m) => {
        clearTimeout(timer);
        ok(m);
      });
    });
  ws.quiet = async (ms = 150) => {
    await new Promise((ok) => setTimeout(ok, ms));
    return queue.length === 0 && waiting.length === 0;
  };
  ws.closed = new Promise((ok) => ws.on('close', (code) => ok(code)));
  ws.opened = new Promise((ok, fail) => {
    ws.on('open', ok);
    ws.on('error', fail);
  });
  return ws;
}

// A signed in PC, with asks=1 unless told otherwise. Its first word from
// the relay is its brothers list.
async function pc(base, secret, sub, { asks = true, name = 'Desk' } = {}) {
  const q = new URLSearchParams({ name });
  if (asks) q.set('asks', '1');
  const headers = { 'X-Horadric-Secret': secret };
  if (sub) headers.Authorization = `Bearer ${sign(sub)}`;
  const ws = connect(`${base}/pc?${q}`, headers);
  if (sub) assert.ok(Array.isArray((await ws.next()).brothers));
  else await ws.opened;
  ws.skipBrothers = true;
  ws.id = R.pcId(secret);
  return ws;
}

const VERIFIER = 'v'.repeat(43);

async function signedIn(base, sub) {
  const phone = connect(`${base}/ask`);
  await phone.opened;
  phone.send(JSON.stringify({ code: `good:${sub}`, verifier: VERIFIER }));
  const first = await phone.next();
  return { phone, first };
}

function get(port, path) {
  return new Promise((ok, fail) => {
    http.get({ host: '127.0.0.1', port, path }, (res) => {
      res.resume();
      ok({ status: res.statusCode, location: res.headers.location, cache: res.headers['cache-control'] });
    }).on('error', fail);
  });
}

test('the handshake derives the pinned commit, code and ask key', async () => {
  const phonePub = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 0x22)]);
  const phoneNonce = Buffer.alloc(16, 0x33);
  const pcPub = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 0x44)]);
  const pcNonce = Buffer.alloc(16, 0x55);
  const hex = (u) => Buffer.from(u).toString('hex');
  assert.strictEqual(hex(await Ask.commitOf(phonePub, phoneNonce)), 'aee2fd1a606cd5cbf15ee8f00eda999ad2887d7c8b1cd08ce50e0463e887cac3');
  const { code, key } = await Ask.codeAndKey(Buffer.alloc(32, 0x11), phonePub, phoneNonce, pcPub, pcNonce);
  assert.strictEqual(code, '835 086');
  assert.strictEqual(hex(key), 'e18619d9e6d4de5e13c7da7a75d3de6013e9ca2f014c2efeec51e0d127c1611f');
});

test('a code with few digits keeps its leading zeros', async () => {
  // Searched for: parts whose first four bytes are small mod a million.
  for (let i = 0; i < 5000; i++) {
    const s = Buffer.alloc(32);
    s.writeUInt32BE(i);
    const { code } = await Ask.codeAndKey(s, Buffer.alloc(65, 4), Buffer.alloc(16), Buffer.alloc(65, 4), Buffer.alloc(16));
    assert.match(code, /^\d{3} \d{3}$/);
    if (code.startsWith('0')) return;
  }
  assert.fail('no code below 100000 in 5000 tries');
});

test('/signin sends the browser to WorkOS with the page client, the origin and the challenge', async () => {
  const r = await relay();
  try {
    const challenge = 'c'.repeat(43);
    const state = 's'.repeat(22);
    const got = await get(r.port, `/signin?challenge=${challenge}&state=${state}`);
    assert.strictEqual(got.status, 302);
    assert.strictEqual(got.cache, 'no-store');
    assert.strictEqual(
      got.location,
      'https://api.workos.com/user_management/authorize?client_id=client_page&redirect_uri=https%3A%2F%2Fportal.example%2F' +
        `&response_type=code&provider=authkit&code_challenge=${challenge}&code_challenge_method=S256&state=${state}`,
    );
    assert.strictEqual((await get(r.port, `/signin?challenge=short&state=${state}`)).status, 400);
    assert.strictEqual((await get(r.port, `/signin?challenge=${challenge}&state=bad%20state%20here%20!!!`)).status, 400);
    assert.strictEqual((await get(r.port, `/signin?challenge=${challenge}`)).status, 400);
  } finally {
    await r.close();
  }
  const off = await relay({ pageClient: '' });
  try {
    assert.strictEqual((await get(off.port, `/signin?challenge=${'c'.repeat(43)}&state=${'s'.repeat(22)}`)).status, 503);
  } finally {
    await off.close();
  }
});

test('the page client falls back to the first PC client, the origin to the portal', async () => {
  const saved = { ...process.env };
  process.env.WORKOS_CLIENT_ID = 'client_a,client_b';
  delete process.env.WORKOS_PAGE_CLIENT_ID;
  delete process.env.PUBLIC_ORIGIN;
  try {
    const r = await relay({ pageClient: undefined, origin: undefined });
    try {
      const got = await get(r.port, `/signin?challenge=${'c'.repeat(43)}&state=${'s'.repeat(22)}`);
      const q = new URL(got.location).searchParams;
      assert.strictEqual(q.get('client_id'), 'client_a');
      assert.strictEqual(q.get('redirect_uri'), 'https://portal.horadric.dev/');
    } finally {
      await r.close();
    }
    process.env.WORKOS_PAGE_CLIENT_ID = 'client_p';
    process.env.PUBLIC_ORIGIN = 'http://127.0.0.1:43200/';
    const r2 = await relay({ pageClient: undefined, origin: undefined });
    try {
      const q = new URL((await get(r2.port, `/signin?challenge=${'c'.repeat(43)}&state=${'s'.repeat(22)}`)).location).searchParams;
      assert.strictEqual(q.get('client_id'), 'client_p');
      assert.strictEqual(q.get('redirect_uri'), 'http://127.0.0.1:43200/');
    } finally {
      await r2.close();
    }
  } finally {
    process.env = saved;
  }
});

test('/ask trades the code with WorkOS, a secret only when the relay has one', async () => {
  const r = await relay();
  try {
    const { phone, first } = await signedIn(r.base, 'user_1');
    assert.deepStrictEqual(first, { machines: [], email: 'user_1@example.com' });
    assert.deepStrictEqual(r.workos.posts, [
      {
        url: 'https://api.workos.com/user_management/authenticate',
        body: { client_id: 'client_page', grant_type: 'authorization_code', code: 'good:user_1', code_verifier: VERIFIER },
      },
    ]);
    phone.close();
  } finally {
    await r.close();
  }
  const keyed = await relay({ apiKey: 'sk_test' });
  try {
    const { phone } = await signedIn(keyed.base, 'user_1');
    assert.strictEqual(keyed.workos.posts[0].body.client_secret, 'sk_test');
    phone.close();
  } finally {
    await keyed.close();
  }
});

test('a code WorkOS refuses, or a token that does not check, is an error and the socket closes', async () => {
  const r = await relay();
  try {
    const phone = connect(`${r.base}/ask`);
    await phone.opened;
    phone.send(JSON.stringify({ code: 'made up', verifier: VERIFIER }));
    assert.deepStrictEqual(await phone.next(), { error: 'Invalid authorization code' });
    await phone.closed;
  } finally {
    await r.close();
  }
  const forged = await relay({ workosFetch: async () => ({ access_token: 'not.a.jwt', user: { email: 'x@y' } }) });
  try {
    const phone = connect(`${forged.base}/ask`);
    await phone.opened;
    phone.send(JSON.stringify({ code: 'good:user_1', verifier: VERIFIER }));
    assert.deepStrictEqual(await phone.next(), { error: 'malformed token' });
    await phone.closed;
  } finally {
    await forged.close();
  }
});

test('only the same user\'s signed in PCs that take asks are listed, and list asks again', async () => {
  const r = await relay();
  try {
    const desk = await pc(r.base, 'secret-desk-0000000000', 'user_1', { name: 'Desk' });
    const old = await pc(r.base, 'secret-old-00000000000', 'user_1', { asks: false, name: 'Old' });
    const theirs = await pc(r.base, 'secret-theirs-00000000', 'user_2', { name: 'Theirs' });
    const plain = await pc(r.base, 'secret-plain-000000000', null, { name: 'Plain' });
    const { phone, first } = await signedIn(r.base, 'user_1');
    assert.deepStrictEqual(first, { machines: [{ id: desk.id, name: 'Desk' }], email: 'user_1@example.com' });
    const laptop = await pc(r.base, 'secret-laptop-00000000', 'user_1', { name: 'Laptop' });
    phone.send('{"list":1}');
    const again = await phone.next();
    assert.deepStrictEqual(
      again.machines,
      [
        { id: desk.id, name: 'Desk' },
        { id: laptop.id, name: 'Laptop' },
      ].sort((a, b) => (a.id < b.id ? -1 : 1)),
    );
    // A PC that is not listed cannot be asked.
    for (const other of [old, theirs, plain]) {
      phone.send(JSON.stringify({ ask: other.id }));
      assert.deepStrictEqual(await phone.next(), { error: 'no such machine' });
    }
    assert.ok(await old.quiet(50), 'nor is it told of an ask');
    for (const ws of [phone, desk, old, theirs, plain, laptop]) ws.close();
  } finally {
    await r.close();
  }
});

test('nothing but a code is taken before sign in, and a list or ask then goes nowhere', async () => {
  const r = await relay();
  try {
    const desk = await pc(r.base, 'secret-desk-0000000000', 'user_1');
    const phone = connect(`${r.base}/ask`);
    await phone.opened;
    phone.send(JSON.stringify({ ask: desk.id }));
    phone.send('{"list":1}');
    phone.send(Buffer.from('frame'));
    assert.ok(await phone.quiet());
    assert.ok(await desk.quiet(0));
    phone.send('{"ping":1}');
    assert.deepStrictEqual(await phone.next(), { pong: 1 });
    phone.close();
    desk.close();
  } finally {
    await r.close();
  }
});

test('an ask opens a channel on the PC: frames pass both ways, never a broadcast', async () => {
  const r = await relay();
  try {
    const desk = await pc(r.base, 'secret-desk-0000000000', 'user_1');
    const watcher = connect(`${r.base}/phone?id=${desk.id}`);
    assert.deepStrictEqual(await watcher.next(), { relay: 'online' });
    const watcherCh = (await desk.next()).open;
    const { phone } = await signedIn(r.base, 'user_1');
    phone.send(JSON.stringify({ ask: desk.id }));
    const told = await desk.next();
    assert.deepStrictEqual(Object.keys(told).sort(), ['ask', 'email']);
    assert.strictEqual(told.email, 'user_1@example.com');
    const ch = told.ask;
    assert.ok(Number.isInteger(ch) && ch !== watcherCh && ch > 0);

    phone.send(Buffer.from('{"t":"ask"}'));
    const f = R.unframe(await desk.next());
    assert.strictEqual(f.ch, ch);
    assert.strictEqual(f.payload.toString(), '{"t":"ask"}');

    desk.send(R.frame(ch, Buffer.from('{"t":"asking"}')));
    assert.strictEqual((await phone.next()).toString(), '{"t":"asking"}');
    desk.send(R.frame(R.BROADCAST, Buffer.from('to every phone')));
    assert.strictEqual((await watcher.next()).toString(), 'to every phone');
    assert.ok(await phone.quiet(), 'a broadcast never reaches an ask');

    // A second ask closes the first, on its PC.
    const laptop = await pc(r.base, 'secret-laptop-00000000', 'user_1');
    phone.send(JSON.stringify({ ask: laptop.id }));
    assert.deepStrictEqual(await desk.next(), { close: ch });
    const ch2 = (await laptop.next()).ask;
    assert.ok(ch2);
    desk.send(R.frame(ch, Buffer.from('late')));
    phone.send(Buffer.from('to the laptop'));
    assert.strictEqual(R.unframe(await laptop.next()).payload.toString(), 'to the laptop');
    assert.ok(await phone.quiet(), 'the closed channel passes nothing');

    // The phone's socket closing closes the ask on its PC.
    phone.close();
    assert.deepStrictEqual(await laptop.next(), { close: ch2 });
    for (const ws of [desk, laptop, watcher]) ws.close();
  } finally {
    await r.close();
  }
});

test('the PC going tells the phone offline, and the phone may ask again', async () => {
  const r = await relay();
  try {
    const desk = await pc(r.base, 'secret-desk-0000000000', 'user_1');
    const { phone } = await signedIn(r.base, 'user_1');
    phone.send(JSON.stringify({ ask: desk.id }));
    await desk.next();
    desk.close();
    assert.deepStrictEqual(await phone.next(), { relay: 'offline' });
    const back = await pc(r.base, 'secret-desk-0000000000', 'user_1');
    assert.ok(await back.quiet(), 'a PC coming back is not opened the old ask');
    phone.send(JSON.stringify({ ask: back.id }));
    assert.ok((await back.next()).ask);

    // A reconnect drops the ask too, since its handshake lived in the old socket.
    const again = await pc(r.base, 'secret-desk-0000000000', 'user_1');
    assert.deepStrictEqual(await phone.next(), { relay: 'offline' });
    assert.ok(await again.quiet());
    phone.close();
    again.close();
  } finally {
    await r.close();
  }
});

test('the PC closing the ask channel stops its frames both ways', async () => {
  const r = await relay();
  try {
    const desk = await pc(r.base, 'secret-desk-0000000000', 'user_1');
    const { phone } = await signedIn(r.base, 'user_1');
    phone.send(JSON.stringify({ ask: desk.id }));
    const ch = (await desk.next()).ask;
    desk.send(R.frame(ch, Buffer.from('{"t":"refused"}')));
    desk.send(JSON.stringify({ close: ch }));
    assert.strictEqual((await phone.next()).toString(), '{"t":"refused"}');
    phone.send(Buffer.from('after'));
    assert.ok(await desk.quiet());
    phone.close();
    desk.close();
  } finally {
    await r.close();
  }
});

test('an ask socket with no code in time, and every ask past its life, is closed', async () => {
  const r = await relay({ askSignIn: 100, askLife: 400 });
  try {
    const idle = connect(`${r.base}/ask`);
    await idle.opened;
    assert.deepStrictEqual(await idle.next(), { error: 'no sign in in time' });
    await idle.closed;

    const desk = await pc(r.base, 'secret-desk-0000000000', 'user_1');
    const { phone } = await signedIn(r.base, 'user_1');
    phone.send(JSON.stringify({ ask: desk.id }));
    const ch = (await desk.next()).ask;
    // Signed in, it outlives the sign in limit, not its life.
    await new Promise((ok) => setTimeout(ok, 150));
    assert.strictEqual(phone.readyState, WebSocket.OPEN);
    assert.deepStrictEqual(await phone.next(), { error: 'time is up' });
    await phone.closed;
    assert.deepStrictEqual(await desk.next(), { close: ch });
    desk.close();
  } finally {
    await r.close();
  }
});

test('ask control is parsed, anything else dropped', () => {
  const id = 'a'.repeat(32);
  const p = (o) => R.parseAsk(Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)));
  assert.deepStrictEqual(p({ code: 'c', verifier: VERIFIER }), { code: 'c', verifier: VERIFIER });
  assert.deepStrictEqual(p({ list: 1 }), { list: true });
  assert.deepStrictEqual(p({ ask: id }), { ask: id });
  assert.deepStrictEqual(p({ ping: 1 }), { ping: true });
  assert.strictEqual(p({ code: 'c', verifier: 'short' }), null);
  assert.strictEqual(p({ code: '', verifier: VERIFIER }), null);
  assert.strictEqual(p({ ask: 'nope' }), null);
  assert.strictEqual(p('nope'), null);
});
