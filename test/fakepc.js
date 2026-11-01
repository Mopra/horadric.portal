// A stand-in for Horadric's PC side, to try the relay and the page without
// a PC: node test/fakepc.js [relay ws url]. It prints a pairing link,
// answers hello, lists sessions, projects, folders and quest logs, starts
// and makes projects, adds quests, takes photos, renames and stops
// sessions, answers their last reply, echoes what the phone types into
// the watched session's screen, and streams output into the working one.
// With FAKE_TOKEN (test/fakerelay.js takes "fake:user_fake") it dials
// signed in and with asks=1, and lets a phone in that signs in (Pairing
// v4): it prints the code and says yes after 4 seconds, or no with
// FAKE_ASK=no.
'use strict';
const crypto = require('crypto');
const os = require('os');
const WebSocket = require('ws');
const R = require('../relay');

const relay = (process.argv[2] || 'ws://127.0.0.1:43200').replace(/\/+$/, '');
const page = process.argv[3] || relay.replace(/^ws/, 'http');
const secret = process.env.FAKE_SECRET || 'fake-pc-secret-for-testing-0000000000000000';
const keyB64 = process.env.FAKE_KEY || 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const key = Buffer.from(keyB64, 'base64url');
const id = R.pcId(secret);

const name = 'Fake ' + os.hostname();
console.log(`pair: ${page}/#r=${encodeURIComponent(relay)}&id=${id}&k=${keyB64}&n=${encodeURIComponent(name)}`);
console.log(`qr:   ${page}/pair.html#r=${encodeURIComponent(relay)}&id=${id}&k=${keyB64}&n=${encodeURIComponent(name)}`);

// The phones let in by signing in each have a key of their own; a
// channel is answered with the key that opened its frames.
const keys = [key];
const chKey = new Map();

function seal(obj, k) {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', k || key, nonce);
  const body = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final(), c.getAuthTag()]);
  return Buffer.concat([nonce, body]);
}
function openWith(k, buf) {
  const nonce = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', k, nonce);
  d.setAuthTag(tag);
  return JSON.parse(Buffer.concat([d.update(buf.subarray(12, buf.length - 16)), d.final()]).toString('utf8'));
}
function open(buf, ch) {
  for (const k of keys) {
    try {
      const m = openWith(k, buf);
      chKey.set(ch, k);
      return m;
    } catch {}
  }
  throw new Error('no key opens it');
}

// Pairing v4, the PC's side, as docs/PORTAL.md has it.
const token = process.env.FAKE_TOKEN || '';
const me = crypto.createECDH('prime256v1');
me.generateKeys();
const myPub = me.getPublicKey();
const signins = new Map(); // ch -> { email, step, name, commit, nonce }
function derive(label, parts) {
  const h = crypto.createHash('sha256').update(label, 'utf8');
  for (const p of parts) {
    const n = Buffer.alloc(4);
    n.writeUInt32BE(p.length);
    h.update(n).update(p);
  }
  return h.digest();
}
const b64 = (u) => Buffer.from(u).toString('base64url');
function onAsk(ch, payload) {
  const a = signins.get(ch);
  const plain = (obj) => ws.send(R.frame(ch, Buffer.from(JSON.stringify(obj))));
  const refuse = (why) => {
    console.log(`ask ${ch} refused: ${why}`);
    plain({ t: 'refused' });
    signins.delete(ch);
    ws.send(JSON.stringify({ close: ch }));
  };
  let m;
  try {
    m = JSON.parse(payload.toString('utf8'));
  } catch {
    return refuse('not JSON');
  }
  console.log('ask', ch, m);
  if (m.t === 'refused') return signins.delete(ch);
  if (a.step === 'ask' && m.t === 'ask' && m.v === 1 && typeof m.commit === 'string') {
    Object.assign(a, { step: 'reveal', name: String(m.name || 'Phone'), commit: m.commit, nonce: crypto.randomBytes(16) });
    return plain({ t: 'asking', v: 1, name, brother: id, pub: b64(myPub), nonce: b64(a.nonce) });
  }
  if (a.step === 'reveal' && m.t === 'reveal') {
    const pub = Buffer.from(String(m.pub), 'base64url');
    const nonce = Buffer.from(String(m.nonce), 'base64url');
    if (b64(derive('horadric ask commit v1', [pub, nonce])) !== a.commit || pub.equals(myPub)) return refuse('commit');
    const s = me.computeSecret(pub);
    const parts = [s, pub, nonce, myPub, a.nonce];
    const n = derive('horadric ask code v1', parts).readUInt32BE(0) % 1000000;
    const code = String(n).padStart(6, '0').replace(/^(...)/, '$1 ');
    const askKey = derive('horadric ask key v1', parts);
    a.step = 'human';
    const yes = process.env.FAKE_ASK !== 'no';
    console.log(`${a.name} wants to use Town Portal, signed in as ${a.email}. Does the phone show ${code}? Saying ${yes ? 'yes' : 'no'} in 4 s.`);
    setTimeout(() => {
      if (signins.get(ch) !== a) return;
      if (!yes) return refuse('the human said no');
      const phone = crypto.randomBytes(8).toString('base64url');
      keys.push(derive('horadric phone key v1', [s, pub, myPub, Buffer.from(phone), Buffer.from(id)]));
      ws.send(R.frame(ch, seal({ t: 'paired', phone, brother: id, bkey: b64(myPub) }, askKey)));
      signins.delete(ch);
      console.log(`paired ${a.name} as ${phone}`);
    }, 4000);
    return;
  }
  refuse('out of order');
}

// The VAPID key pair a real PC keeps in portal.json, made fresh here.
const vapid = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const vapidJwk = vapid.publicKey.export({ format: 'jwk' });
const vapidRaw = Buffer.concat([Buffer.from([4]), Buffer.from(vapidJwk.x, 'base64url'), Buffer.from(vapidJwk.y, 'base64url')]).toString('base64url');
const subs = new Map(); // endpoint -> subscription

// Sessions name their project by name, as the real PC does.
const projects = [
  { path: 'C:\\Users\\me\\horadric.dev', name: 'horadric.dev' },
  { path: 'C:\\Users\\me\\horadric.portal', name: 'horadric.portal' },
  { path: 'C:\\Users\\me\\quiet', name: 'quiet' },
];
let made = 0;

// The folders the PC's projects live in, as 0.22's folders answer has them.
const roots = [
  {
    path: 'C:\\Users\\me',
    name: 'me',
    list: [
      { path: 'C:\\Users\\me\\horadric.dev', name: 'horadric.dev', git: true },
      { path: 'C:\\Users\\me\\horadric.portal', name: 'horadric.portal', git: true },
      { path: 'C:\\Users\\me\\quiet', name: 'quiet', git: false },
      { path: 'C:\\Users\\me\\forgotten', name: 'forgotten', git: true },
    ],
  },
  {
    path: 'D:\\Work',
    name: 'Work',
    list: [{ path: 'D:\\Work\\client-site', name: 'client-site', git: true }],
  },
];
const known = (path) => roots.some((r) => r.list.some((f) => f.path === path));

// Starts a session in a folder, putting it on the "tiles" first.
function startSession(path, reply) {
  const name = path.split('\\').pop();
  if (!projects.some((x) => x.path === path)) {
    projects.push({ path, name });
    broadcast({ t: 'projects', list: projects });
  }
  const id = 'n' + ++made;
  // A real PC takes a moment to start a host.
  setTimeout(() => {
    sessions.push({ id, name: `new ${made}`, project: name, phase: 'idle', line: '' });
    screens[id] = [`New session in ${name}`, '> '];
    broadcast({ t: 'sessions', list: sessions });
    reply({ t: 'started', project: path, id });
  }, 1500);
}

const sessions = [
  { id: 's1', name: 'relay', project: 'horadric.portal', phase: 'waiting', line: 'Bash: npm test', ask: { kind: 'permission', tool: 'Bash', options: [{ label: 'Yes', keys: '1' }, { label: 'No', keys: '2' }] } },
  { id: 's2', name: 'ui', project: 'horadric.dev', phase: 'working', line: 'Editing app.rs' },
  { id: 's4', name: 'pick', project: 'horadric.dev', phase: 'waiting', line: 'Question' },
  { id: 's3', name: 'docs', project: 'horadric.dev', phase: 'idle', line: '', paused: true },
];
// What the waiting ones ask, as the PC's `ask` has it.
const asks = {
  s1: { kind: 'permission', tool: 'Bash', detail: 'npm test', options: [{ label: 'Yes', keys: '1' }, { label: 'Always', keys: '2' }, { label: 'No', keys: '' }] },
  s4: { kind: 'question', tool: 'AskUserQuestion', detail: 'Which database?', options: [{ label: 'SQLite', keys: '1' }, { label: 'Postgres', keys: '2' }] },
};
for (const [sid, ask] of Object.entries(asks)) sessions.find((x) => x.id === sid).ask = { ...ask, since: Math.floor(Date.now() / 1000) - 90 };
const screens = {};
for (const s of sessions) {
  screens[s.id] = [`Session ${s.name}`, ''.padEnd(100, '-'), ...Array.from({ length: 40 }, (_, i) => `line ${i} of ${s.name}`), '> '];
}
const watching = new Map();

// What each session changed, as 0.24's changes and diff answers have it.
const changed = {
  s1: [
    { path: 'server.js', added: 14, removed: 3 },
    { path: 'test/relay.test.js', added: 40, removed: 0 },
    { path: 'public/icon.png', added: null, removed: null },
  ],
  s2: [
    { path: 'crates/horadric-ui/src/portaling.rs', added: 2, removed: 1 },
    { path: 'Cargo.lock', added: 3000, removed: 0 },
  ],
};
const diffs = {
  'server.js': [
    'diff --git a/server.js b/server.js',
    'index 1111111..2222222 100644',
    '--- a/server.js',
    '+++ b/server.js',
    '@@ -10,7 +10,9 @@ const http = require(\'http\');',
    ' const PORT = Number(process.env.PORT) || 43200;',
    '-const MAX = 1 << 20;',
    '+// A frame is at most 1 MB, so a phone cannot make the relay hold more than that for it, whatever it sends.',
    '+const MAX = 1 << 20;',
    '+const PHONES = 8;',
    ' ',
    '\tfunction pcId(secret) {',
    '@@ -80,4 +82,4 @@ function route(req) {',
    '-  return null;',
    '+  return undefined;',
    '\\ No newline at end of file',
    '',
  ].join('\n'),
  'public/icon.png': 'diff --git a/public/icon.png b/public/icon.png\nBinary files a/public/icon.png and b/public/icon.png differ\n',
  'crates/horadric-ui/src/portaling.rs': '@@ -1,3 +1,4 @@\n use std::path::Path;\n-use x;\n+use y;\n+use z;\n',
  'Cargo.lock': '@@ -0,0 +1,3000 @@\n' + Array.from({ length: 3000 }, (_, i) => `+line ${i}`).join('\n') + '\n',
};
// Quest logs, as 0.24's quests answer has them, and the phones that asked.
const logs = [
  {
    project: projects[0].path,
    name: projects[0].name,
    mode: 'warriv',
    warriv: { on: true, drives: true, line: 'reads Build the inbox' },
    done: 14,
    quests: [
      { title: 'Build the inbox', state: 'working', session: 's2', why: '', notes: ['See PLAN.md, item 2.', 'Cards on top of the list.'] },
      { title: 'Pushes that say what waits', state: 'after', session: null, why: 'after Build the inbox', notes: ['After: Build the inbox'] },
      { title: 'Pick a colour for the badge', state: 'blocked', session: 's3', why: 'which gold, the tile\'s or the title\'s?', notes: [] },
      { title: 'Swipe between sessions', state: 'review', session: null, why: '', notes: [] },
      { title: 'A quest with a long title that has to wrap over more than one line on a phone', state: 'open', session: null, why: '', notes: [] },
    ],
  },
  { project: projects[1].path, name: projects[1].name, mode: 'manual', warriv: { on: false, drives: false, line: '' }, done: 3, quests: [] },
  { project: projects[2].path, name: projects[2].name, mode: 'manual', warriv: { on: false, drives: false, line: '' }, done: 0, quests: [] },
];
const questsTo = new Set();
const questsMessage = () => ({ t: 'quests', list: logs });

let ws;
function start() {
  const headers = { 'X-Horadric-Secret': secret };
  if (token) headers.Authorization = `Bearer ${token}`;
  ws = new WebSocket(`${relay}/pc?${new URLSearchParams(token ? { name, asks: '1' } : { name })}`, { headers });
  ws.on('open', () => console.log('connected as', id));
  ws.on('message', (data, isBinary) => {
    if (!isBinary) {
      const m = JSON.parse(data.toString());
      heard = Date.now();
      if (m.pong) return;
      console.log('relay:', m);
      if (Number.isInteger(m.ask)) signins.set(m.ask, { email: m.email, step: 'ask' });
      if (m.close) {
        signins.delete(m.close);
        watching.delete(m.close);
        questsTo.delete(m.close);
      }
      return;
    }
    const f = R.unframe(data);
    if (signins.has(f.ch)) return onAsk(f.ch, f.payload);
    let msg;
    try {
      msg = open(f.payload, f.ch);
    } catch {
      return console.log('dropped a frame that did not decrypt');
    }
    console.log('ch', f.ch, msg);
    const reply = (obj) => ws.send(R.frame(f.ch, seal(obj, chKey.get(f.ch))));
    if (msg.t === 'hello') {
      reply({ t: 'hello', v: 1, pc: name, vapid: vapidRaw });
      reply({ t: 'sessions', list: sessions });
      reply({ t: 'projects', list: projects });
    } else if (msg.t === 'watch') {
      watching.set(f.ch, msg.id);
      const s = sessions.find((x) => x.id === msg.id);
      if (s && s.paused) return reply({ t: 'error', text: `${s.name} is paused` });
      sendScreen(f.ch, msg.id);
    } else if (msg.t === 'start') {
      if (!projects.some((x) => x.path === msg.project) && !known(msg.project)) {
        return reply({ t: 'error', text: 'No such project' });
      }
      startSession(msg.project, reply);
    } else if (msg.t === 'folders') {
      reply({ t: 'folders', roots });
    } else if (msg.t === 'create') {
      const root = roots.find((r) => r.path === msg.root);
      const name = String(msg.name || '');
      if (!root) return reply({ t: 'error', text: 'That is not one of the project folders.' });
      if (!/^[A-Za-z0-9 ._-]{1,64}$/.test(name) || name.startsWith('.')) return reply({ t: 'error', text: 'That name is not allowed.' });
      if (root.list.some((f) => f.name.toLowerCase() === name.toLowerCase())) return reply({ t: 'error', text: `${name} exists already.` });
      const path = `${root.path}\\${name}`;
      root.list.unshift({ path, name, git: true });
      startSession(path, reply);
    } else if (msg.t === 'attach') {
      const bytes = Buffer.from(msg.data || '', 'base64url');
      console.log(`attach ${msg.name}: ${bytes.length} bytes for ${msg.id}`);
      const path = ['C:', 'Users', 'me', 'AppData', 'Roaming', 'Horadric', 'portal-attach', msg.id, `${Math.floor(Date.now() / 1000)}-${msg.name}`].join('\\');
      setTimeout(() => reply({ t: 'attached', id: msg.id, name: msg.name, path }), 300);
    } else if (msg.t === 'resume') {
      const s = sessions.find((x) => x.id === msg.id);
      if (!s) return reply({ t: 'error', text: 'No such session' });
      setTimeout(() => {
        s.paused = false;
        broadcast({ t: 'sessions', list: sessions });
        for (const [ch, sid] of watching) if (sid === s.id) sendScreen(ch, sid);
      }, 1000);
    } else if (msg.t === 'changes') {
      reply({ t: 'changes', id: msg.id, files: changed[msg.id] || [] });
    } else if (msg.t === 'diff') {
      const files = changed[msg.id] || [];
      if (!files.some((f) => f.path === msg.path)) return reply({ t: 'error', text: 'That file has no changes now.' });
      reply({ t: 'diff', id: msg.id, path: msg.path, text: diffs[msg.path] || '', cut: msg.path === 'Cargo.lock' });
    } else if (msg.t === 'quests') {
      questsTo.add(f.ch);
      reply(questsMessage());
    } else if (msg.t === 'quest_add') {
      const log = logs.find((l) => l.project === msg.project);
      const title = String(msg.title || '').trim().replace(/\s+/g, ' ');
      if (!log) return reply({ t: 'error', text: `${msg.project} is not one of the PC's projects.` });
      if (!title) return reply({ t: 'error', text: 'Say what the quest is.' });
      const notes = String(msg.notes || '').split('\n').map((l) => l.trim()).filter(Boolean);
      log.quests.push({ title, state: 'open', session: null, why: '', notes });
      reply({ t: 'quest_added', project: log.project, title });
      for (const ch of questsTo) ws.send(R.frame(ch, seal(questsMessage(), chKey.get(ch))));
    } else if (msg.t === 'rename') {
      const s = sessions.find((x) => x.id === msg.id);
      if (!s) return reply({ t: 'error', text: 'That session is gone.' });
      s.name = String(msg.name || '').trim() || `claude ${s.id}`;
      broadcast({ t: 'sessions', list: sessions });
    } else if (msg.t === 'stop') {
      const at = sessions.findIndex((x) => x.id === msg.id);
      if (at < 0) return reply({ t: 'error', text: 'That session is gone.' });
      sessions.splice(at, 1);
      broadcast({ t: 'sessions', list: sessions });
    } else if (msg.t === 'reply') {
      const s = sessions.find((x) => x.id === msg.id);
      const text = s && s.id !== 's3' ? `Done with ${s.name}.\n\nAll 42 tests pass. Want me to ship it?` : null;
      setTimeout(() => reply({ t: 'reply', id: msg.id, text }), 400);
    } else if (msg.t === 'push') {
      subs.set(msg.sub.endpoint, msg.sub);
      console.log('push subscription', msg.sub.endpoint.slice(0, 60));
    } else if (msg.t === 'unpush') {
      subs.delete(msg.endpoint);
    } else if (msg.t === 'unwatch') {
      watching.delete(f.ch);
    } else if (msg.t === 'input') {
      const lines = screens[msg.id];
      if (!lines) return;
      const asked = sessions.find((x) => x.id === msg.id);
      if (asked && asked.ask && /^[0-9]$/.test(msg.data)) {
        setTimeout(() => {
          asked.phase = 'working';
          delete asked.ask;
          broadcast({ t: 'sessions', list: sessions });
        }, 1500);
      }
      const shown = JSON.stringify(msg.data);
      if (msg.data === '\r') lines.push('> ');
      else lines[lines.length - 1] += msg.data.length === 1 && msg.data >= ' ' ? msg.data : msg.data.length > 1 && !msg.data.startsWith('\u001b') ? msg.data : shown;
      for (const [ch, sid] of watching) if (sid === msg.id) sendScreen(ch, sid);
    }
  });
  ws.on('close', () => {
    console.log('closed, retrying');
    setTimeout(start, 1000);
  });
  ws.on('error', (e) => console.log('error', e.message));
}

function broadcast(obj) {
  if (ws && ws.readyState === 1) ws.send(R.frame(R.BROADCAST, seal(obj)));
}

// Liveness, as docs/PORTAL.md asks of a PC.
let heard = Date.now();
setInterval(() => {
  if (!ws || ws.readyState !== 1) return;
  if (Date.now() - heard > 70000) return ws.terminate();
  ws.send('{"ping":1}');
}, 25000).unref();

// A push with no body, signed with VAPID, the way the PC sends one.
function vapidJwt(endpoint) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head = enc({ typ: 'JWT', alg: 'ES256' });
  const body = enc({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'mailto:portal@horadric.dev' });
  const sig = crypto.sign('sha256', Buffer.from(`${head}.${body}`), { key: vapid.privateKey, dsaEncoding: 'ieee-p1363' });
  return `${head}.${body}.${sig.toString('base64url')}`;
}
async function push() {
  for (const sub of subs.values()) {
    const res = await fetch(sub.endpoint, {
      method: 'POST',
      headers: { TTL: '3600', Urgency: 'high', Authorization: `vapid t=${vapidJwt(sub.endpoint)}, k=${vapidRaw}` },
    }).catch((e) => ({ status: 'error ' + e.message }));
    console.log('push', res.status, sub.endpoint.slice(0, 50));
    if (res.status === 404 || res.status === 410) subs.delete(sub.endpoint);
  }
}

function sendScreen(ch, sid) {
  const lines = screens[sid];
  if (!lines) return ws.send(R.frame(ch, seal({ t: 'error', text: 'No such session' }, chKey.get(ch))));
  ws.send(R.frame(ch, seal({ t: 'screen', id: sid, cols: 100, rows: 30, lines, cursor: [lines.length - 1, lines[lines.length - 1].length] }, chKey.get(ch))));
}

// The working session prints a line every half second, and its oldest
// lines fall off past 80 the way a real PC's do past 500, to try how the
// page keeps the view still while output streams in.
let printed = 0;
setInterval(() => {
  const lines = screens.s2;
  const prompt = lines.pop();
  lines.push(`output ${++printed} at ${new Date().toLocaleTimeString()}`, prompt);
  if (lines.length > 80) lines.splice(0, lines.length - 80);
  for (const [ch, sid] of watching) if (sid === 's2') sendScreen(ch, sid);
}, 500).unref();

// Phases change now and then, as on a real PC.
setInterval(() => {
  sessions[1].phase = sessions[1].phase === 'working' ? 'waiting' : 'working';
  broadcast({ t: 'sessions', list: sessions });
}, 5000).unref();

// A push every 20 seconds while a phone is subscribed, to try its
// notification. FAKE_PUSH=0 turns it off.
if (process.env.FAKE_PUSH !== '0') setInterval(() => subs.size && push(), 20000).unref();

start();
