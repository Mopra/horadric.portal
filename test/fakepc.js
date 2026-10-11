// A stand-in for Horadric's PC side, to try the relay and the page without
// a PC: node test/fakepc.js [relay ws url]. It prints a pairing link,
// answers hello, lists sessions, projects and folders, starts and makes
// projects, and echoes what the phone types into
// the watched session's screen.
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

function seal(obj) {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const body = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final(), c.getAuthTag()]);
  return Buffer.concat([nonce, body]);
}
function open(buf) {
  const nonce = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  d.setAuthTag(tag);
  return JSON.parse(Buffer.concat([d.update(buf.subarray(12, buf.length - 16)), d.final()]).toString('utf8'));
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
  { id: 's1', name: 'relay', project: 'horadric.portal', phase: 'waiting', line: 'Bash: npm test' },
  { id: 's2', name: 'ui', project: 'horadric.dev', phase: 'working', line: 'Editing app.rs' },
  { id: 's3', name: 'docs', project: 'horadric.dev', phase: 'idle', line: '', paused: true },
];
const screens = {};
for (const s of sessions) {
  screens[s.id] = [`Session ${s.name}`, ''.padEnd(100, '-'), ...Array.from({ length: 40 }, (_, i) => `line ${i} of ${s.name}`), '> '];
}
const watching = new Map();

let ws;
function start() {
  ws = new WebSocket(`${relay}/pc?secret=${encodeURIComponent(secret)}`);
  ws.on('open', () => console.log('connected as', id));
  ws.on('message', (data, isBinary) => {
    if (!isBinary) {
      const m = JSON.parse(data.toString());
      heard = Date.now();
      if (m.pong) return;
      console.log('relay:', m);
      if (m.close) watching.delete(m.close);
      return;
    }
    const f = R.unframe(data);
    let msg;
    try {
      msg = open(f.payload);
    } catch {
      return console.log('dropped a frame that did not decrypt');
    }
    console.log('ch', f.ch, msg);
    const reply = (obj) => ws.send(R.frame(f.ch, seal(obj)));
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
    } else if (msg.t === 'resume') {
      const s = sessions.find((x) => x.id === msg.id);
      if (!s) return reply({ t: 'error', text: 'No such session' });
      setTimeout(() => {
        s.paused = false;
        broadcast({ t: 'sessions', list: sessions });
        for (const [ch, sid] of watching) if (sid === s.id) sendScreen(ch, sid);
      }, 1000);
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
  if (!lines) return ws.send(R.frame(ch, seal({ t: 'error', text: 'No such session' })));
  ws.send(R.frame(ch, seal({ t: 'screen', id: sid, cols: 100, rows: 30, lines, cursor: [lines.length - 1, lines[lines.length - 1].length] })));
}

// Phases change now and then, as on a real PC.
setInterval(() => {
  sessions[1].phase = sessions[1].phase === 'working' ? 'waiting' : 'working';
  broadcast({ t: 'sessions', list: sessions });
}, 5000).unref();

// A push every 20 seconds while a phone is subscribed, to try its
// notification. FAKE_PUSH=0 turns it off.
if (process.env.FAKE_PUSH !== '0') setInterval(() => subs.size && push(), 20000).unref();

start();
