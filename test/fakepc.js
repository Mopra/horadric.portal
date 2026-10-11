// A stand-in for Horadric's PC side, to try the relay and the page without
// a PC: node test/fakepc.js [relay ws url]. It prints a pairing link,
// answers hello, lists two sessions and echoes what the phone types into
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

const sessions = [
  { id: 's1', name: 'relay', project: 'C:\\Users\\me\\horadric.portal', phase: 'waiting', line: 'Bash: npm test' },
  { id: 's2', name: 'ui', project: 'C:\\Users\\me\\horadric.dev', phase: 'working', line: 'Editing app.rs' },
  { id: 's3', name: 'docs', project: 'C:\\Users\\me\\horadric.dev', phase: 'idle', line: '' },
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
      reply({ t: 'hello', v: 1, pc: name });
      reply({ t: 'sessions', list: sessions });
    } else if (msg.t === 'watch') {
      watching.set(f.ch, msg.id);
      sendScreen(f.ch, msg.id);
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

function sendScreen(ch, sid) {
  const lines = screens[sid];
  if (!lines) return ws.send(R.frame(ch, seal({ t: 'error', text: 'No such session' })));
  ws.send(R.frame(ch, seal({ t: 'screen', id: sid, cols: 100, rows: 30, lines, cursor: [lines.length - 1, lines[lines.length - 1].length] })));
}

// Phases change now and then, as on a real PC.
setInterval(() => {
  sessions[1].phase = sessions[1].phase === 'working' ? 'waiting' : 'working';
  if (ws && ws.readyState === 1) ws.send(R.frame(R.BROADCAST, seal({ t: 'sessions', list: sessions })));
}, 5000).unref();

start();
