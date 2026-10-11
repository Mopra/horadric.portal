// The Town Portal relay: joins a phone to its PC. Both connect out to it
// over WebSocket, and it passes their encrypted frames along without
// reading them. It keeps nothing on disk. The protocol is docs/PORTAL.md
// in the Horadric repo.
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');
const R = require('./relay');

const PORT = Number(process.env.PORT) || 43200;
const HOST = process.env.HOST || '127.0.0.1';
const PUBLIC = path.join(__dirname, 'public');

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};

// id -> { pc, phones: Map<ch, ws>, last }
const rooms = new Map();

function serveStatic(req, res) {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/health') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    return res.end(`ok ${rooms.size}\n`);
  }
  let rel;
  try {
    rel = decodeURIComponent(url.pathname);
  } catch {
    res.writeHead(400);
    return res.end();
  }
  if (rel.endsWith('/')) rel += 'index.html';
  const file = path.normalize(path.join(PUBLIC, rel));
  if (!file.startsWith(PUBLIC + path.sep)) {
    res.writeHead(403);
    return res.end();
  }
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404, { 'content-type': 'text/plain' });
      return res.end('not found\n');
    }
    res.writeHead(200, {
      'content-type': TYPES[path.extname(file)] || 'application/octet-stream',
      // The page must pick up a new version at once, and it is small.
      'cache-control': 'no-cache',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    });
    res.end(data);
  });
}

function room(id) {
  let r = rooms.get(id);
  if (!r) {
    r = { pc: null, phones: new Map(), last: 0 };
    rooms.set(id, r);
  }
  return r;
}

function dropIfEmpty(id) {
  const r = rooms.get(id);
  if (r && !r.pc && r.phones.size === 0) rooms.delete(id);
}

const sendText = (ws, obj) => ws && ws.readyState === 1 && ws.send(JSON.stringify(obj));

const server = http.createServer(serveStatic);
const wss = new WebSocketServer({ noServer: true, maxPayload: R.MAX_FRAME + 4 });

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/pc') {
    const secret = url.searchParams.get('secret');
    if (!R.isSecret(secret)) return reject(socket, 400);
    wss.handleUpgrade(req, socket, head, (ws) => onPc(ws, R.pcId(secret)));
  } else if (url.pathname === '/phone') {
    const id = url.searchParams.get('id');
    if (!R.isId(id)) return reject(socket, 400);
    const r = rooms.get(id);
    if (r && r.phones.size >= R.MAX_PHONES) return reject(socket, 429);
    wss.handleUpgrade(req, socket, head, (ws) => onPhone(ws, id));
  } else {
    reject(socket, 404);
  }
});

function reject(socket, code) {
  socket.write(`HTTP/1.1 ${code} ${http.STATUS_CODES[code]}\r\nConnection: close\r\n\r\n`);
  socket.destroy();
}

function onPc(ws, id) {
  const r = room(id);
  // A second connection with the same id is the PC reconnecting.
  if (r.pc) r.pc.terminate();
  r.pc = ws;
  alive(ws);
  for (const [ch, phone] of r.phones) {
    sendText(phone, { relay: 'online' });
    sendText(ws, { open: ch });
  }
  ws.on('message', (data, isBinary) => {
    if (!isBinary) return;
    const f = R.unframe(data);
    if (!f) return;
    if (f.ch === R.BROADCAST) {
      for (const phone of r.phones.values()) if (phone.readyState === 1) phone.send(f.payload);
    } else {
      const phone = r.phones.get(f.ch);
      if (phone && phone.readyState === 1) phone.send(f.payload);
    }
  });
  ws.on('close', () => {
    if (r.pc !== ws) return;
    r.pc = null;
    for (const phone of r.phones.values()) sendText(phone, { relay: 'offline' });
    dropIfEmpty(id);
  });
  ws.on('error', () => {});
}

function onPhone(ws, id) {
  const r = room(id);
  if (r.phones.size >= R.MAX_PHONES) return ws.close(1013, 'too many phones');
  const ch = R.nextChannel(r.last, r.phones);
  r.last = ch;
  r.phones.set(ch, ws);
  alive(ws);
  sendText(ws, { relay: r.pc ? 'online' : 'offline' });
  if (r.pc) sendText(r.pc, { open: ch });
  ws.on('message', (data, isBinary) => {
    if (!isBinary || !r.pc || r.pc.readyState !== 1) return;
    r.pc.send(R.frame(ch, data));
  });
  ws.on('close', () => {
    r.phones.delete(ch);
    if (r.pc) sendText(r.pc, { close: ch });
    dropIfEmpty(id);
  });
  ws.on('error', () => {});
}

// A ping every 30 seconds; a socket that missed the last pong is gone.
function alive(ws) {
  ws.isAlive = true;
  ws.on('pong', () => (ws.isAlive = true));
}
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    ws.ping();
  }
}, 30000).unref();

server.listen(PORT, HOST, () => console.log(`horadric portal relay on http://${HOST}:${PORT}`));
