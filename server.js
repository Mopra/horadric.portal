// The Town Portal relay: joins a phone to its PC, and a signed in PC to
// its brothers. They all connect out to it over WebSocket, and it passes
// their encrypted frames along without reading them. It keeps nothing on
// disk. The protocol is docs/PORTAL.md in the Horadric repo.
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');
const R = require('./relay');
const { createVerifiers, AuthError } = require('./auth');

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

// Close codes for a PC whose token was not accepted. 4401: sign in again.
// 4503: the token could not be checked now, so try again later as is.
const CLOSE_BAD_TOKEN = 4401;
const CLOSE_AUTH_DOWN = 4503;
// The user has as many machines connected as the relay serves one.
const CLOSE_TOO_MANY = 4429;

const sendText = (ws, obj) => ws && ws.readyState === 1 && ws.send(JSON.stringify(obj));

function reject(socket, code) {
  socket.write(`HTTP/1.1 ${code} ${http.STATUS_CODES[code]}\r\nConnection: close\r\n\r\n`);
  socket.destroy();
}

// options.verify(token) resolves to the token's claims; tests pass their own.
function createRelay(options = {}) {
  const trustProxy = options.trustProxy ?? process.env.TRUST_PROXY === '1';
  const now = options.now || Date.now;
  const verify =
    options.verify ||
    createVerifiers((process.env.WORKOS_CLIENT_ID || '').split(',').filter(Boolean), {
      issuers: process.env.WORKOS_ISSUER ? process.env.WORKOS_ISSUER.split(',') : undefined,
    });

  // id -> { id, pc, phones: Map<ch, ws>, links: Map<ch, { peer, ch }>, last, user, name }
  const rooms = new Map();
  // WorkOS user (sub) -> Set of ids of that user's connected PCs.
  const users = new Map();
  // Address -> PC sockets open from it, counted from the upgrade on.
  const ips = new Map();

  function holdIp(ip) {
    const n = ips.get(ip) || 0;
    if (n >= R.MAX_PCS_PER_IP) return false;
    ips.set(ip, n + 1);
    return true;
  }

  function releaseIp(ip) {
    const n = (ips.get(ip) || 1) - 1;
    if (n > 0) ips.set(ip, n);
    else ips.delete(ip);
  }

  // Whether one more PC, id, may join user's: one already there reconnects.
  function hasRoomFor(user, id) {
    const ids = users.get(user);
    return !ids || ids.has(id) || ids.size < R.MAX_PCS_PER_USER;
  }

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
      r = { id, pc: null, phones: new Map(), links: new Map(), last: 0, user: null, name: 'PC' };
      rooms.set(id, r);
    }
    return r;
  }

  function dropIfEmpty(id) {
    const r = rooms.get(id);
    if (r && !r.pc && r.phones.size === 0) rooms.delete(id);
  }

  // Phone and brother channels share one number space per PC, so a frame's
  // channel always says which of the two it is.
  const taken = (r) => ({ has: (ch) => r.phones.has(ch) || r.links.has(ch) });

  function tellBrothers(sub) {
    const ids = users.get(sub);
    if (!ids) return;
    const pcs = [...ids].map((id) => rooms.get(id));
    for (const r of pcs) sendText(r.pc, { brothers: R.brothersOf(pcs, r.id) });
  }

  function leaveUser(r) {
    if (!r.user) return;
    const sub = r.user;
    r.user = null;
    const ids = users.get(sub);
    if (ids) {
      ids.delete(r.id);
      if (ids.size === 0) users.delete(sub);
    }
    tellBrothers(sub);
  }

  function closeLink(r, ch) {
    const l = r.links.get(ch);
    if (!l) return;
    r.links.delete(ch);
    l.peer.links.delete(l.ch);
    sendText(l.peer.pc, { close: l.ch });
  }

  function closeLinks(r) {
    for (const ch of [...r.links.keys()]) closeLink(r, ch);
  }

  function join(r, to) {
    const fail = (error) => sendText(r.pc, { error, to });
    if (!r.user) return fail('not signed in');
    const t = rooms.get(to);
    if (!t || t === r || !t.pc || t.user !== r.user) return fail('no such brother');
    if (r.links.size >= R.MAX_LINKS || t.links.size >= R.MAX_LINKS) return fail('too many links');
    const mine = R.nextChannel(r.last, taken(r));
    r.last = mine;
    const theirs = R.nextChannel(t.last, taken(t));
    t.last = theirs;
    r.links.set(mine, { peer: t, ch: theirs });
    t.links.set(theirs, { peer: r, ch: mine });
    sendText(t.pc, { join: theirs, id: r.id, name: r.name });
    sendText(r.pc, { link: mine, id: t.id, name: t.name });
  }

  function onPc(ws, id, user, name) {
    const r = room(id);
    // A second connection with the same id is the PC reconnecting. Its
    // brother channels die with the old socket, as phone sessions would.
    if (r.pc) {
      closeLinks(r);
      r.pc.terminate();
    }
    if (r.user !== user) leaveUser(r);
    r.pc = ws;
    r.name = name;
    alive(ws);
    for (const [ch, phone] of r.phones) {
      sendText(phone, { relay: 'online' });
      sendText(ws, { open: ch });
    }
    if (user) {
      r.user = user;
      if (!users.has(user)) users.set(user, new Set());
      users.get(user).add(id);
      tellBrothers(user);
    }
    ws.on('message', (data, isBinary) => {
      if (!isBinary) {
        const m = R.parseControl(data);
        if (!m) return;
        if (m.ping) return sendText(ws, { pong: 1 });
        if (r.pc !== ws) return;
        if (m.join) return join(r, m.join);
        if (m.close) return closeLink(r, m.close);
        return;
      }
      const f = R.unframe(data);
      if (!f) return;
      if (f.ch === R.BROADCAST) {
        for (const phone of r.phones.values()) if (phone.readyState === 1) phone.send(f.payload);
        return;
      }
      const l = r.links.get(f.ch);
      if (l) {
        if (r.pc === ws && l.peer.pc && l.peer.pc.readyState === 1) l.peer.pc.send(R.frame(l.ch, f.payload));
        return;
      }
      const phone = r.phones.get(f.ch);
      if (phone && phone.readyState === 1) phone.send(f.payload);
    });
    ws.on('close', () => {
      if (r.pc !== ws) return;
      r.pc = null;
      closeLinks(r);
      leaveUser(r);
      for (const phone of r.phones.values()) sendText(phone, { relay: 'offline' });
      dropIfEmpty(id);
    });
    ws.on('error', () => {});
  }

  function onPhone(ws, id) {
    const r = room(id);
    if (r.phones.size >= R.MAX_PHONES) return ws.close(1013, 'too many phones');
    const ch = R.nextChannel(r.last, taken(r));
    r.last = ch;
    r.phones.set(ch, ws);
    alive(ws);
    sendText(ws, { relay: r.pc ? 'online' : 'offline' });
    if (r.pc) sendText(r.pc, { open: ch });
    ws.on('message', (data, isBinary) => {
      if (!isBinary) return R.isPing(data) && sendText(ws, { pong: 1 });
      if (!r.pc || r.pc.readyState !== 1) return;
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

  const server = http.createServer(serveStatic);
  const wss = new WebSocketServer({ noServer: true, maxPayload: R.MAX_FRAME + 4 });

  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url, 'http://x');
    if (url.pathname === '/pc') {
      const { secret, token } = R.credentials(req.headers, url.searchParams, now());
      if (!R.isSecret(secret)) return reject(socket, 400);
      const ip = R.clientIp(req.headers, req.socket.remoteAddress, trustProxy);
      if (!holdIp(ip)) return reject(socket, 429);
      // Held from here, so a token being checked counts too; given back
      // when the socket closes, or now when it never becomes one.
      let held = true;
      const release = () => {
        if (held) releaseIp(ip);
        held = false;
      };
      socket.once('close', release);
      const upgrade = (then) =>
        wss.handleUpgrade(req, socket, head, (ws) => {
          ws.once('close', release);
          then(ws);
        });
      const name = R.cleanName(url.searchParams.get('name'));
      const id = R.pcId(secret);
      if (token === null) return upgrade((ws) => onPc(ws, id, null, name));
      // The token is checked before the PC takes its room, so a refused
      // one never replaces the PC already connected with that secret.
      verify(token).then(
        (claims) => {
          if (socket.destroyed) return release();
          if (!hasRoomFor(claims.sub, id)) return upgrade((ws) => ws.close(CLOSE_TOO_MANY, 'too many machines'));
          upgrade((ws) => onPc(ws, id, claims.sub, name));
        },
        (err) => {
          if (socket.destroyed) return release();
          const retry = err instanceof AuthError ? err.retry : true;
          const reason = err instanceof AuthError ? err.message : 'cannot check token';
          upgrade((ws) => ws.close(retry ? CLOSE_AUTH_DOWN : CLOSE_BAD_TOKEN, reason));
        },
      );
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

  const beat = setInterval(() => {
    for (const ws of wss.clients) {
      if (!ws.isAlive) {
        ws.terminate();
        continue;
      }
      ws.isAlive = false;
      ws.ping();
    }
  }, 30000);
  beat.unref();
  server.on('close', () => {
    clearInterval(beat);
    for (const ws of wss.clients) ws.terminate();
  });

  return server;
}

module.exports = { createRelay, CLOSE_BAD_TOKEN, CLOSE_AUTH_DOWN, CLOSE_TOO_MANY };

if (require.main === module) {
  const PORT = Number(process.env.PORT) || 43200;
  const HOST = process.env.HOST || '127.0.0.1';
  if (!process.env.WORKOS_CLIENT_ID) console.log('WORKOS_CLIENT_ID is not set: signed in PCs are refused');
  createRelay().listen(PORT, HOST, () => console.log(`horadric portal relay on http://${HOST}:${PORT}`));
}
