// The relay's pure parts, kept apart from the sockets so they can be tested.
'use strict';
const crypto = require('crypto');

const BROADCAST = 0xffffffff;
const MAX_FRAME = 1024 * 1024;
const MAX_PHONES = 8;
// Brother channels a PC may hold open at once, so one PC cannot pile them
// up on another.
const MAX_LINKS = 16;
const MAX_NAME = 64;
// Machines one user may have connected at once, and PCs one address may
// hold open. Each signed in PC is told of every other on each connect, so
// the first keeps that from growing with the square of a user's secrets;
// the second keeps one host from holding the relay's sockets.
const MAX_PCS_PER_USER = 16;
const MAX_PCS_PER_IP = 32;
// Ids of one user whose first-seen time the relay remembers, so the cap
// above favours the machines it has known longest. Past this the youngest
// one not connected is forgotten, never the oldest: a burst of made up
// secrets only pushes out each other and machines newer than them.
const MAX_SEEN_PER_USER = 64;
// Until this day /pc also takes the secret and token in its query string,
// as Horadric 0.32 and older send them; 0.33 sends them in headers, where
// a proxy's access log does not keep them. Every install is offered each
// release, so two months covers any that is not left switched off.
const QUERY_UNTIL = Date.parse('2027-01-01T00:00:00Z');

// A PC's id is derived from its secret, so the relay needs no storage to
// know which PC is which, and nobody without the secret can pose as it.
function pcId(secret) {
  return crypto.createHash('sha256').update(secret, 'utf8').digest('hex').slice(0, 32);
}

function frame(ch, payload) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const out = Buffer.allocUnsafe(4 + body.length);
  out.writeUInt32BE(ch >>> 0, 0);
  body.copy(out, 4);
  return out;
}

function unframe(buf) {
  if (buf.length < 4) return null;
  return { ch: buf.readUInt32BE(0), payload: buf.subarray(4) };
}

// Channels are never 0 and never the broadcast channel, and never one a
// phone of this PC already holds.
function nextChannel(last, taken) {
  let ch = last;
  for (;;) {
    ch = (ch + 1) >>> 0;
    if (ch === 0 || ch === BROADCAST) continue;
    if (!taken.has(ch)) return ch;
  }
}

// A liveness ping from either end, answered by the relay and never passed on.
function isPing(data) {
  if (!data || data.length > 64) return false;
  try {
    const m = JSON.parse(data.toString());
    return !!m && m.ping === 1;
  } catch {
    return false;
  }
}

// A PC's name as its brothers see it: what it sent, without control
// characters, cut to a length a tile can show.
function cleanName(s) {
  const t = typeof s === 'string' ? s.replace(/[\x00-\x1f\x7f]/g, '').trim() : '';
  return [...t].slice(0, MAX_NAME).join('') || 'PC';
}

// What one PC is told about the rest of its user's PCs: everyone but itself,
// in a stable order so an unchanged set reads the same.
function brothersOf(pcs, self) {
  return pcs
    .filter((p) => p.id !== self)
    .map((p) => ({ id: p.id, name: p.name }))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

// Text control from a PC: a ping, a join request or a link closed. Anything
// else is dropped, as before.
function parseControl(data) {
  if (!data || data.length > 1024) return null;
  let m;
  try {
    m = JSON.parse(data.toString());
  } catch {
    return null;
  }
  if (!m || typeof m !== 'object') return null;
  if (m.ping === 1) return { ping: true };
  if (m.join && typeof m.join === 'object' && isId(m.join.to)) return { join: m.join.to };
  if (Number.isInteger(m.close) && m.close > 0 && m.close < BROADCAST) return { close: m.close };
  return null;
}

// What proves a PC on /pc: its secret, and when signed in its WorkOS
// access token. From headers (X-Horadric-Secret, Authorization: Bearer),
// or, before QUERY_UNTIL and only when no secret header came, from the
// query string. Gives { secret, token, query } with null for what is not
// there; query says the old way was used.
function credentials(headers, searchParams, now = Date.now()) {
  const secret = headers['x-horadric-secret'];
  if (typeof secret === 'string') {
    const auth = headers.authorization;
    const bearer = typeof auth === 'string' ? /^Bearer ([^\s]+)$/.exec(auth) : null;
    return { secret, token: bearer ? bearer[1] : null, query: false };
  }
  if (now < QUERY_UNTIL) {
    return { secret: searchParams.get('secret'), token: searchParams.get('token'), query: true };
  }
  return { secret: null, token: null, query: false };
}

// The address a connection comes from: behind our proxy (trustProxy) the
// one it says in X-Real-Ip, else the socket's own.
function clientIp(headers, remote, trustProxy) {
  if (trustProxy) {
    const real = headers['x-real-ip'];
    if (typeof real === 'string' && real) return real.trim();
    const fwd = headers['x-forwarded-for'];
    if (typeof fwd === 'string' && fwd) return fwd.split(',').pop().trim();
  }
  return remote || '';
}

// When the relay first saw id among one user's PCs, recorded now (at t) if
// it never did. seen maps id -> { at, n }: n is the order of recording, so
// two ids seen in the same millisecond still have an older and a younger.
// connected holds ids that must not be forgotten to make room.
function firstSeen(seen, id, t, connected) {
  const known = seen.get(id);
  if (known) return known;
  if (seen.size >= MAX_SEEN_PER_USER) {
    let youngest = null;
    for (const [k, v] of seen) {
      if (!connected.has(k) && (!youngest || older(youngest[1], v))) youngest = [k, v];
    }
    if (youngest) seen.delete(youngest[0]);
  }
  let n = 0;
  for (const v of seen.values()) n = Math.max(n, v.n + 1);
  const entry = { at: t, n };
  seen.set(id, entry);
  return entry;
}

const older = (a, b) => a.at < b.at || (a.at === b.at && a.n < b.n);

// Whether id may join a user whose connected ids are connected, and which
// of them gives way. At the cap the oldest first seen win: id takes the
// place of the youngest connected one when it was seen before it, else it
// is refused. Gives { ok, evict } with evict an id or null.
function admit(seen, connected, id) {
  if (connected.has(id) || connected.size < MAX_PCS_PER_USER) return { ok: true, evict: null };
  const mine = seen.get(id);
  let youngest = null;
  for (const k of connected) {
    const v = seen.get(k);
    // An id with no record is younger than any with one.
    if (!v) return mine ? { ok: true, evict: k } : { ok: false, evict: null };
    if (!youngest || older(youngest[1], v)) youngest = [k, v];
  }
  if (mine && older(mine, youngest[1])) return { ok: true, evict: youngest[0] };
  return { ok: false, evict: null };
}

const isId = (s) => typeof s === 'string' && /^[0-9a-f]{32}$/.test(s);
const isSecret = (s) => typeof s === 'string' && s.length >= 16 && s.length <= 256;

module.exports = {
  BROADCAST,
  MAX_FRAME,
  MAX_PHONES,
  MAX_LINKS,
  MAX_NAME,
  MAX_PCS_PER_USER,
  MAX_PCS_PER_IP,
  MAX_SEEN_PER_USER,
  firstSeen,
  admit,
  QUERY_UNTIL,
  credentials,
  clientIp,
  pcId,
  frame,
  unframe,
  nextChannel,
  isPing,
  cleanName,
  brothersOf,
  parseControl,
  isId,
  isSecret,
};
