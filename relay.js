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

const isId = (s) => typeof s === 'string' && /^[0-9a-f]{32}$/.test(s);
const isSecret = (s) => typeof s === 'string' && s.length >= 16 && s.length <= 256;

module.exports = {
  BROADCAST,
  MAX_FRAME,
  MAX_PHONES,
  MAX_LINKS,
  MAX_NAME,
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
