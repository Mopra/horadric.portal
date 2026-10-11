// The relay's pure parts, kept apart from the sockets so they can be tested.
'use strict';
const crypto = require('crypto');

const BROADCAST = 0xffffffff;
const MAX_FRAME = 1024 * 1024;
const MAX_PHONES = 8;

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

const isId = (s) => typeof s === 'string' && /^[0-9a-f]{32}$/.test(s);
const isSecret = (s) => typeof s === 'string' && s.length >= 16 && s.length <= 256;

module.exports = { BROADCAST, MAX_FRAME, MAX_PHONES, pcId, frame, unframe, nextChannel, isPing, isId, isSecret };
