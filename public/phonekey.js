// The phone's key pair and the key it shares with each brother, from
// docs/plan/one-portal.md. The key with a brother is derived, never sent,
// so no brother holds a key that opens the phone's link to another. The
// framing is joining::derive's on the PC: the label, then each part as a
// 4 byte big endian length and its bytes, through SHA-256.
'use strict';
(function (root) {
  const LABEL = 'horadric phone key v1';
  const enc = new TextEncoder();
  const subtle = () => root.crypto.subtle;

  function fromB64url(s) {
    const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
    return Uint8Array.from(b, (c) => c.charCodeAt(0));
  }
  function toB64url(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function framed(label, parts) {
    const all = [enc.encode(label)];
    for (const p of parts) {
      const len = new Uint8Array(4);
      new DataView(len.buffer).setUint32(0, p.length, false);
      all.push(len, p);
    }
    const out = new Uint8Array(all.reduce((t, a) => t + a.length, 0));
    let at = 0;
    for (const a of all) {
      out.set(a, at);
      at += a.length;
    }
    return out;
  }

  // The 32 byte key this phone shares with one brother. `mine` and
  // `theirs` are the 65 byte uncompressed points as b64url; the ids go in
  // as the strings travel, the phone's b64url and the relay's hex.
  async function derive(privateKey, mine, theirs, phoneId, relayId) {
    const pub = await subtle().importKey('raw', fromB64url(theirs), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const shared = new Uint8Array(await subtle().deriveBits({ name: 'ECDH', public: pub }, privateKey, 256));
    const data = framed(LABEL, [shared, fromB64url(mine), fromB64url(theirs), enc.encode(phoneId), enc.encode(relayId)]);
    return new Uint8Array(await subtle().digest('SHA-256', data));
  }

  // The key pairs live in IndexedDB, where a key that cannot be exported
  // can still be kept. One is current, for the next pairing; a forget
  // retires it, since pairing again after a forget must be a new key, and
  // the old one stays only while a brotherhood paired with it remains.
  const DB = 'horadric-phone';
  const STORE = 'pairs';
  const CURRENT = 'horadric.kp';

  function db() {
    return new Promise((resolve, reject) => {
      const req = root.indexedDB.open(DB, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: 'id' });
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  async function tx(mode, f) {
    const d = await db();
    try {
      return await new Promise((resolve, reject) => {
        const t = d.transaction(STORE, mode);
        const req = f(t.objectStore(STORE));
        t.oncomplete = () => resolve(req && req.result);
        t.onerror = () => reject(t.error);
        t.onabort = () => reject(t.error);
      });
    } finally {
      d.close();
    }
  }

  // {id, privateKey, pub} or null when this browser cannot keep one, so
  // the caller pairs as v2 instead.
  async function pairOf(id) {
    try {
      const p = id && (await tx('readonly', (s) => s.get(id)));
      return p && p.privateKey && p.pub ? p : null;
    } catch {
      return null;
    }
  }

  async function current() {
    try {
      const had = await pairOf(root.localStorage.getItem(CURRENT));
      if (had) return had;
      const kp = await subtle().generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
      const pub = toB64url(new Uint8Array(await subtle().exportKey('raw', kp.publicKey)));
      const p = { id: pub.slice(0, 16), privateKey: kp.privateKey, pub };
      await tx('readwrite', (s) => s.put(p));
      // A browser that keeps nothing would hand out a pair it loses.
      if (!(await pairOf(p.id))) return null;
      root.localStorage.setItem(CURRENT, p.id);
      return p;
    } catch {
      return null;
    }
  }

  async function retire(id, stillUsed) {
    try {
      if (root.localStorage.getItem(CURRENT) === id) root.localStorage.removeItem(CURRENT);
      if (!stillUsed) await tx('readwrite', (s) => s.delete(id));
    } catch {}
  }

  const api = { derive, framed, fromB64url, toB64url, current, pairOf, retire, LABEL };
  root.PhoneKey = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
