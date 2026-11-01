// Pairing by signing in, docs/PORTAL.md "Pairing v4". The login only
// finds the human's PCs; what lets this phone in is a yes on the PC after
// its human saw the same six digits as this phone shows, and a yes here
// too, since a relay playing the PC could otherwise be believed. The
// digits come from both sides' keys and nonces, and the phone commits to
// its half before it sees the PC's, so a relay in the middle cannot pick
// keys that make two codes match.
'use strict';
(function (root) {
  const PK = root.PhoneKey || require('./phonekey.js');
  const subtle = () => root.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const sha256 = async (bytes) => new Uint8Array(await subtle().digest('SHA-256', bytes));
  const derive = (label, parts) => sha256(PK.framed(label, parts));

  // What the phone sends first: its public key and nonce, hashed.
  const commitOf = (phonePub, phoneNonce) => derive('horadric ask commit v1', [phonePub, phoneNonce]);

  // The six digits both humans compare, as "587 941", and the 32 byte key
  // the PC seals `paired` with. `s` is the ECDH x coordinate.
  async function codeAndKey(s, phonePub, phoneNonce, pcPub, pcNonce) {
    const parts = [s, phonePub, phoneNonce, pcPub, pcNonce];
    const c = await derive('horadric ask code v1', parts);
    const n = new DataView(c.buffer, c.byteOffset, 4).getUint32(0, false) % 1000000;
    const digits = String(n).padStart(6, '0');
    return { code: `${digits.slice(0, 3)} ${digits.slice(3)}`, key: await derive('horadric ask key v1', parts) };
  }

  const random = (n) => root.crypto.getRandomValues(new Uint8Array(n));
  const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  const isPoint = (u) => u && u.length === 65 && u[0] === 4;
  function bytesOf(s, n) {
    if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s)) return null;
    try {
      const u = PK.fromB64url(s);
      return u.length === n ? u : null;
    } catch {
      return null;
    }
  }

  const api = { commitOf, codeAndKey };
  root.Ask = api;
  if (typeof module !== 'undefined') module.exports = api;
  if (typeof document === 'undefined') return;

  // The page's part. It leans on app.js for the paired PCs and the views.

  const VERIFIER = 'horadric.signin.verifier';
  const STATE = 'horadric.signin.state';
  const $ = (id) => document.getElementById(id);
  const relayUrl = () => location.origin.replace(/^http/, 'ws');

  // The ask in progress: its socket, the step it is at and what the
  // handshake has so far. Null when none is.
  let cur = null;

  async function begin() {
    const verifier = PK.toB64url(random(32));
    const st = PK.toB64url(random(16));
    try {
      sessionStorage.setItem(VERIFIER, verifier);
      sessionStorage.setItem(STATE, st);
    } catch {
      return fail('This browser keeps nothing for this page, so it cannot sign in. Scan the code on the PC instead.');
    }
    const challenge = PK.toB64url(await sha256(enc.encode(verifier)));
    location.assign(`/signin?${new URLSearchParams({ challenge, state: st })}`);
  }

  // WorkOS sent the browser back with ?code&state, or ?error&state. Both
  // leave the address bar at once, and the verifier leaves this tab: the
  // code is used once, right away, and nothing of the login stays.
  function takeReturn() {
    const q = new URLSearchParams(location.search);
    if (!q.has('code') && !q.has('error')) return null;
    history.replaceState(history.state, '', location.pathname + location.hash);
    let verifier = null;
    let made = null;
    try {
      verifier = sessionStorage.getItem(VERIFIER);
      made = sessionStorage.getItem(STATE);
      sessionStorage.removeItem(VERIFIER);
      sessionStorage.removeItem(STATE);
    } catch {}
    if (!made || q.get('state') !== made || !verifier) return null;
    if (q.has('error') || !q.get('code')) return { error: true };
    return { code: q.get('code'), verifier };
  }

  function start() {
    const back = takeReturn();
    if (!back) return;
    if (back.error) return fail('Signing in did not finish.');
    run(back.code, back.verifier);
  }

  function run(code, verifier) {
    end();
    const ws = new WebSocket(`${relayUrl()}/ask`);
    ws.binaryType = 'arraybuffer';
    cur = { ws, step: 'signin', machines: [], email: '', pick: null };
    const me = cur;
    render();
    ws.onopen = () => ws.send(JSON.stringify({ code, verifier }));
    ws.onmessage = (ev) => {
      if (cur !== me) return;
      if (typeof ev.data === 'string') return onText(me, ev.data);
      onFrame(me, new Uint8Array(ev.data)).catch(() => fail('The PC said something this page does not follow.'));
    };
    ws.onclose = () => {
      if (cur !== me || me.step === 'done') return;
      fail(me.step === 'signin' ? 'Signing in did not work. Try again.' : 'The relay ended the sign in. Try again.');
    };
  }

  function onText(a, text) {
    let m;
    try {
      m = JSON.parse(text);
    } catch {
      return;
    }
    if (!m || m.pong) return;
    if (typeof m.error === 'string') {
      if (a.step === 'signin') return fail(`Signing in did not work: ${m.error}.`);
      if (a.step === 'asking' || a.step === 'code' || a.step === 'yes') return fail(`${a.pick.name} cannot be asked now.`);
      return;
    }
    if (m.relay === 'offline' && a.pick) return fail(`${a.pick.name} went away before it said yes.`);
    if (Array.isArray(m.machines)) {
      a.machines = m.machines.filter((x) => x && /^[0-9a-f]{32}$/.test(x.id)).map((x) => ({ id: x.id, name: typeof x.name === 'string' && x.name ? x.name : 'PC' }));
      if (typeof m.email === 'string') a.email = m.email;
      if (a.step === 'signin' || a.step === 'machines') {
        a.step = 'machines';
        render();
      }
    }
  }

  const sendFrame = (a, obj) => a.ws.readyState === 1 && a.ws.send(enc.encode(JSON.stringify(obj)));

  async function pick(machine) {
    const a = cur;
    if (!a || a.step !== 'machines') return;
    const kp = await PK.current();
    if (cur !== a) return;
    if (!kp) return fail('This browser cannot keep a key pair, so it cannot pair by signing in. Scan the code on the PC instead.');
    Object.assign(a, { step: 'asking', pick: machine, kp, pub: PK.fromB64url(kp.pub), nonce: random(16) });
    render();
    a.ws.send(JSON.stringify({ ask: machine.id }));
    sendFrame(a, { t: 'ask', v: 1, name: deviceName(), commit: PK.toB64url(await commitOf(a.pub, a.nonce)) });
  }

  // Plain until the key; only `paired` comes sealed.
  async function onFrame(a, bytes) {
    if ((a.step === 'code' || a.step === 'yes') && a.key) {
      const sealed = await openSealed(a.key, bytes);
      if (sealed) return sealed.t === 'paired' ? gotPaired(a, sealed) : refuse(a, 'The PC said something this page does not follow.');
    }
    const m = JSON.parse(dec.decode(bytes));
    if (!m || typeof m !== 'object') throw new Error('not a message');
    if (m.t === 'refused') return fail(`${a.pick ? a.pick.name : 'The PC'} said no. This phone is not paired.`);
    if (m.t === 'asking' && a.step === 'asking') return asking(a, m);
    refuse(a, 'The PC answered out of turn, so this phone stopped.');
  }

  async function asking(a, m) {
    const pcPub = bytesOf(m.pub, 65);
    const pcNonce = bytesOf(m.nonce, 16);
    if (m.v !== 1 || !isPoint(pcPub) || !pcNonce || m.brother !== a.pick.id || same(pcPub, a.pub)) {
      return refuse(a, 'The PC answered in a way this page does not take.');
    }
    if (typeof m.name === 'string' && m.name) a.pick.name = m.name.slice(0, 64);
    sendFrame(a, { t: 'reveal', pub: a.kp.pub, nonce: PK.toB64url(a.nonce) });
    const theirs = await subtle().importKey('raw', pcPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const s = new Uint8Array(await subtle().deriveBits({ name: 'ECDH', public: theirs }, a.kp.privateKey, 256));
    const { code, key } = await codeAndKey(s, a.pub, a.nonce, pcPub, pcNonce);
    if (cur !== a) return;
    a.code = code;
    a.key = await subtle().importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
    a.step = 'code';
    render();
  }

  async function openSealed(key, bytes) {
    if (bytes.length < 28) return null;
    try {
      const plain = await subtle().decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, 12) }, key, bytes.subarray(12));
      return JSON.parse(dec.decode(plain));
    } catch {
      return null;
    }
  }

  // Held until this phone's human said yes as well.
  function gotPaired(a, m) {
    a.paired = m;
    if (a.step === 'yes') finish(a);
  }

  function yes() {
    const a = cur;
    if (!a || a.step !== 'code') return;
    a.step = 'yes';
    render();
    if (a.paired) finish(a);
  }

  function no() {
    const a = cur;
    if (!a) return;
    refuse(a, 'You said no. This phone is not paired.');
  }

  function refuse(a, text) {
    if (a.pick) sendFrame(a, { t: 'refused' });
    fail(text);
  }

  // Kept as a v3 pairing keeps a PC, so from here it is one like any other.
  async function finish(a) {
    const m = a.paired;
    if (typeof m.phone !== 'string' || !m.phone || m.brother !== a.pick.id || typeof m.bkey !== 'string') {
      return refuse(a, 'The PC answered in a way this page does not take.');
    }
    let k;
    try {
      k = PK.toB64url(await PK.derive(a.kp.privateKey, a.kp.pub, m.bkey, m.phone, m.brother));
    } catch {
      return refuse(a, 'The PC answered in a way this page does not take.');
    }
    if (cur !== a) return;
    a.step = 'done';
    a.ws.close();
    const id = m.brother;
    const pcs = loadPcs().filter((p) => p.id !== id);
    pcs.push({ id, r: relayUrl(), n: a.pick.name, k, phone: m.phone, v: 3, bkey: m.bkey, kp: a.kp.id, band: id, by: id });
    savePcs(pcs);
    try {
      localStorage.setItem('horadric.tab', id);
    } catch {}
    cur = null;
    refresh();
  }

  function fail(text) {
    end();
    cur = { ws: null, step: 'failed', text };
    render();
  }

  // Closes the ask, if one is open, without a word.
  function end() {
    if (cur && cur.ws) {
      cur.ws.onclose = null;
      cur.ws.close();
    }
    cur = null;
  }

  function cancel() {
    if (cur && cur.pick && cur.step !== 'failed') sendFrame(cur, { t: 'refused' });
    end();
    refresh();
  }

  function render() {
    const a = cur;
    if (!a) return;
    if (state.view !== 'asking') show('asking');
    renderTitle();
    const text = $('asktext');
    const list = $('askmachines');
    $('askwho').textContent = a.email ? `Signed in as ${a.email}` : '';
    $('askcode').hidden = a.step !== 'code' && a.step !== 'yes';
    $('askyesno').hidden = a.step !== 'code';
    $('askagain').hidden = a.step !== 'failed';
    $('asklook').hidden = a.step !== 'machines' || a.machines.length > 0;
    $('askcancel').textContent = a.step === 'failed' ? 'Back' : 'Cancel';
    list.replaceChildren();
    if (a.step === 'signin') text.textContent = 'Signing in.';
    else if (a.step === 'machines') {
      text.textContent = a.machines.length ? 'Which PC lets this phone in?' : 'No signed in PC runs a Horadric that can let phones in.';
      for (const m of a.machines) {
        const b = el('button', 'sess');
        b.type = 'button';
        b.append(el('span', 'what', m.name));
        b.onclick = () => pick(m);
        list.append(b);
      }
    } else if (a.step === 'asking') text.textContent = `Asking ${a.pick.name}.`;
    else if (a.step === 'code' || a.step === 'yes') {
      $('askcode').textContent = a.code;
      text.textContent =
        a.step === 'code'
          ? `${a.pick.name} asks you about this phone. Say yes there only if it shows the same code. Then say yes here too.`
          : `Waiting for ${a.pick.name} to say yes.`;
    } else text.textContent = a.text;
  }

  function look() {
    if (cur && cur.step === 'machines' && cur.ws.readyState === 1) cur.ws.send('{"list":1}');
  }

  Object.assign(api, { begin, start, cancel, yes, no, look, busy: () => !!cur });
})(typeof window !== 'undefined' ? window : globalThis);
