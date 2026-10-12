// The Town Portal page: the phone's side of docs/PORTAL.md. It talks to
// the PC through the relay, and everything it says is encrypted with this
// phone's own key, which lives only on the PC and in this browser. A PC
// on Horadric 0.21 shares one key with every phone instead.
'use strict';

const VERSION = 2;
// The PC versions this page speaks: 1 is Horadric 0.21.
const SPEAKS = [1, 2];
const $ = (id) => document.getElementById(id);

// Pairing

function loadPcs() {
  try {
    return JSON.parse(localStorage.getItem('horadric.pcs') || '[]');
  } catch {
    return [];
  }
}
function savePcs(list) {
  localStorage.setItem('horadric.pcs', JSON.stringify(list));
}

// A pairing link carries everything in its fragment, which no server ever
// sees. Returns whether `fragment` held a pairing. From Horadric 0.22 the
// PC's link holds a one-time code (p, good until x) that the page trades
// for a key of this phone's own (k); a link from 0.21 holds the PC's one
// key as k.
function pairWith(fragment) {
  const p = new URLSearchParams(fragment.replace(/^[^#]*#/, ''));
  const id = p.get('id');
  const k = p.get('k');
  const pk = p.get('p');
  const r = p.get('r');
  if (!id || !(k || pk) || !r || !/^[0-9a-f]{32}$/.test(id)) return false;
  const before = loadPcs().find((pc) => pc.id === id);
  const pcs = loadPcs().filter((pc) => pc.id !== id);
  const pc = { id, r: r.replace(/\/+$/, ''), n: p.get('n') || 'PC' };
  if (k) pc.k = k;
  else {
    pc.pk = pk;
    pc.x = Number(p.get('x')) || 0;
    // An old link opened again must not cost the key this phone has: it
    // stays until the new code pays off, and is used if the code fails.
    if (before && before.k) {
      pc.k = before.k;
      pc.phone = before.phone;
    }
  }
  pcs.push(pc);
  savePcs(pcs);
  localStorage.setItem('horadric.current', id);
  return true;
}

// Take the link from the address bar, then wipe it from there.
function takeFragment() {
  if (location.hash.length < 2) return;
  pairWith(location.hash);
  history.replaceState(null, '', location.pathname);
}

// A link that carries this pairing somewhere this browser's storage does
// not reach: this phone's key once it has one, else the code not yet used.
function linkFor(pc) {
  const q = pc.k ? { r: pc.r, id: pc.id, k: pc.k, n: pc.n } : { r: pc.r, id: pc.id, p: pc.pk, x: pc.x, n: pc.n };
  return `${location.origin}/#${new URLSearchParams(q)}`;
}

function savePc(pc) {
  savePcs(loadPcs().map((p) => (p.id === pc.id ? pc : p)));
}

// What the PC lists this phone as, in `horadric portal phones`.
function deviceName() {
  const ua = navigator.userAgent;
  const device =
    [
      [/iPhone/, 'iPhone'],
      [/iPad/, 'iPad'],
      [/Android/, 'Android'],
      [/Mac OS X/, 'Mac'],
      [/Windows/, 'Windows'],
    ].find(([re]) => re.test(ua))?.[1] || 'Phone';
  const browser =
    [
      [/EdgA?\//, 'Edge'],
      [/Firefox|FxiOS/, 'Firefox'],
      [/CriOS|Chrome/, 'Chrome'],
      [/Safari/, 'Safari'],
    ].find(([re]) => re.test(ua))?.[1] || '';
  return browser ? `${device}, ${browser}` : device;
}

// Encryption: AES-256-GCM, 12 byte nonce first.

function b64url(s) {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}
async function importKey(k) {
  return crypto.subtle.importKey('raw', b64url(k), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function seal(key, obj) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const body = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, new TextEncoder().encode(JSON.stringify(obj))),
  );
  const out = new Uint8Array(12 + body.length);
  out.set(nonce);
  out.set(body, 12);
  return out;
}
async function open(key, buf) {
  const all = new Uint8Array(buf);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: all.subarray(0, 12) }, key, all.subarray(12));
  return JSON.parse(new TextDecoder().decode(plain));
}

// State

const state = {
  pc: null,
  key: null,
  ws: null,
  link: 'connecting', // connecting | offline (relay down) | pcoff | online
  pcName: '',
  sessions: [],
  projects: [],
  vapid: null,
  s: null, // this connection's id from the PC's hello, sent back on every message
  n: 0, // the count on the last message sent
  answered: null, // the timer that gives up on a PC that never answers hello
  warning: null, // a note that stays: another phone took this phone's pairing code
  starting: null, // { project, at }
  paused: false, // the watched session answered watch with paused
  heard: 0, // when the relay last said anything, ms
  watching: null,
  screen: null,
  backoff: 1000,
  timer: null,
  tooOld: false,
  view: 'list', // unpaired | list | projects | session
  folders: null, // the PC's folders answer, null until it comes
  listed: false, // a sessions answer came from this PC, so the list is real
  sent: new Map(), // session id -> { label, since }: an inbox answer sent, until the phase moves
};

function setLink(link) {
  state.link = link;
  const lamp = $('status').querySelector('.lamp');
  const label = $('status').querySelector('span');
  const words = { connecting: 'Connecting', offline: 'No relay', pcoff: 'PC offline', online: 'Online' };
  lamp.className = 'lamp ' + (link === 'online' ? 'online' : link === 'connecting' ? 'connecting' : 'offline');
  label.textContent = words[link];
  renderNote();
  renderList();
}

// Connection

async function connect() {
  clearTimeout(state.timer);
  if (state.ws) {
    state.ws.onclose = null;
    state.ws.close();
    state.ws = null;
  }
  const pc = state.pc;
  if (!pc) return;
  setLink('connecting');
  state.s = null;
  try {
    state.key = await importKey(pc.pk || pc.k);
  } catch {
    $('note').hidden = false;
    $('note').textContent = 'This pairing link is broken. Pair again with horadric portal.';
    return;
  }
  const ws = new WebSocket(`${pc.r}/phone?id=${pc.id}`);
  ws.binaryType = 'arraybuffer';
  state.ws = ws;
  ws.onopen = () => {
    state.backoff = 1000;
    state.heard = Date.now();
  };
  ws.onmessage = async (ev) => {
    state.heard = Date.now();
    if (typeof ev.data === 'string') {
      let msg;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      if (msg.pong) return;
      if (msg.relay === 'online') {
        setLink('online');
        if (state.pc.pk) pairNow();
        else greet();
      } else if (msg.relay === 'offline') {
        setLink('pcoff');
      }
      return;
    }
    let msg;
    try {
      msg = await open(state.key, ev.data);
    } catch {
      return;
    }
    onMessage(msg);
  };
  ws.onclose = () => {
    if (state.ws !== ws) return;
    state.ws = null;
    setLink('offline');
    state.timer = setTimeout(connect, state.backoff);
    state.backoff = Math.min(state.backoff * 2, 15000);
  };
}

// A socket can look open long after the network under it died, most of
// all on a phone that slept. A ping every 25 seconds, and a reconnect
// after 70 seconds of silence, find that out.
const PING_MS = 25000;
const SILENCE_MS = 70000;
setInterval(() => {
  const ws = state.ws;
  if (!ws || ws.readyState !== 1) return;
  if (Date.now() - state.heard > SILENCE_MS) return connect();
  ws.send('{"ping":1}');
}, PING_MS);

// Back in front, or back on a network: a socket from before is likely
// dead, so check at once instead of waiting for the next ping.
function wake() {
  if (!state.pc) return;
  const ws = state.ws;
  if (!ws || ws.readyState !== 1 || Date.now() - state.heard > PING_MS) connect();
  else ws.send('{"ping":1}');
}

// After hello every message carries the connection's s and a count, so
// the relay cannot play an old one back to the PC.
async function send(obj) {
  const ws = state.ws;
  if (!ws || ws.readyState !== 1 || !state.key) return false;
  if (state.s && obj.t !== 'hello' && obj.t !== 'pair') obj = { ...obj, s: state.s, n: ++state.n };
  ws.send(await seal(state.key, obj));
  return true;
}

function greet() {
  state.s = null;
  send({ t: 'hello', v: VERSION });
  clearTimeout(state.answered);
  state.answered = setTimeout(
    () => say('The PC does not answer this phone. It may have forgotten it: run horadric portal on the PC and pair again.'),
    10000,
  );
}

// Trades the one-time code for a key of this phone's own.
function pairNow() {
  if (state.pc.x && Date.now() / 1000 > state.pc.x) {
    codeFailed('This pairing code ran out. Run horadric portal on the PC for a new one.');
    return;
  }
  send({ t: 'pair', v: VERSION, name: deviceName() });
}

// The code was used or ran out: forget it, and go on with the key this
// phone had before, if any.
function codeFailed(text, used) {
  const pc = state.pc;
  if (used) state.warning = text;
  delete pc.pk;
  delete pc.x;
  savePc(pc);
  if (pc.k) connect();
  else if (!used) say(text);
  renderNote();
}

async function paired(msg) {
  const pc = state.pc;
  try {
    state.key = await importKey(msg.key);
  } catch {
    return;
  }
  pc.k = msg.key;
  pc.phone = msg.phone;
  delete pc.pk;
  delete pc.x;
  savePc(pc);
  greet();
}

// The PC forgot this phone, so its key is no good any more.
function unpaired() {
  const pc = state.pc;
  delete pc.k;
  savePc(pc);
  if (state.ws) {
    state.ws.onclose = null;
    state.ws.close();
    state.ws = null;
  }
  setLink('offline');
  say(`${pc.n} forgot this phone. To use it again, run horadric portal on the PC and pair again.`);
}

function onMessage(msg) {
  switch (msg.t) {
    case 'paired':
      paired(msg);
      break;
    case 'unpaired':
      unpaired();
      break;
    case 'hello':
      clearTimeout(state.answered);
      state.s = typeof msg.s === 'string' ? msg.s : null;
      state.n = 0;
      if (state.watching) send({ t: 'watch', id: state.watching });
      state.tooOld = !SPEAKS.includes(msg.v);
      state.pcName = msg.pc || state.pc.n;
      if (msg.pc && msg.pc !== state.pc.n) {
        state.pc.n = msg.pc;
        savePc(state.pc);
        renderPcs();
      }
      state.vapid = typeof msg.vapid === 'string' ? msg.vapid : null;
      renderNote();
      renderTitle();
      renderPush();
      resendPush();
      if (state.view === 'projects') askFolders();
      break;
    case 'projects':
      state.projects = Array.isArray(msg.list) ? msg.list : [];
      renderList();
      break;
    case 'started':
      state.starting = null;
      renderList();
      renderFolders();
      if (msg.id) watch(msg.id);
      break;
    case 'folders':
      state.folders = Array.isArray(msg.roots) ? msg.roots : [];
      renderFolders();
      break;
    case 'sessions':
      state.listed = true;
      state.sessions = Array.isArray(msg.list) ? msg.list : [];
      pruneSent();
      renderList();
      renderTitle();
      break;
    case 'screen':
      if (msg.id === state.watching) {
        state.paused = false;
        state.screen = msg;
        renderScreen();
      }
      break;
    case 'attached':
      attached(msg);
      break;
    case 'error':
      if (state.attaching) attachDone();
      if (msg.code === 'used' || msg.code === 'expired') {
        codeFailed(msg.text, msg.code === 'used');
        break;
      }
      if (state.watching && /paused/i.test(msg.text || '')) {
        state.paused = true;
        renderScreen();
        break;
      }
      if (state.starting) {
        state.starting = null;
        renderList();
        renderFolders();
      }
      say(msg.text || 'The PC reported an error.');
      break;
  }
}

// Rendering

const PHASES = ['working', 'waiting', 'idle', 'ended'];
const phaseOf = (s) => (PHASES.includes(s.phase) ? s.phase : 'idle');

function renderNote() {
  const note = $('note');
  let text = '';
  if (state.warning) text = state.warning;
  else if (state.tooOld) text = 'This PC runs a Horadric this page does not speak. Update Horadric on the PC.';
  else if (state.link === 'pcoff') text = `${state.pc ? state.pc.n : 'The PC'} is not connected. Is Horadric running, with horadric portal on?`;
  else if (state.link === 'offline') text = 'Cannot reach the relay. Retrying.';
  note.hidden = !text;
  note.textContent = text;
}

// Sessions waiting on the human, longest wait first, and the count in the
// tab title and the page's title bar.
const waitingList = () =>
  state.sessions
    .filter((s) => phaseOf(s) === 'waiting' && !s.paused)
    .sort((a, b) => (askSince(a) || Infinity) - (askSince(b) || Infinity));

// `since` as seconds or milliseconds since the epoch, whichever the PC sent.
function askSince(s) {
  const t = Number(s.ask && s.ask.since);
  if (!t) return 0;
  return t < 1e12 ? t * 1000 : t;
}

function renderTitle() {
  const n = waitingList().length;
  document.title = n ? `(${n}) Horadric` : 'Horadric';
  if (state.watching) {
    const s = state.sessions.find((x) => x.id === state.watching);
    $('title').textContent = s ? s.name : 'Session';
  } else if (state.view === 'projects') {
    $('title').textContent = 'Open project';
  } else {
    $('title').textContent = (state.pc ? state.pc.n : 'Horadric') + (n ? ` (${n} waiting)` : '');
  }
}

function renderPcs() {
  const pcs = loadPcs();
  const sel = $('pcs');
  sel.hidden = pcs.length < 2;
  sel.replaceChildren(
    ...pcs.map((p) => {
      const o = document.createElement('option');
      o.value = p.id;
      o.textContent = p.n;
      o.selected = state.pc && p.id === state.pc.id;
      return o;
    }),
  );
}

const baseName = (p) => String(p).split(/[\\/]/).filter(Boolean).pop() || String(p);

// Every project the PC knows, each with its sessions, so a project with
// none can still get one. A session names its project by name or path.
function grouped() {
  const groups = new Map();
  const keyOf = new Map();
  for (const p of state.projects) {
    if (!p || !p.path) continue;
    groups.set(p.path, { path: p.path, name: p.name || baseName(p.path), list: [] });
    keyOf.set(p.path, p.path);
    if (p.name && !keyOf.has(p.name)) keyOf.set(p.name, p.path);
  }
  for (const s of state.sessions) {
    const raw = s.project || 'Other';
    const key = keyOf.get(raw) || raw;
    if (!groups.has(key)) groups.set(key, { path: null, name: baseName(raw), list: [] });
    groups.get(key).list.push(s);
  }
  const rank = (s) => (s.paused ? 2.5 : { waiting: 0, working: 1, idle: 2, ended: 3 }[phaseOf(s)]);
  const best = (g) => (g.list.length ? Math.min(...g.list.map(rank)) : 9);
  const order = state.projects.map((p) => p && p.path);
  for (const g of groups.values()) g.list.sort((a, b) => rank(a) - rank(b) || String(a.name).localeCompare(b.name));
  return [...groups.values()].sort((a, b) => {
    const r = best(a) - best(b);
    if (r) return r;
    const ia = order.indexOf(a.path);
    const ib = order.indexOf(b.path);
    if (ia >= 0 && ib >= 0) return ia - ib;
    return a.name.localeCompare(b.name);
  });
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

// Grey rows in the shape of the list, while the first answer is on its way,
// so connecting looks like loading and not like a PC with nothing on it.
function skeleton() {
  const out = [];
  for (const rows of [2, 1]) {
    const sec = el('section', 'group skeleton');
    sec.setAttribute('aria-hidden', 'true');
    sec.append(el('div', 'bone head'));
    for (let i = 0; i < rows; i++) {
      const row = el('div', 'sess');
      const what = el('div', 'what');
      what.append(el('div', 'bone name'), el('div', 'bone line'));
      row.append(el('i', 'lamp'), what);
      sec.append(row);
    }
    out.push(sec);
  }
  return out;
}

// "5s", "3m", "2h": how long a card has waited.
function ago(since) {
  const sec = Math.max(0, Math.floor((Date.now() - since) / 1000));
  if (sec < 60) return sec + 's';
  if (sec < 3600) return Math.floor(sec / 60) + 'm';
  return Math.floor(sec / 3600) + 'h';
}

// An answer is "Sent" until the session leaves that wait: its phase moves, or
// a new ask replaces the one answered.
function pruneSent() {
  for (const [id, sent] of state.sent) {
    const s = state.sessions.find((x) => x.id === id);
    if (!s || phaseOf(s) !== 'waiting' || askSince(s) !== sent.since) state.sent.delete(id);
  }
}

function answer(s, opt) {
  haptic('answer');
  state.sent.set(s.id, { label: opt.label, since: askSince(s) });
  send({ t: 'input', id: s.id, data: opt.keys });
  renderInbox();
}

function card(s) {
  const ask = s.ask && typeof s.ask === 'object' ? s.ask : null;
  const c = el('article', 'card');
  const top = el('div', 'ctop');
  top.append(el('span', 'cproj', s.project ? baseName(s.project) : s.name || s.id));
  const since = askSince(s);
  if (since) top.append(el('span', 'cage', ago(since)));
  c.append(top);
  const what = ask ? [ask.tool, ask.detail].filter(Boolean).join(': ') : '';
  c.append(el('div', 'cwhat', what || s.line || 'Waiting for you'));
  const row = el('div', 'cbtns');
  const sent = state.sent.get(s.id);
  const options = ask && Array.isArray(ask.options) ? ask.options.filter((o) => o && o.label && typeof o.keys === 'string') : [];
  if (sent) {
    row.append(el('span', 'csent', `Sent: ${sent.label}`));
  } else {
    for (const o of options) {
      const b = el('button', 'pill', o.label);
      b.onclick = () => answer(s, o);
      row.append(b);
    }
  }
  const open = el('button', 'link', 'Open');
  open.onclick = () => watch(s.id);
  row.append(open);
  c.append(row);
  return c;
}

function renderInbox() {
  const list = waitingList();
  $('inbox').hidden = !list.length;
  $('inbox').replaceChildren(...list.map(card));
  renderTitle();
}

// The ages move on their own.
setInterval(() => {
  if (state.view === 'list' && !document.hidden) renderInbox();
}, 15000);

function renderList() {
  renderInbox();
  if (!state.listed && state.pc && (state.link === 'connecting' || state.link === 'online')) {
    $('groups').replaceChildren(...skeleton());
    $('empty').hidden = true;
    return;
  }
  const out = [];
  for (const g of grouped()) {
    const sec = el('section', 'group');
    const head = el('div', 'ghead');
    head.append(el('h2', null, g.name));
    if (g.path) {
      const plus = el('button', 'plus', '+');
      plus.setAttribute('aria-label', `New session in ${g.name}`);
      plus.disabled = !!state.starting || state.link !== 'online';
      plus.onclick = () => startIn(g.path);
      head.append(plus);
    }
    sec.append(head);
    const startingHere = state.starting && state.starting.project === g.path;
    if (startingHere) {
      const row = el('div', 'sess starting');
      row.append(el('i', 'spinner'), el('div', 'what', 'Starting a session...'));
      sec.append(row);
    }
    for (const s of g.list) {
      const ph = phaseOf(s);
      const b = el('div', 'sess ' + ph + (s.paused ? ' paused' : ''));
      b.setAttribute('role', 'button');
      b.tabIndex = 0;
      const what = el('div', 'what');
      what.append(el('div', 'name', s.name || s.id), el('div', 'line', s.paused ? 'paused' : s.line || ph));
      b.append(el('i', 'lamp ' + (s.paused ? 'paused' : ph)), what);
      if (s.paused) {
        const r = el('button', 'resume', 'Resume');
        r.onclick = (ev) => {
          ev.stopPropagation();
          resume(s.id);
        };
        b.append(r);
      }
      b.onclick = () => watch(s.id);
      sec.append(b);
    }
    if (!g.list.length && !startingHere) sec.append(el('div', 'dim none', 'No sessions'));
    out.push(sec);
  }
  $('groups').replaceChildren(...out);
  $('empty').hidden = out.length > 0 || state.link !== 'online';
}

// Starting and resuming

// A note on whichever view is up, so an error is seen where it happened.
function say(text) {
  const note = state.view === 'projects' ? $('pnote') : $('note');
  note.hidden = false;
  note.textContent = text;
}

// `ask` is the message that starts it: start in a known folder, or
// create a new one. `path` only marks where the spinner goes.
function startIn(path, ask = { t: 'start', project: path }) {
  const at = Date.now();
  state.starting = { project: path, at };
  $('pnote').hidden = true;
  renderList();
  renderFolders();
  send(ask);
  // A PC that never answers must not leave the spinner forever.
  setTimeout(() => {
    if (!state.starting || state.starting.at !== at) return;
    state.starting = null;
    renderList();
    renderFolders();
    say('The PC did not start the session. Is its Horadric up to date?');
  }, 30000);
}

// Opening any project: the folders the PC's projects live in, so one
// that was not open on the PC can still be worked on.

function askFolders() {
  const at = Date.now();
  askFolders.at = at;
  send({ t: 'folders' });
  setTimeout(() => {
    if (askFolders.at !== at || state.folders || state.view !== 'projects') return;
    say('The PC did not list its projects. Opening projects needs Horadric 0.22 or later on the PC.');
  }, 8000);
}

function openProjects() {
  $('pnote').hidden = true;
  show('projects');
  history.pushState({ projects: true }, '');
  renderTitle();
  renderFolders();
  askFolders();
}

const sepOf = (root) => (String(root).includes('\\') ? '\\' : '/');

// The spec's rule for a new folder's name, so a typo is caught before the
// PC has to refuse it.
function nameProblem(name, root) {
  if (!name) return 'Give it a name.';
  if (name.length > 64) return 'At most 64 characters.';
  if (!/^[A-Za-z0-9 ._-]+$/.test(name)) return 'Letters, digits, space, dot, dash and underscore only.';
  if (name.startsWith('.')) return 'It cannot start with a dot.';
  const r = (state.folders || []).find((x) => x.path === root);
  const lower = name.toLowerCase();
  if (r && (r.list || []).some((f) => String(f.name).toLowerCase() === lower)) return 'That folder exists. Open it from the list instead.';
  return '';
}

function renderFolders() {
  const roots = state.folders || [];
  const sel = $('root');
  const keep = sel.value;
  sel.replaceChildren(
    ...roots.map((r) => {
      const o = document.createElement('option');
      o.value = r.path;
      o.textContent = r.name || baseName(r.path);
      return o;
    }),
  );
  if (roots.some((r) => r.path === keep)) sel.value = keep;
  $('newproject').disabled = !roots.length;

  if (!state.folders) {
    const wait = el('div', 'dim center', state.link === 'online' ? 'Asking the PC for its projects...' : 'Waiting for the PC...');
    $('folders').replaceChildren(wait);
    return;
  }
  const q = $('search').value.trim().toLowerCase();
  const busy = !!state.starting || state.link !== 'online';
  const out = [];
  for (const r of roots) {
    const list = (r.list || []).filter((f) => !q || String(f.name).toLowerCase().includes(q));
    const creating =
      state.starting && state.starting.root === r.path && !list.some((f) => f.path === state.starting.project);
    if (q && !list.length && !creating) continue;
    const sec = el('section', 'group root');
    sec.append(el('h2', null, r.name || baseName(r.path)), el('div', 'rpath', r.path));
    if (creating) {
      const row = el('div', 'sess starting');
      row.append(el('i', 'spinner'), el('div', 'what', 'Making the project...'));
      sec.append(row);
    }
    for (const f of list) {
      const here = state.starting && state.starting.project === f.path;
      const row = el('div', 'sess folder' + (here ? ' starting' : ''));
      row.setAttribute('role', 'button');
      row.tabIndex = 0;
      const what = el('div', 'what');
      what.append(el('div', 'name', f.name || baseName(f.path)));
      if (here) what.append(el('div', 'line', 'Starting a session...'));
      row.append(here ? el('i', 'spinner') : el('i', 'lamp'), what);
      if (f.git) row.append(el('span', 'git', 'git'));
      row.onclick = () => {
        if (!busy) startIn(f.path);
      };
      sec.append(row);
    }
    if (!list.length && !creating) sec.append(el('div', 'dim none', 'No folders'));
    out.push(sec);
  }
  if (!out.length) out.push(el('div', 'dim center', q ? 'No project matches.' : 'The PC knows no project folders yet.'));
  $('folders').replaceChildren(...out);
}

function resume(id) {
  send({ t: 'resume', id });
  watch(id);
}

// Push

function pushSupport() {
  if (!('serviceWorker' in navigator)) return 'This browser cannot notify.';
  if (!('PushManager' in window) || !('Notification' in window)) {
    const ios = /iP(hone|ad|od)/.test(navigator.userAgent);
    const installed = matchMedia('(display-mode: standalone)').matches || navigator.standalone;
    if (ios && !installed) return 'For notifications, tap Share, then Add to Home Screen, and open Horadric from there.';
    return 'This browser cannot notify.';
  }
  return null;
}

function renderPush() {
  const b = $('notify');
  const hint = $('notifyhint');
  const why = state.vapid ? pushSupport() : null;
  let text = why;
  let button = !!state.vapid && !why;
  if (button && Notification.permission === 'denied') {
    button = false;
    text = 'Notifications are blocked for this page in the browser settings.';
  } else if (button && Notification.permission === 'granted' && localStorage.getItem('horadric.push.' + state.pc.id) === state.vapid) {
    button = false;
    text = 'You get a notification when a session waits.';
  }
  b.hidden = !button;
  hint.hidden = !text;
  hint.textContent = text || '';
}

async function subscription(create) {
  const reg = await navigator.serviceWorker.ready;
  let sub = await reg.pushManager.getSubscription();
  const want = b64url(state.vapid);
  if (sub && sub.options && sub.options.applicationServerKey) {
    const have = new Uint8Array(sub.options.applicationServerKey);
    if (have.length !== want.length || have.some((x, i) => x !== want[i])) {
      // Subscribed for another PC's key. A page holds one subscription, so
      // it moves to the PC in front, and only when the human asks.
      if (!create) return null;
      await sub.unsubscribe();
      sub = null;
    }
  }
  if (!sub && create) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: want });
  return sub;
}

async function enablePush() {
  try {
    if ((await Notification.requestPermission()) === 'granted') {
      const sub = await subscription(true);
      if (sub && (await send({ t: 'push', sub: sub.toJSON() }))) {
        localStorage.setItem('horadric.push.' + state.pc.id, state.vapid);
      }
    }
    renderPush();
  } catch (e) {
    renderPush();
    $('notifyhint').hidden = false;
    $('notifyhint').textContent = 'Could not turn notifications on: ' + (e && e.message ? e.message : e);
  }
}

// The PC dedupes, so sending the subscription on every hello costs little
// and heals a PC that lost it (a rekey, a new install).
async function resendPush() {
  if (!state.vapid || pushSupport() || Notification.permission !== 'granted') return;
  try {
    const sub = await subscription(false);
    if (sub) send({ t: 'push', sub: sub.toJSON() });
  } catch {}
}

// The screen's text size is kept as an offset from the base size, so a
// size saved before pinching (whole steps from the A buttons) still reads.
const BASE_TEXT = 13;
const MIN_TEXT = 8;
const MAX_TEXT = 28;
let zoom = Number(localStorage.getItem('horadric.textzoom')) || 0;
const textSize = () => Math.max(MIN_TEXT, Math.min(MAX_TEXT, BASE_TEXT + zoom));

// A PC terminal is 150 columns or more and a phone fits about 45 readable
// ones. Shrinking the PC's width to the phone made text too small to read,
// so the phone keeps a readable size and wraps instead. Rules and the gaps
// that right align a status line are drawn for the PC's width, and wrapped
// they turn into rows of dashes, so they are cut to the phone's first.
const RULE = /[─━═╌┄┈\-]{4,}/g;
const GAP = /(?<=\S) {3,}(?=\S)/g;

// A line as cells, one per character, each with the index of its run in
// the PC's styles (-1 for plain), so fitting a line keeps its colours.
function cells(line, runs) {
  const chars = [...line];
  const style = new Array(chars.length).fill(-1);
  let at = 0;
  (runs || []).forEach((r, i) => {
    for (let k = 0; k < r[0] && at < chars.length; k++) style[at++] = i;
  });
  return chars.map((c, i) => [c, style[i]]);
}

// Drops the characters of each match of `re` past its first `keep`.
function squeeze(cs, re, keep) {
  const text = cs.map((c) => c[0]).join('');
  const at = [];
  cs.forEach((c, i) => { for (let k = 0; k < c[0].length; k++) at.push(i); });
  at.push(cs.length);
  const drop = new Set();
  for (const m of text.matchAll(re)) {
    const from = at[m.index];
    const to = at[m.index + m[0].length];
    for (let i = from + keep; i < to; i++) drop.add(i);
  }
  return drop.size ? cs.filter((_, i) => !drop.has(i)) : cs;
}

function fitLine(cs, cols) {
  if (cs.length <= cols) return cs;
  if (/^[─━═╌┄┈\-\s]+$/.test(cs.map((c) => c[0]).join(''))) {
    const first = cs.findIndex((c) => c[0] !== ' ');
    return cs.slice(first).slice(0, cols);
  }
  let out = squeeze(cs, RULE, 3);
  if (out.length > cols) out = squeeze(out, GAP, 2);
  return out;
}

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;' };
const hex = (n) => '#' + n.toString(16).padStart(6, '0');

// The CSS of a run from the PC: [count, fg, bg, flags], colours as
// 0xRRGGBB or null for the terminal's own.
function runCss(r) {
  let css = '';
  if (r[1] != null) css += `color:${hex(r[1])};`;
  if (r[2] != null) css += `background:${hex(r[2])};`;
  if (r[3] & 1) css += 'font-weight:bold;';
  if (r[3] & 2) css += 'font-style:italic;';
  const lines = [r[3] & 4 && 'underline', r[3] & 8 && 'line-through'].filter(Boolean);
  if (lines.length) css += `text-decoration:${lines.join(' ')};`;
  return css;
}

function lineHtml(cs, runs) {
  let html = '';
  let i = 0;
  while (i < cs.length) {
    const s = cs[i][1];
    let text = '';
    while (i < cs.length && cs[i][1] === s) text += cs[i++][0];
    text = text.replace(/[&<>]/g, (c) => ESC[c]);
    const css = s < 0 ? '' : runCss(runs[s]);
    html += css ? `<span style="${css}">${text}</span>` : text;
  }
  return html;
}

// The width of one monospace cell at the screen's font size.
function cellWidth(pre) {
  const ctx = (cellWidth.canvas ||= document.createElement('canvas')).getContext('2d');
  const style = getComputedStyle(pre);
  ctx.font = `${style.fontSize} ${style.fontFamily}`;
  return ctx.measureText('M'.repeat(20)).width / 20 || 8;
}

function renderScreen() {
  const sc = state.screen;
  const pre = $('screen');
  const wrap = $('screenwrap');
  const atBottom = wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < 40;
  pre.style.fontSize = textSize() + 'px';
  const cols = Math.max(20, Math.floor((pre.clientWidth - 12) / cellWidth(pre)));
  if (sc) {
    // A PC before colours sends no styles, and its lines draw plain.
    const styles = sc.styles || [];
    pre.innerHTML = (sc.lines || [])
      .map((l, i) => lineHtml(fitLine(cells(l, styles[i]), cols), styles[i]))
      .join('\n');
  } else {
    pre.textContent = state.paused ? 'This session is paused.' : 'Waiting for the screen...';
  }
  $('resumebar').hidden = !state.paused;
  if (atBottom || !renderScreen.seen) wrap.scrollTop = wrap.scrollHeight;
  renderScreen.seen = true;
}

// Navigation

// How deep a view sits, so going deeper slides in from the right and back
// slides the other way.
const DEPTH = { unpaired: 0, list: 0, projects: 1, session: 1 };
const still = matchMedia('(prefers-reduced-motion: reduce)');

function show(view) {
  const from = state.view;
  state.view = view;
  const leaving = from !== view && !$(from).hidden ? $(from) : null;
  // Measured while it still shows, since hidden it has no size.
  const where = leaving && leaving.getBoundingClientRect();
  for (const v of ['unpaired', 'list', 'projects', 'session']) $(v).hidden = v !== view;
  $('back').hidden = view !== 'session' && view !== 'projects';
  if (leaving) slide(leaving, where, $(view), DEPTH[view] < DEPTH[from] ? 'back' : 'fwd');
}

// The view going away is pinned where it was and slides out while the new
// one slides in, so both move together for a moment. A timer ends it, not
// animationend, which a page in the background may never get.
const SLIDE_MS = 240;
function slide(out, where, into, way) {
  clearTimeout(slide.timer);
  settle();
  if (still.matches) return;
  if (where.height) {
    out.hidden = false;
    out.style.top = where.top + 'px';
    out.style.height = where.height + 'px';
    out.classList.add('leaving', way);
  }
  void into.offsetWidth;
  into.classList.add('entering', way);
  slide.timer = setTimeout(settle, SLIDE_MS + 60);
}

function settle() {
  for (const v of document.querySelectorAll('.view.leaving, .view.entering')) {
    v.classList.remove('leaving', 'entering', 'fwd', 'back');
    v.style.top = v.style.height = '';
    v.hidden = state.view !== v.id;
  }
}

function watch(id) {
  const again = state.watching === id;
  // A session started from the projects view takes that view's place in
  // history, so back goes to the session list.
  const swap = (state.watching && !again) || state.view === 'projects';
  state.watching = id;
  state.screen = null;
  state.paused = false;
  renderScreen.seen = false;
  show('session');
  renderTitle();
  renderScreen();
  send({ t: 'watch', id });
  // One history entry for the session view, whichever session it shows.
  if (swap) history.replaceState({ session: id }, '');
  else if (!again) history.pushState({ session: id }, '');
}

function unwatch() {
  if (!state.watching) return;
  state.watching = null;
  state.paused = false;
  state.screen = null;
  send({ t: 'unwatch' });
  show('list');
  renderTitle();
}

function choose(pc) {
  state.pc = pc;
  state.sessions = [];
  state.projects = [];
  state.vapid = null;
  state.warning = null;
  state.starting = null;
  state.watching = null;
  state.tooOld = false;
  state.folders = null;
  state.listed = false;
  if (pc) localStorage.setItem('horadric.current', pc.id);
  renderPcs();
  renderTitle();
  renderList();
  show(pc ? 'list' : 'unpaired');
  if (pc) connect();
  else {
    if (state.ws) state.ws.close();
    $('status').hidden = true;
  }
}

// Input

// A short tick where the phone can vibrate: one for a message sent, a
// double one for an answer to what the agent asked. iOS has no vibrate and
// stays silent.
const TICK = { send: 12, answer: [12, 60, 12] };
function haptic(kind) {
  if (navigator.vibrate) navigator.vibrate(TICK[kind]);
}

// The keys that answer a waiting agent: a choice's digit, yes or no.
const isAnswer = (k) => /^[0-9yn]$/.test(k);

function typeInto(data) {
  if (!state.watching) return;
  send({ t: 'input', id: state.watching, data });
}

$('keys').addEventListener('click', (ev) => {
  const b = ev.target.closest('button');
  if (!b || !b.dataset.k) return;
  haptic(isAnswer(b.dataset.k) ? 'answer' : 'send');
  typeInto(b.dataset.k);
});

// Pinching the screen sizes its text. The text rewraps at every size, so
// the anchor is how far down the content the fingers' midpoint sits, which
// rewrapping keeps roughly where it was.
const pinch = { from: 0, size: 0, at: 0, y: 0, frame: 0 };

function fingers(ev) {
  const [a, b] = ev.touches;
  return { gap: Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY), y: (a.clientY + b.clientY) / 2 };
}

function zoomTo(size, y) {
  const wrap = $('screenwrap');
  const top = y - wrap.getBoundingClientRect().top;
  const at = (wrap.scrollTop + top) / (wrap.scrollHeight || 1);
  zoom = Math.max(MIN_TEXT, Math.min(MAX_TEXT, size)) - BASE_TEXT;
  renderScreen();
  wrap.scrollTop = at * wrap.scrollHeight - top;
}

// Settles on a half pixel, so the size kept is one the page draws again.
function saveZoom(size, y) {
  cancelAnimationFrame(pinch.frame);
  pinch.frame = 0;
  zoomTo(Math.round(size * 2) / 2, y);
  localStorage.setItem('horadric.textzoom', zoom);
}

const screenwrap = $('screenwrap');
screenwrap.addEventListener('touchstart', (ev) => {
  if (ev.touches.length !== 2) return;
  const f = fingers(ev);
  pinch.from = f.gap || 1;
  pinch.size = textSize();
  pinch.at = pinch.size;
  pinch.y = f.y;
}, { passive: true });
screenwrap.addEventListener('touchmove', (ev) => {
  if (ev.touches.length !== 2 || !pinch.from) return;
  ev.preventDefault();
  const f = fingers(ev);
  pinch.at = pinch.size * (f.gap / pinch.from);
  pinch.y = f.y;
  // Rewrapping the whole screen costs a layout, so once a frame at most.
  pinch.frame ||= requestAnimationFrame(() => {
    pinch.frame = 0;
    zoomTo(pinch.at, pinch.y);
  });
}, { passive: false });
screenwrap.addEventListener('touchend', (ev) => {
  if (ev.touches.length >= 2 || !pinch.from) return;
  pinch.from = 0;
  saveZoom(pinch.at, pinch.y);
});
screenwrap.addEventListener('touchcancel', () => {
  if (!pinch.from) return;
  pinch.from = 0;
  saveZoom(pinch.at, pinch.y);
});
// Safari's own pinch gesture would scale the whole page instead.
document.addEventListener('gesturestart', (ev) => ev.preventDefault());
// A trackpad pinch on a computer arrives as a wheel with Ctrl held.
screenwrap.addEventListener('wheel', (ev) => {
  if (!ev.ctrlKey) return;
  ev.preventDefault();
  const size = textSize() * Math.exp(-ev.deltaY / 100);
  zoomTo(size, ev.clientY);
  clearTimeout(pinch.idle);
  pinch.idle = setTimeout(() => saveZoom(size, ev.clientY), 300);
}, { passive: false });

$('send').addEventListener('submit', (ev) => {
  ev.preventDefault();
  const text = $('text').value;
  haptic('send');
  if (!text) return typeInto('\r');
  typeInto(text);
  // Enter apart from the text, so the agent sees typing then a key, not a
  // paste with a newline in it.
  setTimeout(() => typeInto('\r'), 80);
  $('text').value = '';
  $('text').style.height = '';
});
$('text').addEventListener('keydown', (ev) => {
  if (ev.key === 'Enter' && !ev.shiftKey) {
    ev.preventDefault();
    $('send').requestSubmit();
  }
});
$('text').addEventListener('input', () => {
  const t = $('text');
  t.style.height = '';
  t.style.height = t.scrollHeight + 'px';
});

// Photos. The frame is 1 MB and base64 adds a third, so the page shrinks
// the picture until it is well under that before sending it.

const PHOTO_BYTES = 700 * 1024;

async function bitmapOf(file) {
  try {
    return await createImageBitmap(file, { imageOrientation: 'from-image' });
  } catch {
    const url = URL.createObjectURL(file);
    try {
      const img = new Image();
      img.src = url;
      await img.decode();
      return img;
    } finally {
      URL.revokeObjectURL(url);
    }
  }
}

// A JPEG under PHOTO_BYTES: the long side at most 2048 pixels, smaller
// and rougher until it fits.
async function shrink(file) {
  const img = await bitmapOf(file);
  const w0 = img.width, h0 = img.height;
  let side = Math.min(2048, Math.max(w0, h0));
  let quality = 0.85;
  for (;;) {
    const scale = side / Math.max(w0, h0);
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(w0 * scale));
    canvas.height = Math.max(1, Math.round(h0 * scale));
    canvas.getContext('2d').drawImage(img, 0, 0, canvas.width, canvas.height);
    const blob = await new Promise((done) => canvas.toBlob(done, 'image/jpeg', quality));
    if (blob && (blob.size <= PHOTO_BYTES || side <= 320)) return blob;
    if (quality > 0.6) quality -= 0.15;
    else side = Math.round(side * 0.75);
  }
}

function toB64url(blob) {
  return new Promise((done, fail) => {
    const r = new FileReader();
    r.onload = () => done(r.result.slice(r.result.indexOf(',') + 1).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
    r.onerror = () => fail(r.error);
    r.readAsDataURL(blob);
  });
}

function attachDone() {
  clearTimeout(state.attaching && state.attaching.timer);
  state.attaching = null;
  $('attach').classList.remove('busy');
  $('attach').disabled = false;
}

async function attachPhoto(file) {
  const id = state.watching;
  if (!id || state.attaching) return;
  state.attaching = { id };
  $('attach').classList.add('busy');
  $('attach').disabled = true;
  try {
    const blob = await shrink(file);
    const name = (file.name || 'photo').replace(/\.[^.]*$/, '') + '.jpg';
    if (!(await send({ t: 'attach', id, name, data: await toB64url(blob) }))) throw new Error('offline');
    // A PC before the attach message never answers.
    state.attaching.timer = setTimeout(() => {
      attachDone();
      say('The PC did not take the photo. It may need a newer Horadric.');
    }, 30000);
  } catch {
    attachDone();
    say('Could not send that photo.');
  }
}

// The PC saved it: its path goes into the message, for the agent to read.
function attached(msg) {
  if (!state.attaching || msg.id !== state.attaching.id) return;
  attachDone();
  if (typeof msg.path !== 'string' || msg.id !== state.watching) return;
  const t = $('text');
  const sep = t.value && !/\s$/.test(t.value) ? ' ' : '';
  t.value += sep + msg.path + ' ';
  t.dispatchEvent(new Event('input'));
  t.focus();
}

$('attach').onclick = () => $('photo').click();
$('photo').addEventListener('change', () => {
  const file = $('photo').files[0];
  $('photo').value = '';
  if (file) attachPhoto(file);
});

$('back').onclick = () => history.back();
window.addEventListener('popstate', () => {
  if (state.watching) return unwatch();
  if (state.view === 'projects') {
    show('list');
    renderTitle();
  }
});

$('openproject').onclick = openProjects;
$('search').addEventListener('input', renderFolders);
$('newproject').onclick = () => {
  $('create').hidden = !$('create').hidden;
  if (!$('create').hidden) $('pname').focus();
};
$('pname').addEventListener('input', () => {
  $('createhint').className = 'dim';
  $('createhint').textContent = '';
});
$('create').onsubmit = (ev) => {
  ev.preventDefault();
  const root = $('root').value;
  const name = $('pname').value.trim();
  const problem = root ? nameProblem(name, root) : 'The PC listed no place to make it in.';
  if (problem) {
    $('createhint').className = 'dim bad';
    $('createhint').textContent = problem;
    return;
  }
  if (state.starting || state.link !== 'online') return;
  $('pname').value = '';
  $('create').hidden = true;
  startIn(root + sepOf(root) + name, { t: 'create', root, name });
  state.starting.root = root;
  renderFolders();
};

$('pcs').onchange = () => choose(loadPcs().find((p) => p.id === $('pcs').value) || null);

$('forget').onclick = () => {
  if (!state.pc || !confirm(`Forget ${state.pc.n}? You will need its pairing link again.`)) return;
  const pcs = loadPcs().filter((p) => p.id !== state.pc.id);
  savePcs(pcs);
  choose(pcs[0] || null);
};

// On iOS a home screen app keeps storage of its own, and the camera opens
// links only in the browser, so a pairing has to be carried over by hand.
$('copylink').onclick = async () => {
  if (!state.pc) return;
  try {
    await navigator.clipboard.writeText(linkFor(state.pc));
    $('copylink').textContent = 'Copied. Paste it in the home screen app.';
  } catch {
    prompt('Copy this pairing link:', linkFor(state.pc));
  }
};
$('pasteform').onsubmit = (ev) => {
  ev.preventDefault();
  if (!pairWith($('pastelink').value.trim())) {
    $('pastehint').textContent = 'That is not a pairing link.';
    return;
  }
  $('pastelink').value = '';
  $('pastehint').textContent = '';
  pairFromLink();
};

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') wake();
});
window.addEventListener('online', wake);
$('notify').onclick = enablePush;
$('resume').onclick = () => state.watching && resume(state.watching);
window.addEventListener('resize', () => state.watching && renderScreen());

// Start

// A pairing link opened on a page that is already up only changes the
// fragment, so take it then too.
function pairFromLink() {
  takeFragment();
  const pcs = loadPcs();
  const current = localStorage.getItem('horadric.current');
  choose(pcs.find((p) => p.id === current) || pcs[0] || null);
}
window.addEventListener('hashchange', pairFromLink);
pairFromLink();

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
