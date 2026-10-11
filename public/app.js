// The Town Portal page: the phone's side of docs/PORTAL.md. It talks to
// the PC through the relay, and everything it says is encrypted with the
// pairing key, which lives only in this browser.
'use strict';

const VERSION = 1;
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
// sees. Returns whether `fragment` held a pairing.
function pairWith(fragment) {
  const p = new URLSearchParams(fragment.replace(/^[^#]*#/, ''));
  const id = p.get('id');
  const k = p.get('k');
  const r = p.get('r');
  if (!id || !k || !r || !/^[0-9a-f]{32}$/.test(id)) return false;
  const pcs = loadPcs().filter((pc) => pc.id !== id);
  pcs.push({ id, k, r: r.replace(/\/+$/, ''), n: p.get('n') || 'PC' });
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

// The same link the PC prints, so it can be carried somewhere this
// browser's storage does not reach.
function linkFor(pc) {
  const q = new URLSearchParams({ r: pc.r, id: pc.id, k: pc.k, n: pc.n });
  return `${location.origin}/#${q}`;
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
  starting: null, // { project, at }
  paused: false, // the watched session answered watch with paused
  heard: 0, // when the relay last said anything, ms
  watching: null,
  screen: null,
  backoff: 1000,
  timer: null,
  tooOld: false,
};

function setLink(link) {
  state.link = link;
  const lamp = $('status').querySelector('.lamp');
  const label = $('status').querySelector('span');
  const words = { connecting: 'Connecting', offline: 'No relay', pcoff: 'PC offline', online: 'Online' };
  lamp.className = 'lamp ' + (link === 'online' ? 'online' : link === 'connecting' ? 'connecting' : 'offline');
  label.textContent = words[link];
  renderNote();
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
  try {
    state.key = await importKey(pc.k);
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
        send({ t: 'hello', v: VERSION });
        if (state.watching) send({ t: 'watch', id: state.watching });
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

async function send(obj) {
  const ws = state.ws;
  if (!ws || ws.readyState !== 1 || !state.key) return false;
  ws.send(await seal(state.key, obj));
  return true;
}

function onMessage(msg) {
  switch (msg.t) {
    case 'hello':
      state.tooOld = msg.v !== VERSION;
      state.pcName = msg.pc || state.pc.n;
      if (msg.pc && msg.pc !== state.pc.n) {
        state.pc.n = msg.pc;
        savePcs(loadPcs().map((p) => (p.id === state.pc.id ? state.pc : p)));
        renderPcs();
      }
      state.vapid = typeof msg.vapid === 'string' ? msg.vapid : null;
      renderNote();
      renderTitle();
      renderPush();
      resendPush();
      break;
    case 'projects':
      state.projects = Array.isArray(msg.list) ? msg.list : [];
      renderList();
      break;
    case 'started':
      state.starting = null;
      renderList();
      if (msg.id) watch(msg.id);
      break;
    case 'sessions':
      state.sessions = Array.isArray(msg.list) ? msg.list : [];
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
    case 'error':
      if (state.watching && /paused/i.test(msg.text || '')) {
        state.paused = true;
        renderScreen();
        break;
      }
      if (state.starting) {
        state.starting = null;
        renderList();
      }
      $('note').hidden = false;
      $('note').textContent = msg.text || 'The PC reported an error.';
      break;
  }
}

// Rendering

const PHASES = ['working', 'waiting', 'idle', 'ended'];
const phaseOf = (s) => (PHASES.includes(s.phase) ? s.phase : 'idle');

function renderNote() {
  const note = $('note');
  let text = '';
  if (state.tooOld) text = 'This PC runs a Horadric this page does not speak. Update Horadric on the PC.';
  else if (state.link === 'pcoff') text = `${state.pc ? state.pc.n : 'The PC'} is not connected. Is Horadric running, with horadric portal on?`;
  else if (state.link === 'offline') text = 'Cannot reach the relay. Retrying.';
  note.hidden = !text;
  note.textContent = text;
}

function renderTitle() {
  if (state.watching) {
    const s = state.sessions.find((x) => x.id === state.watching);
    $('title').textContent = s ? s.name : 'Session';
  } else {
    $('title').textContent = state.pc ? state.pc.n : 'Horadric';
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

function renderList() {
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

function startIn(path) {
  const at = Date.now();
  state.starting = { project: path, at };
  renderList();
  send({ t: 'start', project: path });
  // A PC that never answers must not leave the spinner forever.
  setTimeout(() => {
    if (!state.starting || state.starting.at !== at) return;
    state.starting = null;
    renderList();
    $('note').hidden = false;
    $('note').textContent = 'The PC did not start the session. Is its Horadric up to date?';
  }, 30000);
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

let zoom = Number(localStorage.getItem('horadric.zoom')) || 0;

function renderScreen() {
  const sc = state.screen;
  const pre = $('screen');
  const wrap = $('screenwrap');
  const atBottom = wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < 40;
  const cols = sc && sc.cols ? sc.cols : 80;
  // Fit the PC's columns to the phone's width, then let the human zoom.
  const fit = (wrap.clientWidth - 12) / (cols * 0.6);
  const size = Math.max(5, Math.min(16, fit + zoom));
  pre.style.fontSize = size.toFixed(2) + 'px';
  pre.textContent = sc ? (sc.lines || []).join('\n') : state.paused ? 'This session is paused.' : 'Waiting for the screen...';
  $('resumebar').hidden = !state.paused;
  if (atBottom || !renderScreen.seen) wrap.scrollTop = wrap.scrollHeight;
  renderScreen.seen = true;
}

// Navigation

function show(view) {
  for (const v of ['unpaired', 'list', 'session']) $(v).hidden = v !== view;
  $('back').hidden = view !== 'session';
}

function watch(id) {
  const again = state.watching === id;
  const swap = state.watching && !again;
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
  state.starting = null;
  state.watching = null;
  state.tooOld = false;
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

function typeInto(data) {
  if (!state.watching) return;
  send({ t: 'input', id: state.watching, data });
}

$('keys').addEventListener('click', (ev) => {
  const b = ev.target.closest('button');
  if (!b || !b.dataset.k) return;
  typeInto(b.dataset.k);
});

$('zoomin').onclick = () => {
  zoom += 1;
  localStorage.setItem('horadric.zoom', zoom);
  renderScreen();
};
$('zoomout').onclick = () => {
  zoom -= 1;
  localStorage.setItem('horadric.zoom', zoom);
  renderScreen();
};

$('send').addEventListener('submit', (ev) => {
  ev.preventDefault();
  const text = $('text').value;
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

$('back').onclick = () => history.back();
window.addEventListener('popstate', () => unwatch());

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
