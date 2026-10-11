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
// sees. Take it and wipe it from the address bar.
function takeFragment() {
  if (location.hash.length < 2) return;
  const p = new URLSearchParams(location.hash.slice(1));
  const id = p.get('id');
  const k = p.get('k');
  const r = p.get('r');
  if (id && k && r && /^[0-9a-f]{32}$/.test(id)) {
    const pcs = loadPcs().filter((pc) => pc.id !== id);
    pcs.push({ id, k, r: r.replace(/\/+$/, ''), n: p.get('n') || 'PC' });
    savePcs(pcs);
    localStorage.setItem('horadric.current', id);
  }
  history.replaceState(null, '', location.pathname);
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
  };
  ws.onmessage = async (ev) => {
    if (typeof ev.data === 'string') {
      let msg;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
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
      renderNote();
      renderTitle();
      break;
    case 'sessions':
      state.sessions = Array.isArray(msg.list) ? msg.list : [];
      renderList();
      renderTitle();
      break;
    case 'screen':
      if (msg.id === state.watching) {
        state.screen = msg;
        renderScreen();
      }
      break;
    case 'error':
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

function renderList() {
  const groups = new Map();
  for (const s of state.sessions) {
    const key = s.project || 'Other';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(s);
  }
  const rank = (s) => ({ waiting: 0, working: 1, idle: 2, ended: 3 })[phaseOf(s)];
  const sorted = [...groups.entries()]
    .map(([project, list]) => [project, list.sort((a, b) => rank(a) - rank(b) || String(a.name).localeCompare(b.name))])
    .sort((a, b) => rank(a[1][0]) - rank(b[1][0]) || a[0].localeCompare(b[0]));
  const out = [];
  for (const [project, list] of sorted) {
    const g = document.createElement('section');
    g.className = 'group';
    const h = document.createElement('h2');
    h.textContent = project.split(/[\\/]/).filter(Boolean).pop() || project;
    g.append(h);
    for (const s of list) {
      const b = document.createElement('button');
      const ph = phaseOf(s);
      b.className = 'sess ' + ph;
      const lamp = document.createElement('i');
      lamp.className = 'lamp ' + ph;
      const what = document.createElement('div');
      what.className = 'what';
      const name = document.createElement('div');
      name.className = 'name';
      name.textContent = s.name || s.id;
      const line = document.createElement('div');
      line.className = 'line';
      line.textContent = s.line || ph;
      what.append(name, line);
      b.append(lamp, what);
      b.onclick = () => watch(s.id);
      g.append(b);
    }
    out.push(g);
  }
  $('groups').replaceChildren(...out);
  $('empty').hidden = state.sessions.length > 0 || state.link !== 'online';
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
  pre.textContent = sc ? (sc.lines || []).join('\n') : 'Waiting for the screen...';
  if (atBottom || !renderScreen.seen) wrap.scrollTop = wrap.scrollHeight;
  renderScreen.seen = true;
}

// Navigation

function show(view) {
  for (const v of ['unpaired', 'list', 'session']) $(v).hidden = v !== view;
  $('back').hidden = view !== 'session';
}

function watch(id) {
  state.watching = id;
  state.screen = null;
  renderScreen.seen = false;
  show('session');
  renderTitle();
  renderScreen();
  send({ t: 'watch', id });
  history.pushState({ session: id }, '');
}

function unwatch() {
  if (!state.watching) return;
  state.watching = null;
  state.screen = null;
  send({ t: 'unwatch' });
  show('list');
  renderTitle();
}

function choose(pc) {
  state.pc = pc;
  state.sessions = [];
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

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && state.pc && !state.ws) connect();
});
window.addEventListener('resize', () => state.watching && renderScreen());

// Start

takeFragment();
{
  const pcs = loadPcs();
  const current = localStorage.getItem('horadric.current');
  choose(pcs.find((p) => p.id === current) || pcs[0] || null);
}

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
