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
  try {
    localStorage.setItem('horadric.tab', id);
  } catch {}
  return true;
}

// Take the link from the address bar, then wipe it from there, so a
// reload does not answer twice. A notification's link,
// #s=<session>&pc=<pc>, is kept in `state.open` for the page to show that
// session, and a button's answer on it (&a=<keys>&l=<label>&w=<since>) in
// `state.answer` until the PC lists that session.
function takeFragment() {
  if (location.hash.length < 2) return;
  const p = new URLSearchParams(location.hash.slice(1));
  if (p.get('s')) {
    state.open = { id: p.get('s'), pc: p.get('pc') || '' };
    if (p.has('a')) holdAnswer(state.open, { keys: p.get('a'), label: p.get('l'), since: p.get('w') });
  } else pairWith(location.hash);
  history.replaceState(null, '', location.pathname);
}

// An answer from a notification's button waits for the first session list
// from its PC, and is dropped after a few minutes unsent.
const ANSWER_FOR = 5 * 60 * 1000;
function holdAnswer(open, a) {
  if (!a || typeof a.keys !== 'string' || !a.keys) return;
  const since = Number(a.since) || 0;
  state.answer = { id: open.id, pc: open.pc, keys: a.keys, label: a.label || a.keys, since, at: Date.now() };
}

// Sends the held answer once, if the session still waits on the same
// thing: the wait that began at `since` when the push said so, and one of
// its options when the PC lists them. A wait that moved on keeps its keys.
function sendHeldAnswer(L) {
  const a = state.answer;
  if (!a || (a.pc && a.pc !== L.pc.id)) return;
  const s = L.sessions.find((x) => x.id === a.id);
  // A push from a PC that names none is for whichever PC lists the session.
  if (!s && !a.pc && many()) return;
  state.answer = null;
  if (Date.now() - a.at > ANSWER_FOR) return;
  if (!s || phaseOf(s) !== 'waiting' || s.paused) return;
  const at = askSince(s);
  if (a.since && at && at !== (a.since < 1e12 ? a.since * 1000 : a.since)) return;
  const options = s.ask && Array.isArray(s.ask.options) ? s.ask.options : null;
  const opt = options ? options.find((o) => o && o.keys === a.keys) : { label: a.label, keys: a.keys };
  if (opt) answer(s, { label: opt.label || a.label, keys: opt.keys });
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

// Every paired PC has a link of its own, all open at once: its socket,
// its key, its replay count, and what it last said.
function newLink(pc) {
  return {
    pc,
    key: null,
    ws: null,
    link: 'connecting', // connecting | offline (relay down) | pcoff | online
    greeted: false, // the PC answered this connection's hello
    s: null, // this connection's id from the PC's hello, sent back on every message
    n: 0, // the count on the last message sent
    answered: null, // the timer that gives up on a PC that never answers hello
    heard: 0, // when the relay last said anything, ms
    backoff: 1000,
    timer: null,
    tooOld: false,
    warning: null, // a note that stays: another phone took this phone's pairing code
    vapid: null,
    sessions: [],
    projects: [],
    take: [], // a silent brother's sessions this PC can take over
    taking: null,
    listed: false, // a sessions answer came from this PC, so the list is real
    starting: null, // { project, at }
    folders: null, // the PC's folders answer, null until it comes
    quests: null, // the PC's quests answer, null until it comes
    added: null, // { project, at } while an added quest is on its way
    sent: new Map(), // session id -> { label, since }: an inbox answer sent, until the phase moves
  };
}

// The link that listed a session, so a row tapped in "All" opens it on
// the PC it lives on.
const owner = new WeakMap();

const state = {
  links: [], // one per paired PC, in the order they were paired
  tab: 'all', // 'all' or a PC's id
  open: null, // the session a notification asked to show, {id, pc}
  answer: null, // a notification button's answer, until its PC lists sessions, see holdAnswer
  wlink: null, // the link of the watched session
  paused: false, // the watched session answered watch with paused
  watching: null,
  screen: null,
  view: 'list', // unpaired | list | projects | quests | session
  changes: null, // the watched session's changed files, null until the PC answers
  changesOpen: false, // whether the list of them is open
  watchedPhase: null, // the watched session's phase, to ask again when it moves
  diffPath: null, // the file whose diff is shown
  diff: null, // the PC's diff answer for it
  diffError: null,
  adding: null, // the project whose add-a-quest form is open
  notesOpen: new Set(), // the quests whose notes show, by project and title
  sheet: null, // the long press menu, see openSheet
  replyWait: null, // { id, L, resolve, reject, timer } while a reply is asked for
};

const many = () => state.links.length > 1;
const linkOf = (id) => state.links.find((L) => L.pc.id === id) || null;

// The PC the tab in front is about: the only one, or the one whose tab is
// picked. Null in "All" with several.
function tabLink() {
  return many() ? linkOf(state.tab) : state.links[0] || null;
}

// The PC whatever is done now goes to: the watched session's, else the tab's.
function here() {
  return state.wlink || tabLink();
}

// The PCs the list shows.
function shownLinks() {
  const L = tabLink();
  return L ? [L] : state.links;
}

function setLink(L, link) {
  L.link = link;
  if (link !== 'online') L.greeted = false;
  renderTabs();
  renderStatus();
  renderNote();
  renderList();
  if (state.view === 'quests' && here() === L) renderQuests();
}

function renderStatus() {
  const L = here();
  $('status').hidden = !L || state.view === 'unpaired';
  if (!L) return;
  const lamp = $('status').querySelector('.lamp');
  const label = $('status').querySelector('span');
  const words = { connecting: 'Connecting', offline: 'No relay', pcoff: 'PC offline', online: 'Online' };
  lamp.className = 'lamp ' + (L.link === 'online' ? 'online' : L.link === 'connecting' ? 'connecting' : 'offline');
  label.textContent = words[L.link];
}

// Connection

async function connect(L) {
  clearTimeout(L.timer);
  if (L.ws) {
    L.ws.onclose = null;
    L.ws.close();
    L.ws = null;
  }
  if (!state.links.includes(L)) return;
  L.s = null;
  try {
    L.key = await importKey(L.pc.pk || L.pc.k);
  } catch {
    // A PC that forgot this phone has said so already, in a note that stays.
    L.warning ||= 'This pairing link is broken. Pair again with horadric portal.';
    setLink(L, 'offline');
    return;
  }
  setLink(L, 'connecting');
  const ws = new WebSocket(`${L.pc.r}/phone?id=${L.pc.id}`);
  ws.binaryType = 'arraybuffer';
  L.ws = ws;
  ws.onopen = () => {
    L.backoff = 1000;
    L.heard = Date.now();
  };
  ws.onmessage = async (ev) => {
    if (L.ws !== ws) return;
    L.heard = Date.now();
    if (typeof ev.data === 'string') {
      let msg;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      if (msg.pong) return;
      if (msg.relay === 'online') {
        setLink(L, 'online');
        if (L.pc.pk) pairNow(L);
        else greet(L);
      } else if (msg.relay === 'offline') {
        setLink(L, 'pcoff');
      }
      return;
    }
    let msg;
    try {
      msg = await open(L.key, ev.data);
    } catch {
      return;
    }
    onMessage(L, msg);
  };
  ws.onclose = () => {
    if (L.ws !== ws) return;
    L.ws = null;
    setLink(L, 'offline');
    L.timer = setTimeout(() => connect(L), L.backoff);
    L.backoff = Math.min(L.backoff * 2, 15000);
  };
}

// A forgotten PC's link goes quiet for good.
function drop(L) {
  clearTimeout(L.timer);
  clearTimeout(L.answered);
  if (L.ws) {
    L.ws.onclose = null;
    L.ws.close();
    L.ws = null;
  }
  if (state.sheet && state.sheet.L === L) closeSheet();
  if (state.wlink === L) {
    clearWatch();
    show('list');
  }
}

// The links follow the paired PCs: a new PC gets one, a forgotten one
// loses its own, and a PC paired again (a new code or key) reconnects.
function syncLinks() {
  const old = state.links;
  const fresh = [];
  state.links = loadPcs().map((pc) => {
    const L = old.find((x) => x.pc.id === pc.id);
    if (!L) {
      const made = newLink(pc);
      fresh.push(made);
      return made;
    }
    if (pc.pk !== L.pc.pk || pc.k !== L.pc.k) {
      L.warning = null;
      fresh.push(L);
    }
    L.pc = pc;
    return L;
  });
  for (const L of old) if (!state.links.includes(L)) drop(L);
  for (const L of fresh) connect(L);
}

// A socket can look open long after the network under it died, most of
// all on a phone that slept. A ping every 25 seconds, and a reconnect
// after 70 seconds of silence, find that out.
const PING_MS = 25000;
const SILENCE_MS = 70000;
setInterval(() => {
  for (const L of state.links) {
    const ws = L.ws;
    if (!ws || ws.readyState !== 1) continue;
    if (Date.now() - L.heard > SILENCE_MS) connect(L);
    else ws.send('{"ping":1}');
  }
}, PING_MS);

// Back in front, or back on a network: a socket from before is likely
// dead, so check at once instead of waiting for the next ping.
function wake() {
  for (const L of state.links) {
    if (!L.pc.k && !L.pc.pk) continue;
    const ws = L.ws;
    if (!ws || ws.readyState !== 1 || Date.now() - L.heard > PING_MS) connect(L);
    else ws.send('{"ping":1}');
  }
}

// After hello every message carries the connection's s and a count, so
// the relay cannot play an old one back to the PC.
async function send(obj, L = here()) {
  const ws = L && L.ws;
  if (!ws || ws.readyState !== 1 || !L.key) return false;
  if (L.s && obj.t !== 'hello' && obj.t !== 'pair') obj = { ...obj, s: L.s, n: ++L.n };
  ws.send(await seal(L.key, obj));
  return true;
}

// A note from one PC names it when there are several.
function tell(L, text) {
  say(many() ? `${L.pc.n}: ${text}` : text);
}

function greet(L) {
  L.s = null;
  L.greeted = false;
  send({ t: 'hello', v: VERSION }, L);
  clearTimeout(L.answered);
  L.answered = setTimeout(
    () => tell(L, 'The PC does not answer this phone. It may have forgotten it: run horadric portal on the PC and pair again.'),
    10000,
  );
}

// Trades the one-time code for a key of this phone's own.
function pairNow(L) {
  if (L.pc.x && Date.now() / 1000 > L.pc.x) {
    codeFailed(L, 'This pairing code ran out. Run horadric portal on the PC for a new one.');
    return;
  }
  send({ t: 'pair', v: VERSION, name: deviceName() }, L);
}

// The code was used or ran out: forget it, and go on with the key this
// phone had before, if any.
function codeFailed(L, text, used) {
  const pc = L.pc;
  if (used) L.warning = text;
  delete pc.pk;
  delete pc.x;
  savePc(pc);
  if (pc.k) connect(L);
  else if (!used) tell(L, text);
  renderNote();
}

async function paired(L, msg) {
  const pc = L.pc;
  try {
    L.key = await importKey(msg.key);
  } catch {
    return;
  }
  pc.k = msg.key;
  pc.phone = msg.phone;
  delete pc.pk;
  delete pc.x;
  savePc(pc);
  greet(L);
}

// The PC forgot this phone, so its key is no good any more.
function unpaired(L) {
  const pc = L.pc;
  delete pc.k;
  savePc(pc);
  if (L.ws) {
    L.ws.onclose = null;
    L.ws.close();
    L.ws = null;
  }
  L.warning = `${pc.n} forgot this phone. To use it again, run horadric portal on the PC and pair again.`;
  setLink(L, 'offline');
}

function onMessage(L, msg) {
  const watched = state.wlink === L;
  switch (msg.t) {
    case 'paired':
      paired(L, msg);
      break;
    case 'unpaired':
      unpaired(L);
      break;
    case 'hello':
      clearTimeout(L.answered);
      L.s = typeof msg.s === 'string' ? msg.s : null;
      L.n = 0;
      L.greeted = true;
      if (watched && state.watching) {
        send({ t: 'watch', id: state.watching }, L);
        askChanges();
        if (state.diffPath) send({ t: 'diff', id: state.watching, path: state.diffPath }, L);
      }
      L.tooOld = !SPEAKS.includes(msg.v);
      if (msg.pc && msg.pc !== L.pc.n) {
        L.pc.n = msg.pc;
        savePc(L.pc);
      }
      L.vapid = typeof msg.vapid === 'string' ? msg.vapid : null;
      renderTabs();
      renderNote();
      renderTitle();
      renderPush();
      resendPush(L);
      if (here() === L && state.view === 'projects') askFolders();
      if (here() === L && state.view === 'quests') askQuests();
      break;
    case 'quests':
      L.quests = Array.isArray(msg.list) ? msg.list : [];
      if (here() === L) renderQuests();
      break;
    case 'quest_added':
      // The text stays in the form until the PC has it, so an error
      // costs nothing typed.
      if (addForm.el) addForm.el.reset();
      L.added = null;
      state.adding = null;
      if (here() === L) renderQuests();
      break;
    case 'projects':
      L.projects = Array.isArray(msg.list) ? msg.list : [];
      renderList();
      break;
    case 'started':
      L.starting = null;
      renderList();
      if (here() === L) renderFolders();
      if (msg.id) watch(msg.id, null, L);
      break;
    case 'folders':
      L.folders = Array.isArray(msg.roots) ? msg.roots : [];
      if (here() === L) renderFolders();
      break;
    case 'sessions':
      L.listed = true;
      L.sessions = Array.isArray(msg.list) ? msg.list.filter((s) => s && typeof s === 'object') : [];
      for (const s of L.sessions) owner.set(s, L);
      // A silent brother's sessions this PC can take over, apart from its
      // own so nothing else treats them as the PC's.
      L.take = Array.isArray(msg.take) ? msg.take : [];
      if (L.taking && !L.take.some((x) => x.id === L.taking)) L.taking = null;
      pruneSent(L);
      sendHeldAnswer(L);
      renderList();
      if (state.view === 'quests' && here() === L) renderQuests();
      renderTitle();
      renderBadge();
      // A rename being typed must not be reset by an update.
      if (state.sheet && state.sheet.L === L && (state.sheet.mode !== 'rename' || !L.sessions.some((s) => s.id === state.sheet.id))) renderSheet();
      // A turn that ends or starts waiting has likely changed files.
      if (watched && state.watching) {
        const s = L.sessions.find((x) => x.id === state.watching);
        const phase = s ? s.phase : null;
        if (phase !== state.watchedPhase) askChanges();
        state.watchedPhase = phase;
      }
      break;
    case 'reply':
      gotReply(L, msg);
      break;
    case 'changes':
      if (watched && msg.id === state.watching) {
        state.changes = Array.isArray(msg.files) ? msg.files.filter((f) => f && typeof f.path === 'string') : [];
        renderChanges();
        if (state.view === 'diff') renderDiff();
      }
      break;
    case 'diff':
      if (watched && msg.id === state.watching && msg.path === state.diffPath) {
        state.diff = msg;
        renderDiff();
      }
      break;
    case 'screen':
      if (watched && msg.id === state.watching) {
        state.paused = false;
        state.screen = msg;
        renderScreen();
      }
      break;
    case 'attached':
      if (watched) attached(msg);
      break;
    case 'error':
      if (watched && state.attaching) attachDone();
      if (msg.code === 'used' || msg.code === 'expired') {
        codeFailed(L, msg.text, msg.code === 'used');
        break;
      }
      if (watched && state.watching && /paused/i.test(msg.text || '')) {
        state.paused = true;
        renderScreen();
        break;
      }
      if (watched && state.view === 'diff' && !state.diff) {
        state.diffError = msg.text || 'The PC could not show this file.';
        renderDiff();
        break;
      }
      if (L.starting) {
        L.starting = null;
        renderList();
        if (here() === L) renderFolders();
      }
      if (L.taking) {
        L.taking = null;
        renderList();
      }
      if (L.added) {
        L.added = null;
        if (here() === L) renderQuests();
      }
      tell(L, msg.text || 'The PC reported an error.');
      break;
  }
}

// Rendering

const PHASES = ['working', 'waiting', 'idle', 'ended'];
const phaseOf = (s) => (PHASES.includes(s.phase) ? s.phase : 'idle');

function noteOf(L) {
  if (L.warning) return L.warning;
  if (L.tooOld) return 'This PC runs a Horadric this page does not speak. Update Horadric on the PC.';
  if (L.link === 'pcoff') return `${L.pc.n} is not connected. Is Horadric running, with horadric portal on?`;
  if (L.link === 'offline') return 'Cannot reach the relay. Retrying.';
  return '';
}

// In "All" a PC that is merely off shows as its tab's grey dot, so only
// what needs the human is said there, by the PC's name.
function renderNote() {
  const links = shownLinks();
  let text = '';
  if (links.length === 1) text = noteOf(links[0]);
  else if (links.length) {
    const lines = links.filter((L) => L.warning || L.tooOld).map((L) => `${L.pc.n}: ${noteOf(L)}`);
    if (links.every((L) => L.link === 'offline' && !L.warning)) lines.push('Cannot reach the relay. Retrying.');
    text = lines.join(' ');
  }
  const note = $('note');
  note.hidden = !text;
  note.textContent = text;
}

// Sessions waiting on the human, longest wait first, and the count in the
// tab title and the page's title bar.
const waitingList = (links = shownLinks()) =>
  links
    .flatMap((L) => L.sessions)
    .filter((s) => phaseOf(s) === 'waiting' && !s.paused)
    .sort((a, b) => (askSince(a) || Infinity) - (askSince(b) || Infinity));

// `since` as seconds or milliseconds since the epoch, whichever the PC sent.
function askSince(s) {
  const t = Number(s.ask && s.ask.since);
  if (!t) return 0;
  return t < 1e12 ? t * 1000 : t;
}

// Esc, Ctrl+C, arrows and Tab always fit. y, n and the digits answer a
// prompt, so they show only while the session waits, and the digits only as
// many as its `ask` has options (1 to 3 when an older PC sends no `ask`).
function renderKeys(s) {
  const waiting = !!s && phaseOf(s) === 'waiting';
  const options = s && s.ask && Array.isArray(s.ask.options) ? s.ask.options.length : 3;
  for (const b of $('keys').querySelectorAll('[data-answer]')) {
    const k = b.dataset.k;
    b.hidden = !waiting || (/^[0-9]$/.test(k) && Number(k) > options);
  }
}

function renderTitle() {
  renderDots();
  const total = waitingList(state.links).length;
  document.title = total ? `(${total}) Horadric` : 'Horadric';
  if (state.view === 'diff') {
    $('title').textContent = baseName(state.diffPath || '') || 'Changes';
  } else if (state.watching) {
    const s = state.wlink && state.wlink.sessions.find((x) => x.id === state.watching);
    renderKeys(s);
    $('title').textContent = s ? s.name : 'Session';
  } else if (state.view === 'projects') {
    $('title').textContent = 'Open project';
  } else if (state.view === 'quests') {
    $('title').textContent = 'Quests';
  } else {
    const L = tabLink();
    const n = waitingList().length;
    $('title').textContent = (L ? L.pc.n : 'Horadric') + (n ? ` (${n} waiting)` : '');
  }
}

// The app icon's count of sessions waiting, as the pushes set it while the
// page is shut. Where the browser has no badge, nothing.
function renderBadge() {
  if (!navigator.setAppBadge) return;
  const n = state.links.reduce((t, L) => t + L.sessions.filter((s) => s.phase === 'waiting').length, 0);
  (n ? navigator.setAppBadge(n) : navigator.clearAppBadge()).catch(() => {});
}

// "All", then a tab per PC with a dot: lit once the relay has the PC and
// it answered hello. One PC needs no tabs, and only the list shows them.
// The buttons are kept and only changed, since a status that comes
// between a finger's down and up would otherwise lose the tap.
function renderTabs() {
  const bar = $('tabs');
  bar.hidden = !many() || state.view !== 'list';
  if (bar.hidden) return;
  const tabs = [{ id: 'all', label: 'All' }, ...state.links.map((L) => ({ id: L.pc.id, label: L.pc.n, L }))];
  if (bar.children.length !== tabs.length || tabs.some((t, i) => bar.children[i].dataset.id !== t.id)) {
    bar.replaceChildren(
      ...tabs.map((t) => {
        const b = el('button', 'tab');
        b.type = 'button';
        b.dataset.id = t.id;
        b.setAttribute('role', 'tab');
        if (t.L) b.append(el('i', 'lamp'));
        b.append(el('span'));
        b.onclick = () => pickTab(t.id);
        return b;
      }),
    );
  }
  tabs.forEach((t, i) => {
    const b = bar.children[i];
    const on = state.tab === t.id;
    b.classList.toggle('on', on);
    b.setAttribute('aria-selected', String(on));
    b.lastChild.textContent = t.label;
    if (t.L) {
      const live = t.L.link === 'online' && t.L.greeted;
      b.firstChild.className = 'lamp' + (live ? ' online' : '');
      b.title = live ? `${t.label} is online` : `${t.label} is not reached`;
    }
  });
}

function pickTab(id) {
  if (id !== 'all' && !linkOf(id)) id = 'all';
  if (state.tab !== id) state.adding = null;
  state.tab = id;
  try {
    localStorage.setItem('horadric.tab', id);
  } catch {}
  renderAll();
}

function storedTab() {
  try {
    return localStorage.getItem('horadric.tab') || 'all';
  } catch {
    return 'all';
  }
}

// What is about one PC (its tools, its pairing, its notifications) shows
// in its own tab, not in "All".
function renderAll() {
  const L = tabLink();
  $('listtools').hidden = !L;
  $('copylink').hidden = !L;
  $('forget').hidden = !L;
  $('empty').textContent = L ? 'No sessions on this PC.' : 'No sessions.';
  renderTabs();
  renderStatus();
  renderNote();
  renderTitle();
  renderList();
  renderPush();
}

const baseName = (p) => String(p).split(/[\\/]/).filter(Boolean).pop() || String(p);

// Every project the PCs know, each with its sessions, so a project with
// none can still get one. A session names its project by name or path.
// Over several PCs a project is one group by its name, as the stage
// shows it, and `starts` says which PCs can start a session in it.
function grouped(links = shownLinks()) {
  const groups = new Map();
  const merge = links.length > 1;
  const group = (key, name) => {
    if (!groups.has(key)) groups.set(key, { name, starts: [], list: [], order: Infinity });
    return groups.get(key);
  };
  for (const L of links) {
    const keyOf = new Map();
    L.projects.forEach((p, i) => {
      if (!p || !p.path) return;
      const name = p.name || baseName(p.path);
      const key = merge ? name.toLowerCase() : p.path;
      const g = group(key, name);
      g.starts.push({ L, path: p.path });
      g.order = Math.min(g.order, i);
      keyOf.set(p.path, key);
      if (p.name && !keyOf.has(p.name)) keyOf.set(p.name, key);
    });
    for (const s of L.sessions) {
      const raw = s.project || 'Other';
      const key = keyOf.get(raw) || (merge ? baseName(raw).toLowerCase() : raw);
      group(key, baseName(raw)).list.push(s);
    }
  }
  const rank = (s) => (s.paused ? 2.5 : { waiting: 0, working: 1, idle: 2, ended: 3 }[phaseOf(s)]);
  const best = (g) => (g.list.length ? Math.min(...g.list.map(rank)) : 9);
  for (const g of groups.values()) g.list.sort((a, b) => rank(a) - rank(b) || String(a.name).localeCompare(b.name));
  return [...groups.values()].sort((a, b) => {
    const r = best(a) - best(b);
    if (r) return r;
    if (a.order !== b.order) return a.order - b.order;
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
function pruneSent(L) {
  for (const [id, sent] of L.sent) {
    const s = L.sessions.find((x) => x.id === id);
    if (!s || phaseOf(s) !== 'waiting' || askSince(s) !== sent.since) L.sent.delete(id);
  }
}

function answer(s, opt) {
  const L = owner.get(s);
  if (!L) return;
  haptic('answer');
  L.sent.set(s.id, { label: opt.label, since: askSince(s) });
  send({ t: 'input', id: s.id, data: opt.keys }, L);
  renderInbox();
}

function card(s) {
  const L = owner.get(s);
  const ask = s.ask && typeof s.ask === 'object' ? s.ask : null;
  const c = el('article', 'card');
  const top = el('div', 'ctop');
  top.append(el('span', 'cproj', s.project ? baseName(s.project) : s.name || s.id));
  if (many() && !tabLink()) top.append(el('span', 'cpc', L.pc.n));
  const since = askSince(s);
  if (since) top.append(el('span', 'cage', ago(since)));
  c.append(top);
  const what = ask ? [ask.tool, ask.detail].filter(Boolean).join(': ') : '';
  c.append(el('div', 'cwhat', what || s.line || 'Waiting for you'));
  const row = el('div', 'cbtns');
  const sent = L.sent.get(s.id);
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
  open.onclick = () => watch(s.id, null, L);
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
  const links = shownLinks();
  const all = links.length > 1;
  if (!links.some((L) => L.listed) && links.some((L) => L.link === 'connecting' || L.link === 'online')) {
    $('groups').replaceChildren(...skeleton());
    $('empty').hidden = true;
    return;
  }
  const out = [];
  if (!all && links.length && links[0].take.length) out.push(takeSection(links[0]));
  for (const g of grouped(links)) {
    const sec = el('section', 'group');
    const head = el('div', 'ghead');
    head.append(el('h2', null, g.name));
    // A project on several PCs is started from the tab of the one meant.
    const start = g.starts.length === 1 ? g.starts[0] : null;
    if (start) {
      const plus = el('button', 'plus', '+');
      plus.setAttribute('aria-label', `New session in ${g.name}`);
      plus.disabled = !!start.L.starting || start.L.link !== 'online';
      plus.onclick = () => startIn(start.path, undefined, start.L);
      head.append(plus);
    }
    sec.append(head);
    const startingHere = g.starts.some(({ L, path }) => L.starting && L.starting.project === path);
    if (startingHere) {
      const row = el('div', 'sess starting');
      row.append(el('i', 'spinner'), el('div', 'what', 'Starting a session...'));
      sec.append(row);
    }
    for (const s of g.list) {
      const L = owner.get(s);
      const ph = phaseOf(s);
      const b = el('div', 'sess ' + ph + (s.paused ? ' paused' : ''));
      b.setAttribute('role', 'button');
      b.tabIndex = 0;
      const what = el('div', 'what');
      what.append(el('div', 'name', s.name || s.id), el('div', 'line', s.paused ? 'paused' : s.line || ph));
      b.append(el('i', 'lamp ' + (s.paused ? 'paused' : ph)), what);
      if (all) b.append(el('span', 'where', L.pc.n));
      if (s.paused) {
        const r = el('button', 'resume', 'Resume');
        r.onclick = (ev) => {
          ev.stopPropagation();
          resume(s.id, L);
        };
        b.append(r);
      }
      b.onclick = () => watch(s.id, null, L);
      holdable(b, () => openSheet(s.id, L));
      sec.append(b);
    }
    if (!g.list.length && !startingHere) sec.append(el('div', 'dim none', 'No sessions'));
    out.push(sec);
  }
  $('groups').replaceChildren(...out);
  $('empty').hidden = out.length > 0 || !links.some((L) => L.link === 'online');
}

// A silent brother's sessions, each with "Take over": the PC asks to
// have it handed to itself, which for a brother that does not answer is
// taking it over from what the PC keeps of it.
function takeSection(L) {
  const sec = el('section', 'group');
  const head = el('div', 'ghead');
  head.append(el('h2', null, 'Silent brothers'));
  sec.append(head);
  for (const s of L.take) {
    const b = el('div', 'sess paused');
    const what = el('div', 'what');
    const where = s.project ? `${s.project} · ` : '';
    what.append(el('div', 'name', s.name || s.id), el('div', 'line', where + (s.line || 'silent')));
    b.append(el('i', 'lamp paused'), what);
    const r = el('button', 'resume', L.taking === s.id ? 'Taking over...' : 'Take over');
    r.disabled = !!L.taking || L.link !== 'online';
    r.onclick = () => {
      L.taking = s.id;
      send({ t: 'handoff', id: s.id, to: s.to }, L);
      renderList();
    };
    b.append(r);
    sec.append(b);
  }
  return sec;
}

// Starting and resuming

// A note on whichever view is up, so an error is seen where it happened.
function say(text) {
  const note = { projects: $('pnote'), quests: $('qnote') }[state.view] || $('note');
  note.hidden = false;
  note.textContent = text;
}

// `ask` is the message that starts it: start in a known folder, or
// create a new one. `path` only marks where the spinner goes.
function startIn(path, ask = { t: 'start', project: path }, L = here()) {
  if (!L) return;
  const at = Date.now();
  L.starting = { project: path, at };
  $('pnote').hidden = true;
  renderList();
  renderFolders();
  send(ask, L);
  // A PC that never answers must not leave the spinner forever.
  setTimeout(() => {
    if (!L.starting || L.starting.at !== at) return;
    L.starting = null;
    renderList();
    renderFolders();
    tell(L, 'The PC did not start the session. Is its Horadric up to date?');
  }, 30000);
}

// Opening any project: the folders the PC's projects live in, so one
// that was not open on the PC can still be worked on.

function askFolders() {
  const L = here();
  const at = Date.now();
  askFolders.at = at;
  send({ t: 'folders' }, L);
  setTimeout(() => {
    if (askFolders.at !== at || !L || L.folders || state.view !== 'projects') return;
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
  const L = here();
  const r = ((L && L.folders) || []).find((x) => x.path === root);
  const lower = name.toLowerCase();
  if (r && (r.list || []).some((f) => String(f.name).toLowerCase() === lower)) return 'That folder exists. Open it from the list instead.';
  return '';
}

function renderFolders() {
  const L = here();
  if (!L) return;
  const roots = L.folders || [];
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

  if (!L.folders) {
    const wait = el('div', 'dim center', L.link === 'online' ? 'Asking the PC for its projects...' : 'Waiting for the PC...');
    $('folders').replaceChildren(wait);
    return;
  }
  const q = $('search').value.trim().toLowerCase();
  const busy = !!L.starting || L.link !== 'online';
  const out = [];
  for (const r of roots) {
    const list = (r.list || []).filter((f) => !q || String(f.name).toLowerCase().includes(q));
    const creating = L.starting && L.starting.root === r.path && !list.some((f) => f.path === L.starting.project);
    if (q && !list.length && !creating) continue;
    const sec = el('section', 'group root');
    sec.append(el('h2', null, r.name || baseName(r.path)), el('div', 'rpath', r.path));
    if (creating) {
      const row = el('div', 'sess starting');
      row.append(el('i', 'spinner'), el('div', 'what', 'Making the project...'));
      sec.append(row);
    }
    for (const f of list) {
      const busyHere = L.starting && L.starting.project === f.path;
      const row = el('div', 'sess folder' + (busyHere ? ' starting' : ''));
      row.setAttribute('role', 'button');
      row.tabIndex = 0;
      const what = el('div', 'what');
      what.append(el('div', 'name', f.name || baseName(f.path)));
      if (busyHere) what.append(el('div', 'line', 'Starting a session...'));
      row.append(busyHere ? el('i', 'spinner') : el('i', 'lamp'), what);
      if (f.git) row.append(el('span', 'git', 'git'));
      row.onclick = () => {
        if (!busy) startIn(f.path, undefined, L);
      };
      sec.append(row);
    }
    if (!list.length && !creating) sec.append(el('div', 'dim none', 'No folders'));
    out.push(sec);
  }
  if (!out.length) out.push(el('div', 'dim center', q ? 'No project matches.' : 'The PC knows no project folders yet.'));
  $('folders').replaceChildren(...out);
}

// Quests: each project's quest log and what Warriv does there. The phone
// reads them and adds to them; it does not drive anything yet.

function askQuests() {
  const L = here();
  const at = Date.now();
  askQuests.at = at;
  send({ t: 'quests' }, L);
  setTimeout(() => {
    if (askQuests.at !== at || !L || L.quests || state.view !== 'quests') return;
    say('The PC did not send its quests. Quests on the phone need Horadric 0.24 or later on the PC.');
  }, 8000);
}

function openQuests() {
  $('qnote').hidden = true;
  show('quests');
  history.pushState({ quests: true }, '');
  renderTitle();
  renderQuests();
  askQuests();
}

// What a quest's state reads as, and its lamp.
const QUEST = {
  open: ['Ready', ''],
  after: ['After', 'idle'],
  tangled: ['Tangled', 'blocked'],
  working: ['Working', 'working'],
  review: ['For review', 'review'],
  blocked: ['Blocked', 'blocked'],
};

// What the head of a project's log says about Warriv and the mode.
function warrivWords(log) {
  const w = log.warriv || {};
  const who = w.drives ? 'Warriv drives' : w.on ? 'Warriv is on' : '';
  const mode = { review: 'Review', warriv: 'Warriv reviews', auto: 'Auto' }[log.mode] || '';
  return [who, w.line, !w.drives && mode].filter(Boolean).join(' · ');
}

function renderQuests() {
  const L = here();
  if (!L) return;
  if (!L.quests) {
    const wait = el('div', 'dim center', L.link === 'online' ? 'Asking the PC for its quests...' : 'Waiting for the PC...');
    $('logs').replaceChildren(wait);
    return;
  }
  const out = [];
  for (const log of L.quests) {
    if (!log || !log.project) continue;
    const quests = Array.isArray(log.quests) ? log.quests : [];
    const sec = el('section', 'group log');
    const head = el('div', 'ghead');
    head.append(el('h2', null, log.name || baseName(log.project)));
    const plus = el('button', 'plus', '+');
    plus.setAttribute('aria-label', `New quest in ${log.name}`);
    plus.disabled = L.link !== 'online';
    plus.onclick = () => {
      state.adding = state.adding === log.project ? null : log.project;
      renderQuests();
      if (state.adding) $('qtitle').focus();
    };
    head.append(plus);
    sec.append(head);
    const words = warrivWords(log);
    if (words) sec.append(el('div', 'warriv' + (log.warriv && log.warriv.drives ? ' drives' : ''), words));
    if (state.adding === log.project) sec.append(addForm(log, L));
    for (const q of quests) sec.append(questRow(log, q, L));
    const done = Number(log.done) || 0;
    if (!quests.length) sec.append(el('div', 'dim none', done ? `All ${done} done` : 'No quests'));
    else if (done) sec.append(el('div', 'dim none', `${done} done`));
    out.push(sec);
  }
  if (!out.length) out.push(el('div', 'dim center', 'No projects on the PC.'));
  $('logs').replaceChildren(...out);
}

function questRow(log, q, L) {
  const [word, lamp] = QUEST[q.state] || [q.state || '', ''];
  const id = log.project + '\n' + q.title;
  const notes = Array.isArray(q.notes) ? q.notes : [];
  const row = el('div', 'sess quest ' + (q.state || ''));
  row.setAttribute('role', 'button');
  row.tabIndex = 0;
  const what = el('div', 'what');
  // The PC's why for a quest that waits on another says "after" already.
  const why = String(q.why || '');
  const line = !why ? word : q.state === 'after' ? why[0].toUpperCase() + why.slice(1) : `${word}: ${why}`;
  what.append(el('div', 'name', q.title), el('div', 'line', line));
  if (state.notesOpen.has(id)) what.append(el('div', 'notes' + (notes.length ? '' : ' dim'), notes.length ? notes.join('\n') : 'No notes'));
  row.append(el('i', 'lamp ' + lamp), what);
  // The session on it, which the phone can open like any other.
  const holder = q.session && L.sessions.find((s) => s.id === q.session);
  if (holder) {
    const go = el('button', 'resume', 'Open');
    go.setAttribute('aria-label', `Open ${holder.name}`);
    go.onclick = (ev) => {
      ev.stopPropagation();
      watch(holder.id, null, L);
    };
    row.append(go);
  }
  row.onclick = () => {
    if (!state.notesOpen.delete(id)) state.notesOpen.add(id);
    renderQuests();
  };
  return row;
}

// The form a project's + opens. It is made once and moved, so what is
// typed survives the re-renders an update from the PC causes.
function addForm(log, L) {
  const f = (addForm.el ||= makeAddForm());
  f.dataset.project = log.project;
  const sending = !!L.added;
  const b = f.querySelector('button');
  b.disabled = sending || L.link !== 'online';
  b.textContent = sending ? 'Adding...' : 'Add quest';
  return f;
}

function makeAddForm() {
  const f = el('form', 'create addquest');
  const title = el('input');
  title.id = 'qtitle';
  title.placeholder = 'Quest';
  title.maxLength = 200;
  title.autocomplete = 'off';
  title.setAttribute('enterkeyhint', 'next');
  const notes = el('textarea');
  notes.id = 'qnotes';
  notes.placeholder = 'Notes for the agent (optional)';
  notes.rows = 3;
  const add = el('button', 'pill', 'Add quest');
  add.type = 'submit';
  const hint = el('p', 'dim');
  hint.id = 'qhint';
  f.append(title, notes, add, hint);
  title.addEventListener('input', () => (hint.textContent = ''));
  f.onsubmit = (ev) => {
    ev.preventDefault();
    const t = title.value.trim().replace(/\s+/g, ' ');
    if (!t) {
      hint.className = 'dim bad';
      hint.textContent = 'Say what the quest is.';
      return;
    }
    const L = here();
    if (!L || L.added || L.link !== 'online') return;
    const project = f.dataset.project;
    const at = Date.now();
    L.added = { project, at };
    send({ t: 'quest_add', project, title: t, notes: notes.value }, L);
    haptic('send');
    hint.textContent = '';
    renderQuests();
    setTimeout(() => {
      if (!L.added || L.added.at !== at) return;
      L.added = null;
      renderQuests();
      say('The PC did not add the quest. Adding quests needs Horadric 0.24 or later on the PC.');
    }, 10000);
  };
  return f;
}

function resume(id, L = here()) {
  send({ t: 'resume', id }, L);
  watch(id, null, L);
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

// Notifications are turned on in a PC's own tab, since each PC signs its
// pushes with a key of its own.
function renderPush() {
  const b = $('notify');
  const hint = $('notifyhint');
  const L = tabLink();
  const vapid = L && L.vapid;
  const why = vapid ? pushSupport() : null;
  let text = why;
  let button = !!vapid && !why;
  if (button && Notification.permission === 'denied') {
    button = false;
    text = 'Notifications are blocked for this page in the browser settings.';
  } else if (button && Notification.permission === 'granted' && localStorage.getItem('horadric.push.' + L.pc.id) === vapid) {
    button = false;
    text = 'You get a notification when a session waits.';
  }
  b.hidden = !button;
  hint.hidden = !text;
  hint.textContent = text || '';
}

async function subscription(create, vapid) {
  const reg = await navigator.serviceWorker.ready;
  let sub = await reg.pushManager.getSubscription();
  const want = b64url(vapid);
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
  const L = tabLink();
  if (!L || !L.vapid) return;
  try {
    if ((await Notification.requestPermission()) === 'granted') {
      const sub = await subscription(true, L.vapid);
      if (sub && (await send({ t: 'push', sub: sub.toJSON() }, L))) {
        localStorage.setItem('horadric.push.' + L.pc.id, L.vapid);
      }
      // Every other PC that signs with the same key can push to it too.
      for (const o of state.links) if (o !== L) resendPush(o);
    }
    renderPush();
  } catch (e) {
    renderPush();
    $('notifyhint').hidden = false;
    $('notifyhint').textContent = 'Could not turn notifications on: ' + (e && e.message ? e.message : e);
  }
}

// Every PC is sent the subscription on every hello: the PC dedupes, so it
// costs little and heals a PC that lost it (a rekey, a new install). A PC
// whose key is not the one subscribed with could not push to it.
async function resendPush(L) {
  if (!L.vapid || pushSupport() || Notification.permission !== 'granted') return;
  try {
    const sub = await subscription(false, L.vapid);
    if (sub && (await send({ t: 'push', sub: sub.toJSON() }, L))) localStorage.setItem('horadric.push.' + L.pc.id, L.vapid);
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

// How far from the bottom still counts as following the output.
const NEAR = 40;
const atBottom = (wrap) => wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < NEAR;

// How many lines fell off the top between two frames. Once the PC's 500
// lines of scrollback are full, new output pushes old lines out, and
// matching the new first lines against the old ones finds by how many,
// so the rest keep their nodes instead of every line being redrawn.
function dropped(old, lines) {
  if (!old.length || !lines.length || old[0] === lines[0]) return 0;
  const run = Math.min(8, lines.length);
  for (let k = 1; k < old.length; k++) {
    let m = 0;
    while (m < run && k + m < old.length && old[k + m] === lines[m]) m++;
    if (m === run || (m > 0 && k + m === old.length)) return k;
  }
  return 0;
}

// The screen is one div per line, and a frame changes only the lines
// whose HTML differs, so a selection and the scroll position survive the
// four updates a second. The HTML of each shown line is kept here.
let shown = [];

function renderScreen() {
  const sc = state.screen;
  const pre = $('screen');
  const wrap = $('screenwrap');
  const follow = atBottom(wrap) || !renderScreen.seen;
  pre.style.fontSize = textSize() + 'px';
  // Whole pixel lines, since the browser rounds scrollTop and keeping the
  // view still adds up line heights a frame at a time.
  pre.style.lineHeight = Math.round(textSize() * 1.3) + 'px';
  const cols = Math.max(20, Math.floor((pre.clientWidth - 12) / cellWidth(pre)));
  if (sc) {
    // A PC before colours sends no styles, and its lines draw plain.
    const styles = sc.styles || [];
    const html = (sc.lines || []).map((l, i) => lineHtml(fitLine(cells(l, styles[i]), cols), styles[i]));
    if (!shown.length) pre.textContent = '';
    // Where the reader is looking, to put it back after the change.
    const anchor = follow ? null : firstVisible(pre, wrap);
    const offset = anchor ? anchor.getBoundingClientRect().top : 0;
    let lost = 0;
    const k = dropped(shown, html);
    for (let i = 0; i < k; i++) {
      lost += pre.firstChild.offsetHeight;
      pre.firstChild.remove();
    }
    shown = shown.slice(k);
    const rows = pre.children;
    html.forEach((h, i) => {
      if (i < shown.length) {
        if (shown[i] !== h) rows[i].innerHTML = h;
      } else {
        const div = document.createElement('div');
        div.innerHTML = h;
        pre.appendChild(div);
      }
    });
    while (rows.length > html.length) pre.lastChild.remove();
    shown = html;
    // Measured to the subpixel, since rounded offsets drift a pixel a frame.
    if (anchor && anchor.isConnected) wrap.scrollTop += anchor.getBoundingClientRect().top - offset;
    else if (!follow) wrap.scrollTop -= lost;
  } else {
    shown = [];
    pre.textContent = state.paused ? 'This session is paused.' : 'Waiting for the screen...';
  }
  $('resumebar').hidden = !state.paused;
  if (follow) wrap.scrollTop = wrap.scrollHeight;
  renderScreen.seen = true;
  renderLatest();
}

// What changed

// The watched session's changed files, from the PC's changes answer. A
// PC before 0.24 never answers, and the strip stays hidden.
function askChanges() {
  if (state.watching) send({ t: 'changes', id: state.watching });
}

function countsEl(f) {
  const span = el('span', 'counts');
  if (f.added == null) {
    span.append(el('span', 'dim', 'binary'));
    return span;
  }
  span.append(el('span', 'n-add', `+${f.added}`), ' ', el('span', 'n-del', `−${f.removed}`));
  return span;
}

function renderChanges() {
  const files = state.changes || [];
  $('changes').hidden = !files.length;
  if (!files.length) return;
  const sum = files.reduce((t, f) => ({ added: t.added + (f.added || 0), removed: t.removed + (f.removed || 0) }), { added: 0, removed: 0 });
  $('changecount').textContent = files.length === 1 ? '1 file changed' : `${files.length} files changed`;
  $('changelines').replaceChildren(...countsEl(sum).childNodes);
  $('changesum').setAttribute('aria-expanded', String(state.changesOpen));
  $('changes').classList.toggle('open', state.changesOpen);
  $('changelist').hidden = !state.changesOpen;
  $('changelist').replaceChildren(
    ...files.map((f) => {
      const b = el('button', 'file');
      const cut = f.path.lastIndexOf('/');
      const name = el('span', 'fname');
      if (cut >= 0) name.append(el('span', 'dir', f.path.slice(0, cut + 1)));
      name.append(el('b', null, f.path.slice(cut + 1)));
      b.append(name, countsEl(f));
      b.onclick = () => openDiff(f.path);
      return b;
    }),
  );
}

function openDiff(path) {
  if (!state.watching) return;
  state.diffPath = path;
  state.diff = null;
  state.diffError = null;
  show('diff');
  renderTitle();
  renderDiff();
  $('diff').scrollTop = 0;
  history.pushState({ session: state.watching, diff: path }, '');
  send({ t: 'diff', id: state.watching, path });
}

function closeDiff() {
  state.diffPath = null;
  state.diff = null;
  state.diffError = null;
  show('session');
  renderTitle();
  renderScreen();
  askChanges();
}

// The kind of a line of git's diff, for its colour. The file's own
// header is left out: the title already names the file.
function diffKind(line) {
  if (/^(diff --git|index |--- |\+\+\+ |new file mode|deleted file mode|old mode|new mode|similarity|rename )/.test(line)) return null;
  if (line.startsWith('@@')) return 'hunk';
  if (line.startsWith('+')) return 'add';
  if (line.startsWith('-')) return 'del';
  if (line.startsWith('\\')) return 'meta';
  if (line.startsWith(' ')) return 'ctx';
  // Anything else is git talking, such as "Binary files differ".
  return null;
}

function renderDiff() {
  const path = state.diffPath || '';
  const f = (state.changes || []).find((x) => x.path === path);
  $('diffpath').replaceChildren(el('span', 'dir', path), ...(f ? [countsEl(f)] : []));
  const body = $('diffbody');
  body.style.fontSize = textSize() + 'px';
  const d = state.diff;
  if (!d) {
    body.replaceChildren(el('p', 'dim center', state.diffError || 'Asking the PC...'));
    return;
  }
  const rows = [];
  for (const line of String(d.text || '').split('\n')) {
    const kind = diffKind(line);
    if (!kind) continue;
    if (kind === 'hunk') {
      // `@@ -12,7 +12,9 @@ fn name`: the new side's first line, then
      // the function git found it in.
      const m = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@ ?(.*)$/.exec(line);
      rows.push(el('div', 'dl hunk', m ? `Line ${m[1]}${m[2] ? '  ' + m[2] : ''}` : line));
      continue;
    }
    rows.push(el('div', 'dl ' + kind, kind === 'meta' ? line.slice(2) : line.slice(1) || ' '));
  }
  if (!rows.length) rows.push(el('p', 'dim center', /^Binary files/m.test(d.text || '') ? 'A binary file. Nothing to show as text.' : 'No changes in the text.'));
  if (d.cut) rows.push(el('p', 'dim center', 'Cut at 200 KB. The rest is on the PC.'));
  body.replaceChildren(...rows);
}

$('changesum').onclick = () => {
  state.changesOpen = !state.changesOpen;
  renderChanges();
  if (state.changesOpen) askChanges();
};

// The first line at least partly in view, found by halving since a long
// session has hundreds.
function firstVisible(pre, wrap) {
  const rows = pre.children;
  const top = wrap.scrollTop;
  let lo = 0;
  let hi = rows.length - 1;
  if (hi < 0) return null;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    const r = rows[mid];
    if (r.offsetTop + r.offsetHeight <= top) lo = mid + 1;
    else hi = mid;
  }
  return rows[lo];
}

function renderLatest() {
  $('latest').hidden = !state.screen || atBottom($('screenwrap'));
}

$('screenwrap').addEventListener('scroll', renderLatest, { passive: true });
$('latest').onclick = () => {
  const wrap = $('screenwrap');
  wrap.scrollTop = wrap.scrollHeight;
  renderLatest();
};

// Long press a session: rename, stop, copy its last reply

const HOLD_MS = 500;
const HOLD_SLOP = 10;

// The click a browser may send when a held finger lifts lands on whatever
// is under it by then, which is the sheet the hold opened. So after a hold
// the next click anywhere is eaten, until shortly after the finger is up.
const swallow = { holding: false, until: 0 };
document.addEventListener(
  'pointerup',
  () => {
    if (!swallow.holding) return;
    swallow.holding = false;
    swallow.until = Date.now() + 400;
  },
  true,
);
document.addEventListener(
  'click',
  (ev) => {
    if (!swallow.holding && Date.now() > swallow.until) return;
    swallow.holding = false;
    swallow.until = 0;
    ev.stopImmediatePropagation();
    ev.preventDefault();
  },
  true,
);

// Calls `fn` when `target` is held still for HOLD_MS. A right click does
// the same on a desktop, and Android's own long press arrives as
// contextmenu too.
function holdable(target, fn) {
  let timer = null;
  let from = null;
  let held = false;
  const cancel = () => {
    clearTimeout(timer);
    timer = null;
  };
  const fire = () => {
    cancel();
    held = true;
    swallow.holding = true;
    if (navigator.vibrate) navigator.vibrate(10);
    fn();
  };
  target.addEventListener('pointerdown', (ev) => {
    if (ev.button > 0) return;
    held = false;
    from = [ev.clientX, ev.clientY];
    cancel();
    timer = setTimeout(fire, HOLD_MS);
  });
  target.addEventListener('pointermove', (ev) => {
    if (timer && Math.hypot(ev.clientX - from[0], ev.clientY - from[1]) > HOLD_SLOP) cancel();
  });
  for (const t of ['pointerup', 'pointercancel', 'pointerleave']) target.addEventListener(t, cancel);
  target.addEventListener('contextmenu', (ev) => {
    ev.preventDefault();
    if (held) return;
    fire();
    // A right click has had its pointerup already, and sends no click.
    if (ev.button === 2 && !ev.sourceCapabilities?.firesTouchEvents) swallow.holding = false;
  });
}

// sheet: { id, L, mode: menu | rename | stop | reply, text, copied }
function openSheet(id, L) {
  if (!L || !L.sessions.some((s) => s.id === id)) return;
  if (state.sheet && state.sheet.id === id && state.sheet.L === L) return;
  state.sheet = { id, L, mode: 'menu' };
  renderSheet();
}

function closeSheet() {
  state.sheet = null;
  if (state.replyWait) {
    clearTimeout(state.replyWait.timer);
    state.replyWait.reject();
    state.replyWait = null;
  }
  $('sheet').hidden = true;
}

function sheetButton(label, cls, onclick) {
  const b = el('button', 'sheetbtn' + (cls ? ' ' + cls : ''), label);
  b.type = 'button';
  b.onclick = onclick;
  return b;
}

function renderSheet() {
  const sh = state.sheet;
  if (!sh) return closeSheet();
  const s = sh.L.sessions.find((x) => x.id === sh.id);
  if (!s) return closeSheet();
  const name = s.name || s.id;
  const online = sh.L.link === 'online';
  $('sheettitle').textContent = name;
  const body = [];
  if (sh.mode === 'menu') {
    const actions = [
      sheetButton('Rename', null, () => {
        sh.mode = 'rename';
        renderSheet();
      }),
      sheetButton('Copy last reply', null, copyReply),
      sheetButton('Stop', 'danger', () => {
        sh.mode = 'stop';
        renderSheet();
      }),
    ];
    for (const a of actions) a.disabled = !online;
    body.push(...actions);
  } else if (sh.mode === 'rename') {
    const form = el('form', 'sheetform');
    const input = el('input');
    input.id = 'rename';
    input.value = name;
    input.maxLength = 80;
    input.autocomplete = 'off';
    input.setAttribute('enterkeyhint', 'done');
    const save = sheetButton('Rename', 'gold');
    save.type = 'submit';
    form.append(input, el('p', 'dim', 'Leave it empty and Claude names it again.'), save);
    form.onsubmit = (ev) => {
      ev.preventDefault();
      rename(s.id, input.value.trim(), sh.L);
    };
    body.push(form);
    setTimeout(() => {
      input.focus();
      input.select();
    }, 50);
  } else if (sh.mode === 'stop') {
    body.push(
      el('p', 'sheettext', 'Stop this session? Its agent is ended on the PC and its tile goes, as closing its pane does.'),
      sheetButton('Stop session', 'danger', () => stopSession(s.id, sh.L)),
    );
  } else if (sh.mode === 'reply') {
    if (sh.none) {
      body.push(el('p', 'sheettext', sh.none));
    } else if (sh.text == null) {
      const row = el('div', 'sheetwait');
      row.append(el('i', 'spinner'), el('span', null, 'Getting the last reply...'));
      body.push(row);
    } else {
      body.push(el('pre', 'reply', sh.text));
      body.push(
        sheetButton(sh.copied ? 'Copied' : 'Copy', sh.copied ? 'done' : 'gold', async () => {
          sh.copied = await copyText(sh.text);
          renderSheet();
        }),
      );
    }
  }
  body.push(sheetButton(sh.mode === 'reply' ? 'Close' : 'Cancel', 'quiet', closeSheet));
  $('sheetbody').replaceChildren(...body);
  $('sheet').hidden = false;
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

// The reply comes over the network, after the tap's moment has passed,
// and Safari copies only within a tap. A ClipboardItem may hold a promise
// of its text, so the copy starts with the tap and finishes on the
// answer. Where that fails, the reply shows with a Copy button.
function copyReply() {
  const sh = state.sheet;
  sh.mode = 'reply';
  sh.text = null;
  sh.none = null;
  sh.copied = false;
  const { id, L } = sh;
  const answer = new Promise((resolve, reject) => {
    state.replyWait = {
      id,
      L,
      resolve,
      reject,
      timer: setTimeout(() => {
        state.replyWait = null;
        reject();
        if (state.sheet && state.sheet.id === id) {
          state.sheet.none = 'The PC did not answer. Copying a reply needs a newer Horadric on the PC.';
          renderSheet();
        }
      }, 8000),
    };
  });
  answer.catch(() => {});
  if (window.ClipboardItem && navigator.clipboard && navigator.clipboard.write) {
    const blob = answer.then((t) => (t == null ? Promise.reject() : new Blob([t], { type: 'text/plain' })));
    navigator.clipboard
      .write([new ClipboardItem({ 'text/plain': blob })])
      .then(() => {
        if (state.sheet && state.sheet.id === id) {
          state.sheet.copied = true;
          renderSheet();
        }
      })
      .catch(() => {});
  }
  send({ t: 'reply', id }, L);
  renderSheet();
}

function gotReply(L, msg) {
  const w = state.replyWait;
  if (!w || w.id !== msg.id || w.L !== L) return;
  clearTimeout(w.timer);
  state.replyWait = null;
  const text = typeof msg.text === 'string' && msg.text ? msg.text : null;
  w.resolve(text);
  const sh = state.sheet;
  if (!sh || sh.id !== msg.id) return;
  if (text == null) sh.none = 'This session has no reply yet.';
  sh.text = text;
  renderSheet();
}

// An older PC ignores these, so the page says so if nothing comes of them.
function rename(id, name, L) {
  closeSheet();
  send({ t: 'rename', id, name }, L);
  if (!name) return;
  setTimeout(() => {
    const s = L.sessions.find((x) => x.id === id);
    if (s && s.name !== name) say('The PC did not rename it. Renaming from the phone needs a newer Horadric on the PC.');
  }, 6000);
}

function stopSession(id, L) {
  closeSheet();
  send({ t: 'stop', id }, L);
  if (state.watching === id && state.wlink === L) history.back();
  setTimeout(() => {
    if (L.sessions.some((x) => x.id === id)) say('The PC did not stop it. Stopping from the phone needs a newer Horadric on the PC.');
  }, 8000);
}

holdable($('title'), () => state.watching && openSheet(state.watching, state.wlink));
$('sheet').addEventListener('click', (ev) => {
  if (ev.target === $('sheet')) closeSheet();
});
document.addEventListener('keydown', (ev) => {
  if (ev.key === 'Escape' && state.sheet) closeSheet();
});

// Navigation

// The sessions of the project the open one belongs to, in the list's order.
function siblings() {
  const g = grouped().find((x) => x.list.some((s) => s.id === state.watching && owner.get(s) === state.wlink));
  return g ? g.list : [];
}

// One dot per session of the project, the open one lit. Shown only when
// there is somebody to swipe to.
function renderDots() {
  const list = state.watching ? siblings() : [];
  const box = $('dots');
  box.hidden = list.length < 2;
  box.replaceChildren(...list.map((s) => el('i', s.id === state.watching && owner.get(s) === state.wlink ? 'on' : '')));
}

// The screen slides in from the side the swipe came from.
function swipeIn(way) {
  const box = $('screenbox');
  box.classList.remove('swipe-next', 'swipe-prev');
  if (still.matches) return;
  void box.offsetWidth;
  box.classList.add(way === 'next' ? 'swipe-next' : 'swipe-prev');
}

// A horizontal swipe on the screen goes to the next or previous session of
// the project. Two fingers are the pinch's, and a mostly vertical move is
// scrolling.
const swipe = { x: 0, y: 0, live: false };
$('screenwrap').addEventListener('touchstart', (ev) => {
  swipe.live = ev.touches.length === 1;
  if (swipe.live) [swipe.x, swipe.y] = [ev.touches[0].clientX, ev.touches[0].clientY];
}, { passive: true });
$('screenwrap').addEventListener('touchmove', (ev) => {
  if (ev.touches.length > 1) swipe.live = false;
}, { passive: true });
$('screenwrap').addEventListener('touchend', (ev) => {
  if (!swipe.live || ev.changedTouches.length !== 1) return;
  swipe.live = false;
  const dx = ev.changedTouches[0].clientX - swipe.x;
  const dy = ev.changedTouches[0].clientY - swipe.y;
  if (Math.abs(dx) < 70 || Math.abs(dx) < 2 * Math.abs(dy)) return;
  // Selecting text is not a swipe.
  if (String(getSelection()).length) return;
  const list = siblings();
  const at = list.findIndex((s) => s.id === state.watching && owner.get(s) === state.wlink);
  const to = list[at + (dx < 0 ? 1 : -1)];
  if (to) watch(to.id, dx < 0 ? 'next' : 'prev', owner.get(to));
});

// How deep a view sits, so going deeper slides in from the right and back
// slides the other way.
const DEPTH = { unpaired: 0, list: 0, projects: 1, quests: 1, session: 1, diff: 2 };
const still = matchMedia('(prefers-reduced-motion: reduce)');

function show(view) {
  const from = state.view;
  state.view = view;
  const leaving = from !== view && !$(from).hidden ? $(from) : null;
  // Measured while it still shows, since hidden it has no size.
  const where = leaving && leaving.getBoundingClientRect();
  for (const v of ['unpaired', 'list', 'projects', 'quests', 'session', 'diff']) $(v).hidden = v !== view;
  $('back').hidden = DEPTH[view] === 0;
  renderTabs();
  renderStatus();
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
    // The body is the leaving view's frame, since it is moved to where
    // the keyboard left the page, so the top is measured from it.
    out.style.top = where.top - document.body.getBoundingClientRect().top + 'px';
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

// Opens a session on the PC that listed it. One session is watched at a
// time over all the PCs, so watching on another PC stops the one before.
function watch(id, way, L = here()) {
  if (!L) return;
  const again = state.watching === id && state.wlink === L;
  // A session started from the projects view takes that view's place in
  // history, so back goes to the session list.
  const swap = (state.watching && !again) || state.view === 'projects' || state.view === 'quests';
  if (state.wlink && state.wlink !== L) send({ t: 'unwatch' }, state.wlink);
  state.wlink = L;
  state.watching = id;
  state.screen = null;
  state.paused = false;
  if (!again) {
    state.changes = null;
    state.changesOpen = false;
    const s = L.sessions.find((x) => x.id === id);
    state.watchedPhase = s ? s.phase : null;
  }
  renderScreen.seen = false;
  show('session');
  renderTitle();
  renderScreen();
  send({ t: 'watch', id }, L);
  renderChanges();
  askChanges();
  if (way) swipeIn(way);
  // One history entry for the session view, whichever session it shows.
  if (swap) history.replaceState({ session: id }, '');
  else if (!again) history.pushState({ session: id }, '');
}

function clearWatch() {
  state.wlink = null;
  state.watching = null;
  state.paused = false;
  state.screen = null;
  state.changes = null;
  state.diffPath = null;
  state.diff = null;
}

function unwatch() {
  if (!state.watching) return;
  send({ t: 'unwatch' }, state.wlink);
  clearWatch();
  show('list');
  renderTitle();
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
  if (state.view === 'diff') return closeDiff();
  if (state.watching) return unwatch();
  if (state.view === 'projects' || state.view === 'quests') {
    show('list');
    renderTitle();
  }
});

$('openproject').onclick = openProjects;
$('openquests').onclick = openQuests;
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
  const L = here();
  if (!L || L.starting || L.link !== 'online') return;
  $('pname').value = '';
  $('create').hidden = true;
  startIn(root + sepOf(root) + name, { t: 'create', root, name }, L);
  L.starting.root = root;
  renderFolders();
};

$('forget').onclick = () => {
  const L = tabLink();
  if (!L || !confirm(`Forget ${L.pc.n}? You will need its pairing link again.`)) return;
  savePcs(loadPcs().filter((p) => p.id !== L.pc.id));
  try {
    localStorage.setItem('horadric.tab', 'all');
  } catch {}
  refresh();
};

// On iOS a home screen app keeps storage of its own, and the camera opens
// links only in the browser, so a pairing has to be carried over by hand.
$('copylink').onclick = async () => {
  const L = tabLink();
  if (!L) return;
  try {
    await navigator.clipboard.writeText(linkFor(L.pc));
    $('copylink').textContent = 'Copied. Paste it in the home screen app.';
  } catch {
    prompt('Copy this pairing link:', linkFor(L.pc));
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

// iOS lays the keyboard over the page instead of shrinking it, and pans
// the page to bring the input into view, so the keys and the screen's last
// lines end up under the keyboard. The page is sized to the part of the
// screen that is still visible instead, and moved to wherever iOS panned.
// A screen that showed its bottom line before keeps showing it after.
let stuck = true;
$('screenwrap').addEventListener('scroll', () => {
  const w = $('screenwrap');
  stuck = w.scrollHeight - w.scrollTop - w.clientHeight < 40;
}, { passive: true });

function fitViewport() {
  const vv = window.visualViewport;
  if (!vv) return;
  const root = document.documentElement.style;
  // A page the user zoomed in on is left to the browser to pan.
  const zoomed = vv.scale > 1.01;
  root.setProperty('--vvh', zoomed ? '' : vv.height + 'px');
  root.setProperty('--vvtop', zoomed ? '' : vv.offsetTop + 'px');
  document.body.classList.toggle('kb', !zoomed && window.innerHeight - vv.height > 120);
  if (stuck) {
    const w = $('screenwrap');
    w.scrollTop = w.scrollHeight;
  }
}

if (window.visualViewport) {
  visualViewport.addEventListener('resize', fitViewport);
  visualViewport.addEventListener('scroll', fitViewport);
  fitViewport();
}

// Start

// The links and the page follow the paired PCs. A PC already connected
// keeps its connection, so a notification's link on a page that is up
// costs nothing.
function refresh() {
  syncLinks();
  if (!state.links.length) {
    closeSheet();
    clearWatch();
    show('unpaired');
    return;
  }
  // The first time, nothing shows yet.
  if (state.view === 'unpaired' || !refresh.shown) show('list');
  refresh.shown = true;
  pickTab(storedTab());
}

// A pairing link opened on a page that is already up only changes the
// fragment, so take it then too.
function pairFromLink() {
  takeFragment();
  refresh();
  openFromPush();
}

// Shows the session a notification was about, on its PC when this phone
// knows that PC. The watch goes out once connected, as after any hello,
// and a held answer at once when that PC has listed its sessions already.
function openFromPush() {
  const open = state.open;
  state.open = null;
  if (!open || !state.links.length) return;
  const L = (open.pc && linkOf(open.pc)) || state.links.find((x) => x.sessions.some((s) => s.id === open.id)) || here() || state.links[0];
  watch(open.id, null, L);
  if (L.listed) sendHeldAnswer(L);
}
window.addEventListener('hashchange', pairFromLink);
pairFromLink();

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
  // A notification clicked while the page is open.
  navigator.serviceWorker.addEventListener('message', (ev) => {
    const d = ev.data || {};
    if (d.t !== 'open' || typeof d.id !== 'string') return;
    state.open = { id: d.id, pc: typeof d.pc === 'string' ? d.pc : '' };
    if (d.answer) holdAnswer(state.open, d.answer);
    openFromPush();
  });
}
