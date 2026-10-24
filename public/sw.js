// Keeps the page openable without a network, and always prefers a fresh
// copy when there is one, so an update reaches the phone at once.
const CACHE = 'horadric-portal-v18';
const SHELL = ['/', '/index.html', '/app.js', '/style.css', '/manifest.webmanifest', '/icon.png', '/icon-256.png'];

self.addEventListener('install', (ev) => {
  ev.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (ev) => {
  ev.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (ev) => {
  const req = ev.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== location.origin) return;
  ev.respondWith(
    fetch(req)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy));
        return res;
      })
      .catch(() => caches.match(req, { ignoreSearch: true }).then((r) => r || caches.match('/index.html'))),
  );
});

// A push from a PC before 0.24 carries no body, so it only ever means one
// thing. A newer PC sends {pc, id, project, title, body, waiting},
// encrypted for this browser alone, which the browser has opened by now.
function payload(ev) {
  try {
    const d = ev.data && ev.data.json();
    return d && typeof d.title === 'string' && typeof d.id === 'string' ? d : null;
  } catch {
    return null;
  }
}

// Up to two answers the push offers, {label, keys}, shown as the
// notification's buttons where the browser has them. An older PC sends
// none.
function options(d) {
  const list = Array.isArray(d.options) ? d.options : [];
  return list.filter((o) => o && typeof o.label === 'string' && o.label && typeof o.keys === 'string').slice(0, 2);
}

self.addEventListener('push', (ev) => {
  const d = payload(ev);
  const answers = d ? options(d) : [];
  const shown = d
    ? self.registration.showNotification(d.title, {
        body: typeof d.body === 'string' ? d.body : '',
        tag: 'horadric-' + d.id,
        renotify: true,
        icon: '/icon.png',
        badge: '/icon.png',
        actions: answers.map((o, i) => ({ action: String(i), title: o.label })),
        data: {
          id: d.id,
          pc: typeof d.pc === 'string' ? d.pc : '',
          options: answers,
          since: Number.isFinite(d.since) ? d.since : 0,
        },
      })
    : self.registration.showNotification('Horadric', {
        body: 'A session waits for you',
        tag: 'horadric-wait',
        renotify: true,
        icon: '/icon.png',
        badge: '/icon.png',
      });
  const badge =
    d && Number.isFinite(d.waiting) && self.navigator.setAppBadge
      ? self.navigator.setAppBadge(d.waiting).catch(() => {})
      : null;
  ev.waitUntil(Promise.all([shown, badge]));
});

// Opens the page on the session the notification is about, with the
// answer when one of its buttons was tapped: `a` the keys to type, `l` the
// label, `w` when the wait began, so the page sends it only to that wait.
// A page already open is told, since navigating it would cost its
// connection.
self.addEventListener('notificationclick', (ev) => {
  ev.notification.close();
  const d = ev.notification.data || {};
  const picked = ev.action && Array.isArray(d.options) ? d.options[Number(ev.action)] : null;
  const open = { s: d.id, pc: d.pc || '' };
  if (picked) Object.assign(open, { a: picked.keys, l: picked.label, w: String(d.since || 0) });
  const url = d.id ? '/#' + new URLSearchParams(open) : '/';
  ev.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      const mine = list.find((c) => new URL(c.url).origin === location.origin);
      if (!mine) return self.clients.openWindow(url);
      if (d.id) {
        const msg = { t: 'open', id: d.id, pc: d.pc || '' };
        if (picked) msg.answer = { keys: picked.keys, label: picked.label, since: d.since || 0 };
        mine.postMessage(msg);
      }
      return mine.focus();
    }),
  );
});
