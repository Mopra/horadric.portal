// Keeps the page openable without a network, and always prefers a fresh
// copy when there is one, so an update reaches the phone at once.
const CACHE = 'horadric-portal-v11';
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

self.addEventListener('push', (ev) => {
  const d = payload(ev);
  const shown = d
    ? self.registration.showNotification(d.title, {
        body: typeof d.body === 'string' ? d.body : '',
        tag: 'horadric-' + d.id,
        renotify: true,
        icon: '/icon.png',
        badge: '/icon.png',
        data: { id: d.id, pc: typeof d.pc === 'string' ? d.pc : '' },
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

// Opens the page on the session the notification is about. A page already
// open is told, since navigating it would cost its connection.
self.addEventListener('notificationclick', (ev) => {
  ev.notification.close();
  const d = ev.notification.data || {};
  const url = d.id ? '/#' + new URLSearchParams({ s: d.id, pc: d.pc || '' }) : '/';
  ev.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      const mine = list.find((c) => new URL(c.url).origin === location.origin);
      if (!mine) return self.clients.openWindow(url);
      if (d.id) mine.postMessage({ t: 'open', id: d.id, pc: d.pc || '' });
      return mine.focus();
    }),
  );
});
