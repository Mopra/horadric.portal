// Keeps the page openable without a network, and always prefers a fresh
// copy when there is one, so an update reaches the phone at once.
const CACHE = 'horadric-portal-v2';
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

// A push carries no body: the PC sends nothing a push service could read.
// It only ever means one thing.
self.addEventListener('push', (ev) => {
  ev.waitUntil(
    self.registration.showNotification('Horadric', {
      body: 'A session waits for you',
      tag: 'horadric-wait',
      renotify: true,
      icon: '/icon.png',
      badge: '/icon.png',
    }),
  );
});

self.addEventListener('notificationclick', (ev) => {
  ev.notification.close();
  ev.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      const mine = list.find((c) => new URL(c.url).origin === location.origin);
      return mine ? mine.focus() : self.clients.openWindow('/');
    }),
  );
});
