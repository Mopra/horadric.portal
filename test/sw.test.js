// The service worker's push and click handlers, run in a stand-in for the
// worker's global scope: what a push shows, the badge, and where a click
// goes.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'sw.js'), 'utf8');

function worker({ clients = [], badge = true } = {}) {
  const handlers = {};
  const seen = { shown: [], badges: [], opened: [], posted: [], focused: 0 };
  // Objects made inside the worker's context have its prototypes.
  const plain = (o) => JSON.parse(JSON.stringify(o));
  const self = {
    addEventListener: (t, f) => (handlers[t] = f),
    registration: {
      showNotification: async (title, opts) => seen.shown.push(plain({ title, ...opts })),
    },
    navigator: badge ? { setAppBadge: async (n) => seen.badges.push(n) } : {},
    clients: {
      matchAll: async () =>
        clients.map((url) => ({
          url,
          postMessage: (m) => seen.posted.push(plain(m)),
          focus: async () => seen.focused++,
        })),
      openWindow: async (url) => seen.opened.push(url),
    },
  };
  vm.runInNewContext(source, { self, location: new URL('https://portal.horadric.dev/sw.js'), URL, URLSearchParams, caches: {}, fetch });
  const fire = async (type, ev) => {
    let wait;
    handlers[type]({ ...ev, waitUntil: (p) => (wait = p) });
    await wait;
  };
  return { seen, fire };
}

const push = (body) => ({
  data: body === undefined ? null : { json: () => (typeof body === 'string' ? JSON.parse(body) : body) },
});

test('a push with a payload says what waits, tagged by session, and sets the badge', async () => {
  const w = worker();
  await w.fire('push', push({ pc: 'p1', id: 's9', project: 'horadric', title: 'Allow Bash?', body: 'horadric · ui', waiting: 3 }));
  assert.strictEqual(w.seen.shown.length, 1);
  const n = w.seen.shown[0];
  assert.strictEqual(n.title, 'Allow Bash?');
  assert.strictEqual(n.body, 'horadric · ui');
  assert.strictEqual(n.tag, 'horadric-s9');
  assert.deepStrictEqual(n.data, { id: 's9', pc: 'p1' });
  assert.deepStrictEqual(w.seen.badges, [3]);
});

test('a push without a body, or one not understood, shows the old text', async () => {
  for (const body of [undefined, 'not json', { hello: 1 }]) {
    const w = worker();
    await w.fire('push', push(body));
    assert.strictEqual(w.seen.shown[0].title, 'Horadric');
    assert.strictEqual(w.seen.shown[0].body, 'A session waits for you');
    assert.strictEqual(w.seen.shown[0].tag, 'horadric-wait');
    assert.deepStrictEqual(w.seen.badges, []);
  }
});

test('a browser without badges still shows the push', async () => {
  const w = worker({ badge: false });
  await w.fire('push', push({ id: 's1', title: 'Waiting for you', waiting: 1 }));
  assert.strictEqual(w.seen.shown.length, 1);
});

const click = (data) => ({ notification: { data, close() {} } });

test('a click with no page open opens it on the session', async () => {
  const w = worker();
  await w.fire('notificationclick', click({ id: 's9', pc: 'p1' }));
  assert.deepStrictEqual(w.seen.opened, ['/#s=s9&pc=p1']);
});

test('a click with the page open tells it and focuses it', async () => {
  const w = worker({ clients: ['https://portal.horadric.dev/'] });
  await w.fire('notificationclick', click({ id: 's9', pc: 'p1' }));
  assert.deepStrictEqual(w.seen.opened, []);
  assert.deepStrictEqual(w.seen.posted, [{ t: 'open', id: 's9', pc: 'p1' }]);
  assert.strictEqual(w.seen.focused, 1);
});

test('a click on an old push opens the page as before', async () => {
  const w = worker();
  await w.fire('notificationclick', click(undefined));
  assert.deepStrictEqual(w.seen.opened, ['/']);
});
