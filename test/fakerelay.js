// A relay whose sign in is made up, to try pairing by signing in without
// WorkOS: node test/fakerelay.js [port]. Sign in comes straight back with
// a code for the user "user_fake", and a PC is signed in as that user by
// the token "fake:user_fake" (test/fakepc.js sends it with FAKE_TOKEN).
'use strict';
const { createRelay } = require('../server');
const { AuthError } = require('../auth');

const port = Number(process.argv[2]) || 43200;
const origin = `http://127.0.0.1:${port}`;

const verify = async (token) => {
  const m = /^fake:(.+)$/.exec(token || '');
  if (!m) throw new AuthError('not a fake token');
  return { sub: m[1], exp: Math.floor(Date.now() / 1000) + 3600 };
};
const workosFetch = async (url, body) => {
  if (body.code !== 'fake-code') throw new AuthError('Invalid authorization code');
  return { access_token: 'fake:user_fake', user: { id: 'user_fake', email: 'you@example.com' } };
};

const relay = createRelay({ verify, workosFetch, pageClient: 'client_fake', origin, authorizeUrl: `${origin}/fake-authorize` });
const [serve] = relay.listeners('request');
relay.removeAllListeners('request');
relay.on('request', (req, res) => {
  const url = new URL(req.url, origin);
  if (url.pathname !== '/fake-authorize') return serve(req, res);
  const back = new URLSearchParams({ code: 'fake-code', state: url.searchParams.get('state') || '' });
  res.writeHead(302, { location: `${url.searchParams.get('redirect_uri')}?${back}` });
  res.end();
});
relay.listen(port, '127.0.0.1', () => console.log(`fake sign in relay on ${origin}`));
