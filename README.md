# Horadric Town Portal

The relay and the phone page that let you reach
[Horadric](https://github.com/Mopra/horadric.dev) from your phone: see
every agent session on your PC, read its screen, answer it.

- **The page** is a PWA at <https://portal.horadric.dev>. Add it to your
  home screen.
- **The relay** joins a phone to its PC. Both connect out to it over
  WebSocket, so nothing on your PC or router is opened. It passes frames
  along without reading them: everything is encrypted end to end with
  AES-256-GCM, with a key of each phone's own that lives only on your PC
  and in that phone's browser. It keeps nothing on disk.

The protocol is [docs/PORTAL.md](https://github.com/Mopra/horadric.dev/blob/main/docs/PORTAL.md)
in the Horadric repo.

## Pairing

On the PC, run `horadric portal`. It shows a QR code; scan it with your
phone. The code works once, for 5 minutes, and the phone trades it for a
key of its own. `horadric portal phones` lists the paired phones and
`horadric portal forget N` cuts one off.

## Brothers

A PC signed in with WorkOS is told which of the same user's PCs are
connected, its brothers, and can open a channel to one to ask to join.
The relay checks the WorkOS access token and routes; the approval and
the keys are end to end between the two PCs. It knows only who is
connected now and keeps nothing on disk.

`/pc?secret=<secret>&token=<WorkOS access token>&name=<PC name, URI encoded>`.
Without `token` the PC is a v2 PC, served exactly as before, and
`name` is ignored.

The token is an RS256 JWT, checked with Node's own `crypto` against the
keys at `https://api.workos.com/sso/jwks/<client id>` (`WORKOS_CLIENT_ID` may list several, comma separated: production for installs, staging for dev instances; the token's `client_id` picks one) (cached, and
fetched again for an unknown key id at most every 10 seconds). It must
not be expired (5 seconds of slack), its `iss` must be
`https://api.workos.com/user_management/<client id>`, or one of
`WORKOS_ISSUER` (comma separated) when set, a `client_id` claim must be
ours, and `sub` is the user. A refused token closes the socket at once:

- `4401` with the reason (`token expired`, `wrong issuer`, `bad signature`,
  ...): sign in again.
- `4503` (`cannot reach WorkOS`, `sign in is not set up on this relay`,
  or a key id the relay may not have fetched yet): the token may be fine,
  try again later as is.

Relay to a signed in PC, text:

- `{"brothers":[{"id":"<pc id>","name":"<name>"}]}`: the user's other
  connected PCs, sorted by id. Sent on connect and whenever one comes,
  goes or reconnects. `id` is the 32 hex PC id, as a phone knows it.
- `{"join":<ch>,"id":"<pc id>","name":"<name>"}`: a brother asks to join
  and the relay opened channel `<ch>` to it.
- `{"link":<ch>,"id":"<pc id>","name":"<name>"}`: the answer to this PC's
  own join request, the channel on its side.
- `{"close":<ch>}`: the other end closed the channel or went away.
- `{"error":"not signed in"|"no such brother"|"too many links","to":"<pc id>"}`:
  a join request that went nowhere. Another user's PC is "no such brother".

PC to relay, text:

- `{"join":{"to":"<pc id>"}}`: open a channel to that brother.
- `{"close":<ch>}`: close a brother channel.

Binary on a brother channel is framed as for phones (4 bytes big endian
channel, then the payload) and arrives at the other PC with its own
channel number. Phone and brother channels share one number space per PC,
never 0 or 0xFFFFFFFF, and broadcast (0xFFFFFFFF) still goes to phones
only. A PC holds at most 16 brother channels. They close when either
side sends `close` or disconnects (a reconnect too).

## Run your own relay

You do not have to trust ours. The relay is one small Node program:

```sh
npm ci --omit=dev
HOST=0.0.0.0 PORT=43200 WORKOS_CLIENT_ID=client_01M5NBZGDSBPJMPR5BSJQ9ASEA node server.js
```

Put it behind anything that terminates TLS (Caddy, Traefik, nginx), so it
is reachable as `wss://your.host`, and set `"relay": "wss://your.host"` in
Horadric's `portal.json`. It serves the page too, at the same address.

`deploy.sh` is how we deploy ours: a systemd unit and a Traefik route,
in `deploy/`.

## Developing

```sh
npm test                      # framing, id hashing, tokens, brothers
node server.js                # a relay on 127.0.0.1:43200
node test/fakepc.js           # a stand-in PC; prints a pairing link to open
```

MIT licensed.
