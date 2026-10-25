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
  and in that phone's browser. On disk it keeps only when it first saw
  each signed in PC id (see Brothers).

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
the keys are end to end between the two PCs. It knows who is connected
now, and remembers when it first saw each of a user's PC ids.

`/pc?name=<PC name, URI encoded>`, with the request headers
`X-Horadric-Secret: <secret>` and `Authorization: Bearer <WorkOS access
token>`. What proves a PC is never in the address, where a proxy's access
log would keep it. Without a token the PC is a v2 PC, served exactly as
before, and `name` is ignored. A signed in PC that can hand the relay a
fresh token on the open socket says so with `X-Horadric-Refresh: 1` (see
Fresh tokens below).

Horadric 0.32 and older send `/pc?secret=..&token=..&name=..` instead.
The relay takes that until 2027-01-01 (`QUERY_UNTIL` in `relay.js`), and
only when no `X-Horadric-Secret` header came; after it, such a PC is
answered 400. A phone's `/phone?id=<pc id>` carries no secret: the id is
a hash of it, public as an address is, and the phone's frames are sealed
with its own key.

One user may have 16 machines connected at once. At that cap the machines
the relay has known longest win: it remembers when it first saw each of a
user's PC ids (when its token was accepted), at most 64 per user,
forgetting the youngest one not connected past that. One
more PC takes the place of the youngest connected one when the relay saw
it first, and that one is closed with `4429` (`too many machines`);
otherwise the newcomer is closed with `4429` and tries again later. So a
stolen login opening sockets with made up secrets cannot shut out the
user's real machines, only ones newer than its own. Those times are kept
across restarts in `first-seen.json` in `STATE_DIR` (default `state/`
next to `server.js`; ours is `/var/lib/horadric-portal`): only WorkOS
user ids, PC ids and times, nothing secret. It is written a few seconds
after a change and at shutdown, to a fresh temp file (mode 0600, one left
by a crash removed first) that is flushed to disk, renamed over and the
directory flushed, so a restart no longer makes every id new. A user not
seen for 90 days is forgotten, and past 10,000 users the ones seen
longest ago go first (a connected one never), so the file stays bounded. A missing or unreadable file starts the relay
empty, with a line in its log; then every id is new and the order of
reconnecting decides until the cap fills. One address may hold
32 PCs open, counted from the upgrade on; one more is answered 429. Behind
our proxy (`TRUST_PROXY=1`) the address is the one Traefik puts in
`X-Real-Ip`.

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

### Fresh tokens

A WorkOS access token lasts minutes, far less than a PC stays connected,
so a PC that dialled with `X-Horadric-Refresh: 1` hands the relay a fresh
one on the open socket before its current one expires (Horadric does it
45 seconds before `exp`, and keeps its old expiry until `ok` comes), as a
text frame:

- PC to relay: `{"token":"<fresh WorkOS access token>"}`.
- Relay to PC: `{"token":"ok","exp":<exp>}` when it is accepted: checked
  as at connect, and for the same WorkOS user (`sub`) as the socket. The
  socket's expiry moves to the new `exp`.
- `{"token":"refused","why":"<reason>"}`: not accepted (`another user`,
  `token expired`, `bad signature`, ...). The socket stays, on its old
  expiry, and may try again before it.
- `{"token":"later"}`: the token could not be checked now (WorkOS
  unreachable, a key id not fetched yet), or one is still being checked
  for this socket. Try again soon.

A signed in socket is closed with `4401` and `token expired` once its
`exp` is more than 120 seconds past with no fresh token accepted, so a
token taken from a PC holds a socket open minutes, not for as long as it
likes. Only a signed in PC that did not send the header and whose id
the relay first saw before it began asking for refreshes (Horadric 0.34
and older; the moment is `legacyBefore` in the state file, set on the
relay's first start with this rule) is never closed for its token before
`QUERY_UNTIL`, 2027-01-01; from then on the same rule holds for it. A
new id without the header is held to the rule at once, so leaving the
header out buys a stolen token nothing. A v2 PC without a token is
never closed for expiry, and its `{"token":...}` frames are dropped. A
`{"token":...}` frame is never passed on to a phone or a brother. The
relay checks expiries in one sweep every 10 seconds.

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
- `{"token":"<access token>"}`: a fresh token, see Fresh tokens.

Binary on a brother channel is framed as for phones (4 bytes big endian
channel, then the payload) and arrives at the other PC with its own
channel number. Phone and brother channels share one number space per PC,
never 0 or 0xFFFFFFFF, and broadcast (0xFFFFFFFF) still goes to phones
only. A PC holds at most 16 brother channels. They close when either
side sends `close` or disconnects (a reconnect too).

A frame's payload may be at most 1 MiB (`MAX_FRAME`), from a phone, a PC
to its phones or a PC to a brother. A larger one is dropped, not passed
on, and the socket stays open, so one too large message never takes a
machine's link and its phones down with it. A message over 4 MiB
(`HARD_FRAME`) closes the socket with `1009`, which bounds the memory
one costs.

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
