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

## Run your own relay

You do not have to trust ours. The relay is one small Node program:

```sh
npm ci --omit=dev
HOST=0.0.0.0 PORT=43200 node server.js
```

Put it behind anything that terminates TLS (Caddy, Traefik, nginx), so it
is reachable as `wss://your.host`, and set `"relay": "wss://your.host"` in
Horadric's `portal.json`. It serves the page too, at the same address.

`deploy.sh` is how we deploy ours: a systemd unit and a Traefik route,
in `deploy/`.

## Developing

```sh
npm test                      # the framing and id hashing
node server.js                # a relay on 127.0.0.1:43200
node test/fakepc.js           # a stand-in PC; prints a pairing link to open
```

MIT licensed.
