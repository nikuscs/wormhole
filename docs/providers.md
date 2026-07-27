# Provider drivers

Wormhole can publish one service through multiple drivers. Provider flags authorize only the
specific Serve/Funnel entry, Cloudflare tunnel, and DNS record named by that endpoint.

## Tailscale

Install and log in:

```sh
brew install tailscale             # or https://tailscale.com/download
tailscale up
tailscale status --json
```

Private Serve needs no additional grant. Public Funnel requires MagicDNS and HTTPS certificates,
plus the `funnel` node attribute in the tailnet ACL policy. Verify it before use:

```sh
tailscale funnel --bg localhost:3000
tailscale funnel localhost:3000 off
```

Wormhole snapshots Serve configuration, refuses conflicting entries, and removes only an entry
that still matches what it installed. It never calls `tailscale serve reset`.

## Cloudflare

Install cloudflared:

```sh
brew install cloudflared
cloudflared --version
```

Quick tunnels need no login and are development-only. Named tunnels require account login once:

```sh
cloudflared tunnel login
ls ~/.cloudflared/cert.pem
```

A named endpoint creates/reuses `wormhole-<hostname>-<hash>`, routes only its hostname, and runs
one connector with a hostname ingress rule followed by `http_status:404`. Wormhole stops
connectors but intentionally leaves named tunnels and DNS records in place. After Wormhole has
successfully created a hostname route, it records that exact ownership locally. Restoring the
still-configured persistent endpoint reconciles only that owned hostname with
`--overwrite-dns`; unrelated DNS records are never changed.

## Endpoint qualifiers

| Endpoint | Behavior |
|---|---|
| `tailscale` | Tailnet-only Tailscale Serve |
| `tailscale:funnel` | Public Tailscale Funnel |
| `cloudflare` | Unauthenticated quick tunnel |
| `cloudflare:quick` | Explicit quick tunnel |
| `cloudflare:named` | Persistent named tunnel; requires `--host` and `--persist` |

Examples:

```sh
wormhole http 3000 --endpoint tailscale
wormhole http 3000 --endpoint tailscale:funnel
wormhole http 3000 --endpoint cloudflare
wormhole http 3000 --endpoint cloudflare:named --host app.example.com --persist
wormhole tcp 5432 --endpoint tailscale --public-port 5432
```

## Capabilities

| Driver | HTTP | TCP | Persistent | Custom domain | Inspection |
|---|---:|---:|---:|---:|---:|
| `wormhole` | yes | yes | yes | relay domains | yes |
| `tailscale` | yes | yes | yes | no | no |
| `tailscale:funnel` | yes | yes (443/8443/10000) | yes | no | no |
| `cloudflare:quick` | yes | no | no | no | no |
| `cloudflare:named` | yes | no | yes | yes | no |

`wormhole doctor` reports provider binary, version, login, and Tailscale daemon state. Tunnel
creation repeats the same preflight and fails before making provider changes.
