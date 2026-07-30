# Wormhole protocol

## HTTP

```text
Browser → *.tun.example.com → wormholed → encrypted tunnel → wormhole → local app
```

1. `wormhole` authenticates with its Ed25519 key and opens an outbound QUIC connection to
   `wormholed`. If UDP is unavailable, it falls back to an authenticated WebSocket.
2. The authenticated `Welcome` advertises every public domain accepted by the relay. The relay
   then assigns or accepts a hostname such as `blue-fox.tun.example.com`.
3. Public HTTPS requests reach `wormholed`. TLS SNI and the HTTP `Host` header select the bind.
4. The relay multiplexes traffic through the existing tunnel.
5. The local daemon forwards it to the target, such as `127.0.0.1:3000`.

The client needs no inbound ports or router configuration.

## Invite enrollment

An unknown client may include a transient enrollment invite in its encrypted `Hello` control frame.
The relay always issues a challenge first and verifies the Ed25519 signature before atomically
consuming an invite use and authorizing that public key. A forged or failed signature cannot consume
an invite or persist a key.

Invite records contain a public identifier, SHA-256 secret digest, name, creation time, optional
expiry, optional usage limit, usage count, and revocation state. Plaintext tokens are returned only
when created; they are never listed, logged, returned after redemption, or stored by the client.
Reusable invites omit expiry and usage limits and remain valid until revoked. Existing authorized
keys do not consume invite uses, and revoked keys cannot be resurrected with an invite.

## TCP

The relay allocates or accepts a public port from its configured range. Connections to that VPS
port are carried through the same tunnel and forwarded to the selected local TCP target.

## Stable provider identity

Stable worktree URLs are enabled by default. The public provider identity is derived from
project/package or folder name, service, and non-default Git branch. It never includes the local
listener port.
Cloudflare uses the identity as a hostname label; Tailscale hashes it to a configured external
HTTPS port. A later run can target a different local port without changing either URL. Git is
optional, so ordinary folders use package or directory identity without a branch suffix.

## Cloudflare Worker profile

The `wormholed-cloudflare` server implements protocol v2 over the WebSocket fallback only. Its
`Hello.invite` enrollment, challenge signature, control frames, mux envelopes, HTTP stream headers,
flow-control windows, and persistent reservation identifiers are wire-compatible with `wormholed`.
Clients should configure `transport = "ws"`; `auto` remains compatible but first performs its normal
QUIC probe. The Worker supports edge Basic/Bearer/share-link authentication and public WebSocket
upgrades through bounded message bridging. Both relay profiles override temporary HTTP bind
responses with `X-Robots-Tag: noindex, nofollow, noarchive, nosnippet` while persistent binds preserve
the origin policy. The Worker rejects `BindSpec::Tcp`, buffering options, and other public HTTP
upgrade protocols with explicit errors. See
[the feature matrix](CLOUDFLARE_DEPLOY.md#feature-matrix).

## Relay requirements

A public self-hosted relay needs:

- a Linux server with a public IP;
- apex and wildcard DNS records pointing to it;
- a certificate covering the apex and wildcard domains;
- `80/tcp`, `443/tcp`, and `443/udp` open;
- the configured TCP-forward range open (`10000-20000/tcp` by default).

Cloudflare quick tunnels and Tailscale do not require a self-hosted relay domain.

The client API at `127.0.0.1:52731` is local management traffic and is never part of a public
tunnel.
