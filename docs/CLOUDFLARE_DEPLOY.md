# Cloudflare Worker relay

The `wormholed-cloudflare` crate deploys a protocol-v2 Wormhole relay to Cloudflare Workers and a
SQLite-backed Durable Object. It is separate from the VPS `wormholed` binary.

## One-command deployment

Prerequisites:

- a domain in an active Cloudflare zone;
- a Workers plan that supports Durable Objects;
- Node.js and npm so the CLI can run the bundle's pinned Wrangler version; and
- either a Cloudflare API token with **Zone Read**, **Zone DNS Edit**, **Workers Scripts Edit**, and
  **Workers Routes Edit**, or an existing `wrangler login` plus manually configured DNS.

Validate the exact Worker bundle and Wrangler deployment locally without credentials or account
changes:

```sh
wormhole relay deploy cloudflare --domain wormhole.example.com --dry-run
```

Then deploy. When `CLOUDFLARE_API_TOKEN` is absent, an interactive terminal prompts for it without
echoing or persisting it:

```sh
wormhole relay deploy cloudflare --domain wormhole.example.com
```

To avoid an API token, first create proxied `A` records for `relay.wormhole` and `*.wormhole`
pointing to the placeholder `192.0.2.1`, authenticate with `npx wrangler login`, and run:

```sh
wormhole relay deploy cloudflare --domain wormhole.example.com --manual-dns
```

This mode skips all Cloudflare zone and DNS API operations. It trusts the existing records and uses
Wrangler OAuth for the Worker, routes, Durable Object migration, and secret upload.

Clients connect to `relay.wormhole.example.com`, public apps use names such as
`myapp.wormhole.example.com`, and existing hosts elsewhere under `example.com` remain unaffected.
The `--domain` value defines Wormhole's public namespace. Using `--domain example.com` produces
shorter names such as `myapp.example.com`, but its wildcard Worker route can intercept existing
subdomains such as `www.example.com`; use it only when that namespace is dedicated to Wormhole.
Review and confirm the plan. Use `--yes` only for intentional noninteractive deployment. Without
`--manual-dns`, the command:

1. obtains the version-matched Worker bundle and verifies its published SHA-256 checksum;
2. runs the bundle's pinned Wrangler, verifies Cloudflare authentication, and discovers the zone;
3. reuses suitable proxied DNS or creates relay and wildcard placeholder records;
4. deploys the Worker, control plus wildcard routes, and SQLite Durable Object migration;
5. uploads generated `ADMIN_TOKEN` and `EDGE_AUTH_KEY` values through Wrangler stdin;
6. waits for `GET /health`, creates a one-use invite, enrolls this machine's own key, and writes a
   WebSocket remote named `cloudflare` to the local Wormhole configuration.

The control hostname defaults to `relay.<DOMAIN>`; override it with `--relay-domain` when needed.
Override the deterministic Worker or remote names with `--worker-name` or `--remote-name`. Use
`--bundle PATH` for audited, offline, or development artifacts. A source-tree `0.0.0` development
build creates its local Worker bundle automatically; released CLIs download only their exact GitHub
Release asset.

The provider API token and invite are never persisted; manual-DNS mode does not request a provider
token. A generated relay administrator token is
stored mode `0600` in the user's Wormhole configuration directory so later deployments can create a
fresh invite without rotating relay secrets. Set `WORMHOLE_CLOUDFLARE_ADMIN_TOKEN` instead when
updating a deployment from another machine.

If a later step fails, the automated mode removes only DNS records it created, while manual-DNS mode
leaves operator-managed DNS untouched. Both modes delete a newly created Worker or ask Wrangler to
roll an existing Worker back to the previous deployment. Local
configuration is written only after successful health verification and enrollment. Account-level
WAF rules are intentionally not mutated; apply the recommendations under [Cost and abuse
controls](#cost-and-abuse-controls) after deployment.

After deployment, run the live HTTP semantics gate against the configured remote and namespace:

```sh
make cloudflare-semantics CF_REMOTE=cloudflare CF_DOMAIN=wormhole.example.com
```

The gate creates one temporary hostname, tests compressed and HTML responses, HEAD and null-body
statuses, SSE streaming, ranges, duplicate cookies, 2 MiB uploads/downloads, a public WebSocket
message round trip, and mid-stream failures, then removes the temporary bind and local origin.

## Feature matrix

| Capability | Worker relay | VPS relay |
|---|---:|---:|
| Existing CLI WebSocket fallback and signed handshake | yes | yes |
| Invite enrollment, expiry, reuse limits, revocation | yes | yes |
| Stable/generated HTTP hostnames and persistent reservations | yes | yes |
| Temporary-bind `X-Robots-Tag` protection | yes | yes |
| Streaming HTTP request and response bodies | yes | yes |
| Cloudflare-managed HTTPS | yes | no |
| QUIC control transport | explicit fallback/unsupported | yes |
| Raw TCP binds | rejected with `BindError` | yes |
| Public WebSocket upgrades | bounded message bridge | raw byte tunnel |
| Other public HTTP upgrades | rejected with HTTP 501 | yes |
| Offline webhook buffering | rejected with `BindError` | yes |
| Edge Basic/Bearer/share-link auth | yes | yes |
| Unix-socket administration | not applicable | yes |
| Bearer-protected HTTPS invite administration | yes | no |

Cloudflare's [WebSocket API](https://developers.cloudflare.com/workers/runtime-apis/websockets/)
documents that `accept()` terminates the public WebSocket on Cloudflare's network and delivers
complete string/`ArrayBuffer` messages. The Worker bridges those bounded messages to masked RFC 6455
frames over the protocol-v2 upgrade stream and translates local frames back to Cloudflare messages.
It strips extension negotiation, preserves a selected subprotocol, caps messages at 1 MiB, and
propagates close and ping/pong semantics. Use the VPS relay for other upgrade protocols, raw TCP,
QUIC, buffering, WebSocket extensions, or a transparent raw upgraded byte stream.

## Architecture

A Worker entrypoint terminates Cloudflare-managed TLS, answers control-host health checks and
obvious misses directly, and sends control WebSocket upgrades, public hostname requests, and the authenticated
administration API to one SQLite-backed Durable Object named `relay`. The object is the deployment's
strongly consistent coordination atom: it owns invite redemption, authorized keys, hostname
uniqueness, persistent reservations, live sessions, and HTTP stream routing. This favors a coherent
single-relay consistency boundary over premature sharding.

Control clients use the existing `/_wormhole/ws` fallback and protocol-v2 mux. Channel zero carries
the length-delimited JSON control stream; even-numbered server channels carry HTTP streams. The
Worker uses portable protocol frames, Ed25519 verification, and sans-I/O mux envelopes from
`wormhole-proto`; the Tokio mux runtime remains native-only.

### Security and persistence

Enrollment remains challenge/response. The Worker verifies Ed25519 proof before atomically consuming
an available, unexpired invite and authorizing the key. Plain invite tokens are returned once and
never stored. Reusable invites retain explicit usage and expiry constraints.

SQLite retains invite metadata, key revocation state, persistent HTTP binds, and the canonical active
connection per identity. Hibernatable WebSockets carry pending authentication or authenticated
identity in a bounded attachment, eliminating SQL operations for challenge state and normal control
heartbeats. Connections created before this optimization recover once from legacy SQLite rows, and
superseded sockets retire before their replacement becomes canonical.

A 256-entry in-memory hostname cache removes repeated indexed bind lookups while the object is warm.
Every bind, reservation, identity, and connection lifecycle mutation invalidates matching entries;
SQLite indexes cover hostname resolution and connection/fingerprint cleanup. Temporary binds vanish
on disconnect while persistent binds become offline.

`ADMIN_TOKEN` is a Wrangler secret. Administration is available only under `/_wormhole/admin/*`,
requires a bearer token, and has no browser CORS allowance. Basic and bearer edge credentials are
stored only as HMAC-SHA-256 verifiers keyed by the separate `EDGE_AUTH_KEY` secret. Share-link HMAC
keys remain durable across reconnects. Cloudflare TLS and wildcard DNS replace ACME.

### Data flow and bounds

Public HTTP request metadata uses `StreamHeader::Http`; request and response bodies travel in
at-most-64-KiB WebSocket messages. Protocol windows and bounded queues limit per-stream memory.
Response headers are validated before creating a streamed Worker response. Connection, bind, stream,
header, message, and admin-body limits fail closed with actionable errors.

## Local development

Rust 1.97 and the repository's `wasm32-unknown-unknown` target are required when building the Worker
from source. No Cloudflare account ID or resource ID is committed. Wrangler provisions the SQLite
Durable Object class from migration `v1`.

From `crates/wormholed-cloudflare`:

```sh
npm ci
cargo check --target wasm32-unknown-unknown
npm run build
```

Create an ignored local secret file without printing the generated token:

```sh
umask 077
printf 'ADMIN_TOKEN=' > .dev.vars
openssl rand -base64 32 | tr -d '\n' >> .dev.vars
printf '\nEDGE_AUTH_KEY=' >> .dev.vars
openssl rand -base64 32 | tr -d '\n' >> .dev.vars
printf '\n' >> .dev.vars
```

For an end-to-end CLI check on port 8787, use a locally trusted certificate for `lvh.me` and
`*.lvh.me` (`lvh.me` resolves to loopback), then run:

```sh
npx wrangler dev --local --port 8787 --local-protocol https \
  --https-cert-path ./local-cert.pem --https-key-path ./local-key.pem \
  --var RELAY_DOMAIN:lvh.me --var CONTROL_DOMAIN:relay.lvh.me
```

Create a mode-0600 curl header file containing `Authorization: Bearer <the local ADMIN_TOKEN>`, then
create an invite without putting the token in shell history or process arguments:

```sh
curl --silent --show-error --fail --header @./admin-header.local \
  --header 'content-type: application/json' \
  --data '{"name":"local-client","ttl_secs":600,"max_uses":1}' \
  https://relay.lvh.me:8787/_wormhole/admin/invites
```

Add this temporary remote block to the client configuration (the invite itself is passed only to
`wormhole remote add --invite` and is never persisted):

```toml
[remotes.local-worker]
transport = "ws"
addr = "relay.lvh.me:8787"
https_addr = "relay.lvh.me:8787"
server_name = "relay.lvh.me"
```

Run `wormhole remote test local-worker`, expose an HTTP service with a persistent hostname, and use
`curl https://<hostname>.lvh.me:8787/`. The Rust tests cover control framing and transient invite
presentation; this local flow covers Wrangler, Durable Object SQLite, hibernatable WebSockets,
enrollment, bind activation, and streamed HTTP forwarding.

Local certificate/private-key, `.dev.vars`, header, build, Wrangler-state, and `*.local` files must
remain untracked.

## Manual deployment reference

Use this only when debugging the command or intentionally managing resources yourself:

1. Build the bundle with `npm run bundle` in `crates/wormholed-cloudflare`.
2. Set `RELAY_DOMAIN` to the public suffix, `CONTROL_DOMAIN` to its relay hostname, and configure
   control plus wildcard routes in a private copy of `wrangler.jsonc`.
3. Ensure proxied DNS exists for both the control and wildcard names; do not route the public apex.
4. Upload independent `ADMIN_TOKEN` and `EDGE_AUTH_KEY` values with `wrangler secret bulk` over
   stdin; never place them in Wrangler vars or command arguments.
5. Run `npm run check`, `npx wrangler check startup`, and `npx wrangler deploy`.
6. Create an invite through the HTTPS administration API, then enroll with
   `wormhole remote add NAME relay.example.com:443 --invite TOKEN`, then set `transport = "ws"` in
   that remote's configuration block.

Cloudflare-managed TLS replaces ACME for this relay. Wildcard Workers Routes, rather than Custom
Domains alone, are required for generated public hostnames. Never put administrator tokens, invite
tokens, API tokens, account IDs, or certificate keys in source control.

## Administration API

All endpoints require `Authorization: Bearer ...`, return `Cache-Control: no-store`, and do not
allow browser CORS:

- `POST /_wormhole/admin/invites` — `{name, ttl_secs?, max_uses?}`; returns plaintext token once.
- `GET /_wormhole/admin/invites` — metadata only; no secret digest or token.
- `DELETE /_wormhole/admin/invites/{id}` — durable revocation.
- `GET /health` — unauthenticated liveness on the relay control hostname.

Rotate `ADMIN_TOKEN` with `wrangler secret put`; existing invites and enrolled keys are unaffected.
`EDGE_AUTH_KEY` must contain at least 32 bytes and keys all stored Basic/Bearer verifiers. Rotating it
invalidates those credentials until their tunnels are rebound; share links use their own per-bind
keys and are unaffected. Key/bind administration beyond protocol-owned lifecycle is intentionally
absent from this MVP.

## Cost and abuse controls

The Worker intentionally answers `GET /health` and unknown control-host paths without invoking the
Durable Object. Normal control heartbeats use hibernation-safe WebSocket state and arrive once per minute;
WebSocket protocol pings continue without waking the object. Public hostname traffic still requires
one Durable Object invocation to reach the connected client.

Before exposing wildcard routes, configure account-level
[WAF rate limiting rules](https://developers.cloudflare.com/waf/rate-limiting-rules/) so abusive
traffic is rejected before Worker and Durable Object billing. At minimum, use separate policies for:

- `/_wormhole/admin/*`, restricted to trusted source networks where practical and tightly limited;
- `/_wormhole/ws`, limiting repeated connection and authentication attempts per source; and
- wildcard public hosts, with a per-source and per-host threshold appropriate for the exposed app.

Thresholds are deployment-specific and are not provisioned by Wrangler. Start in logging mode,
verify legitimate CLI reconnect and application burst patterns, then enable blocking. Configure
Cloudflare billing notifications and monitor Worker requests, Durable Object requests/duration,
SQLite rows read/written, and Workers Logs as separate dimensions.

## Operations and security

The Durable Object uses one deployment-wide coordination atom so invite redemption, hostname
uniqueness, and reservations are strongly consistent. The trade-off is one-object throughput. Limits
are 32 binds per key, 32 concurrent HTTP streams per session, 64-KiB mux payloads, a 256-KiB protocol
window, a 16-chunk response queue, and a ten-second response-header deadline. Cloudflare's request
body plan limit still applies.

WebSocket hibernation stores connection tags and bounded authentication/identity attachments;
canonical session and bind state remains in SQLite. Pending authentication retains a nonce and
invite-secret digest, never invite plaintext. The invite-consuming key insert and SQLite trigger are
one statement, so proof verification precedes atomic redemption.

Workers Logs and automatic invocation logs are disabled by default to prevent idle control traffic
and public requests from creating an unbounded logging bill. To opt in, change only the
`observability` block in `wrangler.jsonc` and redeploy:

```jsonc
"observability": {
  "enabled": true,
  "head_sampling_rate": 0.01,
  "logs": { "invocation_logs": true }
}
```

The default 1% ceiling samples about one invocation in one hundred. Increase it only for a bounded
diagnostic window; Cloudflare bills log events above the plan allowance independently of Worker and
Durable Object requests. When enabled, alert on 5xx responses, Durable Object resets, memory/CPU
limit errors, `bind_offline`, `tunnel_failed`, and repeated authentication denial. See
[Workers Logs pricing](https://developers.cloudflare.com/workers/platform/pricing/#workers-logs).
Back up operational metadata by an approved Cloudflare mechanism before destructive migrations.

## Remaining risks

- The single Durable Object is a deliberate scalability ceiling; shard behind a strongly consistent
  hostname directory and per-client session objects before high multi-tenant load.
- Hibernation cannot preserve a partially received channel-zero byte fragment. Current clients send
  control frames as bounded mux messages, but a future client that deliberately fragments one
  control frame across a long idle interval can be disconnected and must retry.
- Worker integration is locally reproducible, but this repository does not perform authenticated
  Cloudflare deployment in CI or tests.
