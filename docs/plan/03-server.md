# Stage 03 — Relay server (`wormholed`)

**Goal:** a single static binary you drop on a VPS with a wildcard DNS record and get: QUIC
listener for clients, HTTPS edge routing `*.tun.example.com` (SNI/Host) into client tunnels,
raw TCP forwards, ACME certificates, persisted binds and authorized keys. Secure by default,
zero runtime deps.

**Depends on:** 02. **Parallel with:** 04. **Blocks:** 05 e2e paths, 07, 08.

## Runtime model

- One tokio runtime. Three listener tasks: QUIC `:443/udp` (configurable), HTTPS `:443/tcp`,
  HTTP `:80/tcp` (redirect only; built-in ACME uses DNS-01). TCP forwards get per-bind tasks from a configured
  port range.
- Each client connection = a **session actor**: owns the QUIC connection + control stream,
  a `mpsc` command channel, and registers its binds in the shared registry.
- Registry: `DashMap<HostKey, BindHandle>` where `HostKey = Hostname(String) | TcpPort(u16)`
  and `BindHandle { session_tx, bind_id, persist, buffer_policy, auth, state }`.
- HTTP edge path: TLS + Hyper HTTP/1.1 → validate Host/SNI and edge auth → open one logical
  client stream per request → send typed request head + streaming body → stream the typed
  response back. TCP stays the raw `copy_bidirectional` hot path. No registry lock is held
  across an await.

## Module layout

```
crates/wormholed/src/
  lib.rs         # relay as a library (embeddable in tests / future single-binary)
  main.rs        # thin bin: clap: serve | key (authorize/ls/revoke) | status | binds | init
  config.rs      # WormholedConfig (TOML), validation, defaults
  state.rs       # AppState { registry, db, certs, limits }
  quic.rs        # quinn Endpoint setup, accept loop, per-conn handshake
  session.rs     # session actor: control loop, bind/unbind, ping, drain
  registry.rs    # HostKey routing table, hostname allocation
  edge_https.rs  # :443 accept, SNI resolver, proxy into sessions
  edge_http.rs   # :80 HTTPS redirect
  edge_tcp.rs    # tcp forward listeners, port-range allocator
  certs.rs       # CertManager: static wildcard | acme | self-signed dev
  acme.rs        # instant-acme account/order flow, storage, renewal task
  db.rs          # redb tables + typed accessors
  authz.rs       # authorized keys store + KeyDecision
  shutdown.rs    # SIGTERM drain: stop accepts, notify clients (Event::Shutdown), 30s grace
```

## Config (`/etc/wormhole/wormholed.toml`)

```toml
[server]
# Domains are SERVER-DECIDED. Clients only request subdomain labels under these; they can
# never introduce a hostname/domain of their own. First entry is the default.
domains = ["tun.example.com"]
public_https_port = 443           # optional external/NAT override; omit to use bound https port
quic_addr = "0.0.0.0:443"         # UDP. 443/udp coexists with 443/tcp edge; configurable.
https_addr = "0.0.0.0:443"
http_addr = "0.0.0.0:80"
data_dir = "/var/lib/wormhole"    # redb, acme account, issued certs

[tls]
# Every configured domain needs a wildcard cert (*.domain + apex). Modes:
#   "static"       — operator provides PEMs (certbot/DNS provider of their choice)
#   "acme-dns01"   — built-in issuance/renewal via instant-acme + DNS API (cloudflare only)
#   "self-signed"  — dev/e2e only
mode = "static"
[tls.static]
certs = [{ domain = "tun.example.com", cert = "/etc/wormhole/fullchain.pem", key = "/etc/wormhole/privkey.pem" }]
# [tls.acme]
# contact = "mailto:ops@example.com"
# directory = "https://acme-v02.api.letsencrypt.org/directory"
# dns_provider = "cloudflare"
# cloudflare_token_file = "/etc/wormhole/cf-token"   # 0600

[tcp]
port_range = { start = 10000, end = 20000 }

[limits]
max_binds_per_key = 32            # enforced GLOBALLY per key fingerprint, across all sessions
max_sessions_per_key = 8
max_streams_per_session = 1024
handshake_per_ip_per_min = 30
buffer_max_bytes_per_key = "100MiB"
buffer_max_bytes_total = "1GiB"

[auth]
authorized_keys = "/etc/wormhole/authorized_keys"   # dir of *.pub files, WH format from P3
```

## Tasks

**Implementation order within this stage:** S1 → S2 → S3 → S5 → S6 → S4 → S7 → S8 → S9.
S4 *wires together* the registry (S5) and CertManager (S6), so build those components first —
the numbering groups by topic, not by execution order.

- [x] **S1 — Config + CLI shell.** `config.rs` with serde + `validate()` (domain is a DNS name,
  ranges sane, static mode requires cert+key paths that exist). `main.rs` subcommands:
  `serve [--config path]`, `init` (writes a commented default config + creates dirs),
  `key authorize <pubkey-or-file> --name <n>`, `key ls [--json]`, `key revoke <fingerprint>`,
  `status [--json]` (client of the S8 admin socket, redb/config fallback; stub until S8).
  Validation: `wormholed init --config /tmp/w.toml && wormholed serve --config /tmp/w.toml
  --check` parses and validates without binding sockets (`--check` flag = validate & exit 0).

- [x] **S2 — redb schema** (`db.rs`). Tables (all keys/values serde_json bytes unless noted):

  | table | key | value |
  |---|---|---|
  | `binds` | stable server bind id (uuid bytes) | `PersistedBind { reservation, spec_without_raw_auth, auth_verifier, hostname/port, key_fpr, created, last_seen }` |
  | `keys` | fingerprint string | `AuthorizedKey { pub_b64, name, created, revoked: bool }` |
  | `webhook_buffer` | (bind id, seq u64) | raw serialized request (stage 07 fills this) |
  | `webhook_failed` | (bind id, seq u64) | serialized request + failure reason/time (stage 07) |

  A `meta` table stores `schema_version`. Before any non-additive migration, close the DB,
  copy it to `data_dir/backups/state-v<old>-<timestamp>.redb`, migrate via a temp DB, fsync,
  then atomically replace; retain the latest two backups. Refuse a newer unknown schema.
  Typed accessor fns only — no raw table access outside `db.rs`. Validation: CRUD tests plus
  old-schema migration, backup creation, and newer-schema refusal.

- [x] **S3 — Auth store** (`authz.rs`). redb `keys` is the sole authority. On first sight,
  import `authorized_keys/*.pub` entries that have no redb row; an existing allowed/revoked row
  always wins, so a revoked file cannot silently re-authorize on restart. `key authorize` and
  `key revoke` update redb atomically; the directory is an import surface, not live policy.
  `is_authorized(pub_b64) ->
  KeyDecision { Allowed { name, limits } | Revoked | Unknown }` — this is the callback P4's
  `ServerHandshake` takes. Validation: unit tests incl. revoked key.

- [ ] **S4 — QUIC listener + session actor** (`quic.rs`, `session.rs`).
  - quinn `Endpoint` with rustls `ServerConfig` from `CertManager` (S6), ALPN `wormhole/1`,
    transport: keep-alive 15s, idle timeout 60s. **Startup order:** CertManager must have the
    default domain's cert ready (loaded or issued) **before** the QUIC socket binds — in
    acme-dns01 mode with an empty cache, `serve` blocks on first issuance and fails loudly on
    error rather than starting cert-less.
  - Per-key global limits: an atomic counter map keyed by fingerprint (sessions, binds) in
    `state.rs` — session-local checks are not enough since one key may open many sessions.
  - Per connection: rate-limit by remote IP (`governor`), accept first bidi stream, run
    `ServerHandshake` over `ControlChannel` with a 5s deadline, then spawn session actor.
  - Session actor loop: `select!` over control frames (`Bind`/`Unbind`/`Ping`) and its command
    channel (`OpenHttp { request, body, reply }`, `OpenTcp { header, reply }`, `Shutdown`).
  - `Bind` → allocate in `Pending` state via registry (S5) → persist if `Persistent` (S2) →
    reply with correlation `request`, stable server `bind`, URLs, and reservation. Only
    `BindReady { bind }` atomically flips it Online and returns `BindActive`; Pending never
    receives public streams or buffered drain.
  - Connection close → temporary binds deregister fully; **persistent binds stay in the
    registry** with their handle flipped to `Offline` (so the edge can still route the
    hostname to the 503/buffer path — a pure redb lookup on the hot path is not acceptable).
    On boot, `serve` preloads all persisted binds into the registry as `Offline`.
  Validation: integration test in `crates/wormholed/tests/` — real quinn client (test-only, using
  proto crate + self-signed cert) handshakes with a wrong key (Denied) and right key (Welcome),
  binds, gets `Bound`, proves traffic is rejected while Pending, sends `BindReady`, receives
  `BindActive`, then serves through `https://<name>.<domain>`.

- [x] **S5 — Registry + hostname allocation** (`registry.rs`).
  - `domain` in spec must be one of `server.domains` (None → first); anything else →
    `BindError`. Clients can never bind a hostname outside the configured domains — there is
    **no** custom-domain-per-key mechanism; adding a domain is a server-config + DNS + cert
    operation by the operator.
  - Requested `host: Some("web-fix-ui")` → `web-fix-ui.<domain>` if free else `BindError`.
  - `host: None` → generate `<adjective>-<noun>-<4 hex>` from embedded wordlists (deterministic
    RNG seeding is not required; use `rand::rng()`).
  - Generated URLs: `https://<host>.<domain>` plus the configured external port when present;
    otherwise use the HTTPS listener's actual bound port (including `:0` e2e listeners).
    TCP remains `tcp://<domain>:<port>`.
  - **Reservations:** persistent `Bound` carries a server-issued `reservation: Uuid` stored in
    redb. Reclaim = `Bind { reservation: Some(id) }` where the reservation's key fingerprint
    matches the session key → same hostname/port restored (works for random hostnames too).
    The secret reservation is distinct from the stable bind id and is redacted from list/admin
    APIs. Reclaim while the bind is still Online is rejected; takeover/fencing is out of scope
    for this plan. Hostname match alone never reclaims a persistent bind.
  - Tcp: requested port must be inside `port_range` and free; `None` → allocate lowest free.
  Validation: conflict, reclaim-by-reservation, hostname-only reclaim rejection, Online
  duplicate rejection, other-key reservation rejection, unknown domain, and range exhaustion.

- [ ] **S6 — CertManager** (`certs.rs`, `acme.rs`). Wildcard-only strategy — since domains are
  server-decided, one wildcard (+apex) cert per configured domain covers every bind; there is
  **no per-hostname issuance** (avoids Let's Encrypt rate limits and the fact that rustls'
  `ResolvesServerCert` is synchronous and cannot await an ACME order mid-handshake).
  - `mode = "static"`: load PEMs per domain (rustls-pki-types `PemObject`); hot-reload on
    SIGHUP + daily mtime check (operator renews via certbot/etc.).
  - `mode = "self-signed"`: rcgen wildcard per domain at boot (dev/e2e; client side uses
    `trusted_ca` remote option, stage 04).
  - `mode = "acme-dns01"`: `instant-acme`, account under `data_dir/acme/`, **DNS-01** for
    `*.<domain>` + apex via the Cloudflare DNS API (TXT create/delete with the configured
    token; reqwest). Issued certs cached in `data_dir/certs/` and hot-swapped via
    `ArcSwap`-style `Arc<CertResolver>` state (a `parking_lot::RwLock<HashMap<domain, CertifiedKey>>`
    is fine). Renewal task: daily scan, renew < 30 days to expiry; failures logged loudly and
    surfaced in `status`.
  - One `Arc<CertResolver>` implementing `rustls::server::ResolvesServerCert` (pure lookup,
    never blocks) shared by the :443 edge **and** quinn's server config.
  Validation: unit test static + self-signed paths + resolver lookup for `a.tun.example.com`
  vs apex vs unknown; acme-dns01 flow gets an **ignored** e2e test (needs pebble + fake DNS;
  wire it in stage 08, leave `#[ignore = "requires pebble"]` now).

- [ ] **S7 — Edges** (`edge_https.rs`, `edge_http.rs`, `edge_tcp.rs`).
  - :443: `tokio_rustls::TlsAcceptor` + Hyper HTTP/1.1. TLS ALPN advertises **`http/1.1`
    only**; no SNI is rejected, Host must equal SNI on every request or receive 421, and ECH is
    unsupported/not advertised. Hyper strips hop-by-hop headers, preserves duplicate/end-to-end
    headers, and adds `Forwarded`/`X-Forwarded-For`/`X-Forwarded-Proto` from the trusted edge
    (removing client-supplied copies first).
    **Tunnel hostnames:** authenticate the request when configured, open one logical HTTP stream
    through `BindHandle`, send `StreamHeader::Http` + streaming body, receive
    `HttpResponseHead` + streaming body, and build the public response. Backpressure is bounded;
    cancellation/reset propagates both ways. A 101 response bridges upgraded bytes raw.
    **Control hostnames** (configured-domain apex): local Hyper routes for 404/landing, health,
    and stage-08 `/_wormhole/ws`; this path never enters a customer bind.
    Unknown host → minimal static 404 page. Known but offline persistent bind → 503 page
    (stage 07 upgrades this to buffering) with `Retry-After: 30`.
  - Timeouts: TLS accept 10s, header 10s, idle 75s both directions (`tokio::time::timeout`
    around copy with an activity-reset — use `tokio_util::time` or manual watchdog).
  - :80: 308 redirect to the generated HTTPS authority, including a non-443 external port.
  - TCP: one listener per bind and raw `StreamHeader::Tcp` + `copy_bidirectional`. A persistent
    bind keeps its listener while offline and immediately closes new connections; this reserves
    the port and avoids another process stealing it before reclaim. Temporary listeners drop.
  Validation: integration test — fake session (channel-backed `BindHandle`) + real TLS edge with
  self-signed certs; curl-equivalent request through, bytes match; offline persistent bind
  returns 503.

- [ ] **S8 — Admin API, observability + shutdown.**
  - **Local admin API** (`admin.rs`): axum over UDS at `data_dir/admin.sock` (0600, owner =
    service user; same flock/socket hygiene rules as the client daemon, stage 05). Routes:
    `GET /v1/status` (uptime, sessions, binds, streams, cert expiries), `GET /v1/binds`,
    `GET /v1/keys`, `DELETE /v1/binds/{id}`, `POST /v1/keys` / `DELETE /v1/keys/{fpr}`.
    Never a TCP listener — this is the contract a future TUI/web dashboard consumes (run such a
    UI as a separate process on the host, e.g. behind SSH). JSON schemas versioned `/v1`,
    additive-only. Routes/types annotated with `utoipa`; `GET /v1/openapi.json` + Scalar UI at
    `GET /docs` on the socket; spec committed at `docs/admin-api.openapi.json` with a
    drift-check unit test (same pattern as the daemon API, stage 05). All secret fields
    (reservation token, bearer/basic material, link key, DNS token path contents) serialize as
    redacted/absent in API responses and tracing.
  - `wormholed status|binds|key` subcommands talk to the admin socket when serve is running,
    fall back to reading redb/config directly when it isn't.
  - `tracing` spans per session/bind/stream (ids as fields, never bodies); SIGTERM →
    `shutdown.rs`: stop accepting, send `Event::Shutdown`, 30s drain, exit 0.
  Validation: run serve in self-signed mode → `wormholed status --json` (via socket) shows a
  live session; SIGTERM exits < 35s with drain log lines; admin socket mode/ownership test.

- [ ] **S9 — Deploy assets.** `deploy/wormholed.service` (systemd: `DynamicUser=yes`,
  `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `StateDirectory=wormhole`,
  `ProtectSystem=strict`, restart on-failure), `deploy/Dockerfile` (distroless static build),
  `docs/server-setup.md`: DNS records needed (`A tun.example.com`, `A *.tun.example.com`),
  ports (80/tcp, 443/tcp, 443/udp — QUIC, configurable — plus the tcp forward range), cert
  options per S6 (static wildcard vs built-in acme-dns01/cloudflare), install +
  `wormholed init` + authorize first key.
  Validation: `docker build -f deploy/Dockerfile .` succeeds; systemd unit passes
  `systemd-analyze verify` if available (skip on macOS with a note).

## Acceptance gate

```bash
cargo test -p wormholed --locked \
&& cargo clippy -p wormholed --all-targets --locked -- -D warnings
```

Plus manual/scripted smoke (also codified in stage 08 e2e): self-signed config, run `serve`,
drive the S4 test client to bind `demo`, then
`curl -k --resolve demo.localtest.wormhole:8443:127.0.0.1 https://demo.localtest.wormhole:8443/`
returns the local target's response end-to-end. Commit `feat(server): wormholed relay`.
