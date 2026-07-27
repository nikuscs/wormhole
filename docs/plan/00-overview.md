# Wormhole — Master Plan

> **Scope mantra: ngrok for agents & worktrees. Simple, fast, secure.**
> No web UI. CLI + JSON + local API only. Full features end to end — there is no cut-down v1.

Wormhole exposes local services (ports, dev servers, worktree apps) on public or private URLs
through pluggable **drivers** — our own self-hosted relay, Tailscale, Cloudflare — and can bind
one local service to **multiple URLs at once** (e.g. tailnet + own domain + trycloudflare
simultaneously).

## How to execute this plan

Each stage is a file in `docs/plan/`. Work them **in order** (dependencies noted per stage).
For each stage:

1. Read the whole stage file before writing code. Read the referenced code that already exists.
2. Do tasks top-to-bottom. Each task has an ID (`F1`, `P3`, …), exact paths, and often a snippet.
   Snippets are **normative for shape, not literal** — adapt names/imports to compile, keep the
   design.
3. Tick the checkbox (`- [ ]` → `- [x]`) in the stage file **only after the task's validation
   command passes**.
4. A stage is done only when its **Acceptance gate** section passes verbatim. Then tick the stage
   here.
5. Never mark partial work complete. If blocked, add a `> BLOCKED:` note under the task and stop.
6. Follow repo conventions (stage 01) — including sibling `_tests.rs` test files (never
   inline `mod tests`) and file-size caps. `cargo fmt`, `cargo clippy --all-targets -- -D
   warnings`, `make size`, and `cargo test` must pass at the end of every stage — no exceptions.
7. Do not add dependencies not listed in stage 01 without recording them in that file's
   dependency table with a one-line justification.

## Stage index

- [x] **01 — Foundation** (`01-foundation.md`): workspace, crates, lints, CI, tooling
- [x] **02 — Protocol** (`02-protocol.md`): `wormhole-proto` wire format, Ed25519 handshake, codec
- [ ] **03 — Relay server** (`03-server.md`): `wormholed` QUIC listener, HTTPS/SNI edge, ACME, TCP forwards, persistence
- [ ] **04 — Client core** (`04-client-core.md`): driver trait + registry, remotes, tunnel manager, interfaces, port utils
- [ ] **05 — Daemon & CLI** (`05-daemon-cli.md`): auto-spawned daemon, local API, full CLI, `wormhole run`, `wormhole.toml`
- [ ] **06 — Provider drivers** (`06-providers.md`): tailscale, cloudflare (free backends only)
- [ ] **07 — Forwards & webhooks** (`07-forwards-webhooks.md`): permanent vs temporary, reserved domains, webhook buffering, inspection & replay
- [ ] **08 — Testing & hardening** (`08-testing-hardening.md`): e2e harness, chaos, security checklist, coverage
- [ ] **09 — Release** (`09-release.md`): packaging, docs, deploy guide, release workflow

Stages 03 and 04 can run **in parallel** after 02 (different crates, both depend only on
`wormhole-proto`). Everything else is sequential.

## Locked decisions (do not re-litigate)

| Decision | Choice |
|---|---|
| Binaries | `wormhole` (client CLI + daemon, one binary) and `wormholed` (relay server). `wormholed` is lib+bin so tests embed it and a future combined single binary stays trivial |
| API self-description | Both local APIs generate OpenAPI via `utoipa`, serve `/v1/openapi.json` + Scalar `/docs` on their unix sockets, and commit the specs under `docs/` with drift-check tests |
| Transport client↔relay | QUIC via `quinn`, ALPN `wormhole/2`, default **443/udp** (configurable; TCP edge owns 443/tcp separately). WebSocket-over-TLS fallback (stage 08) |
| Domains | **Server-decided only.** `wormholed` config lists its domains (wildcard-cert-backed); clients request subdomain labels under them. Clients can never introduce new domains |
| Daemon | **Headless, both binaries.** Client daemon: local API (UDS + token) + memory-only request capture. Server: local admin API (UDS). A future TUI (`ratatui`, modeled on xai-org/grok-build's separate-TUI-crate split) or web UI is a **separate client** of these APIs — UI code never lives inside daemon or server, and admin APIs are never TCP/public |
| Auth client↔relay | Ed25519 keypair; server holds authorized public keys; signed-nonce handshake; **zero per-request auth cost** |
| Client model | Daemon auto-spawned on first use (invisible to user), CLI talks HTTP-over-unix-socket; `--foreground` runs a standalone tunnel with no daemon |
| Multi-server | A client connects to **many** relays. Named `remotes` in config, like git remotes. One Ed25519 identity by default, per-remote override |
| Drivers | Laravel-style registry: `wormhole` (own relay), `tailscale`, `cloudflare` day one — free backends only; **ngrok is the competitor, never a driver**. One service → N endpoints via N drivers concurrently. Cloudflare driver is HTTP-only (provider limitation); TCP goes through `wormhole` or tailscale |
| Multi-URL day one | `[[service.endpoint]]` list per service (LocalCan-style, TOML) |
| Public-URL auth | Edge-enforced per endpoint: basic, bearer, and HMAC-signed expiring share links (`wormhole share`). Client mints links offline; relay verifies. No ngrok-compat API — our local API is the only surface |
| Config formats | TOML everywhere. Global client `~/.config/wormhole/config.toml`, project `wormhole.toml`, server `/etc/wormhole/wormholed.toml` |
| Persistence | `redb` on the server (binds, keys, webhook buffer); daemon state in memory + small `redb` for restarts |
| Protocols tunneled | HTTP(S) and raw TCP. **UDP excluded** (revisit post-plan) |
| Platforms | Client: macOS + Linux. Server: Linux. **Windows excluded** |
| Web UI | **Excluded.** Inspection/replay via CLI + local API only |
| Time | `jiff` (not chrono) |
| HTTP data plane | **HTTP-aware end to end.** The relay terminates HTTP/1.1 with Hyper and opens one logical QUIC/WS stream per request; typed request/response heads + streaming bodies enable auth, buffering, retries, capture, and replay consistently |
| TCP data plane | Raw bidirectional bytes, one QUIC/WS stream per public TCP connection |
| Capture | Memory-only, last 20 eligible HTTP exchanges per endpoint; static assets ignored by default; no JSONL body archive |

## Architecture

```
                       ┌────────────────────────── VPS ──────────────────────────┐
  browser/webhook ──►  │ :443 HTTPS edge (SNI route) ─┐                          │
  tcp client ─────►    │ :10000-20000 TCP forwards ───┤  wormholed               │
                       │ :443/udp QUIC (ALPN wormhole/2)   ── session registry    │
                       │        redb: binds / authorized keys / webhook buffer   │
                       └───────────────▲─────────────────────────────────────────┘
                                       │ 1 QUIC conn, N muxed HTTP/TCP streams
┌──────────────────────────────────────┴──────────────────────────┐
│ wormhole daemon (auto-spawned, per-user)                        │
│   tunnel manager ── driver registry                             │
│     ├─ wormhole driver ──► remote "myvps" / remote "work"       │
│     ├─ tailscale driver ─► documented tailscale CLI/config      │
│     └─ cloudflare driver ► cloudflared subprocess (/quicktunnel)│
│   local API: HTTP over ~/.local/state UDS  ◄── wormhole CLI /   │
│   memory-only request ring (inspect/replay)         agents(curl) │
└─────────────────────────────────────────────────────────────────┘
        │ proxies to targets: localhost:3000, 100.x.y.z:8080 (interface aliases)
```

One service, three URLs at once:

```console
$ wormhole http 3000 --endpoint wormhole:myvps --endpoint tailscale --endpoint cloudflare --json
{"service":"web","target":"127.0.0.1:3000","endpoints":[
 {"driver":"wormhole","url":"https://web-fix-ui.tun.example.com","persist":false},
 {"driver":"tailscale","url":"https://mbp.tailnet.ts.net","persist":false},
 {"driver":"cloudflare","url":"https://odd-words-here.trycloudflare.com","persist":false}]}
```

## Repo layout (created in stage 01)

```
Cargo.toml                  # workspace: crates/*
crates/
  wormhole-proto/           # wire types, codec, keys, handshake — no I/O deps beyond bytes
  wormhole-core/            # client engine: drivers, remotes, tunnel manager, ports, interfaces
  wormhole-cli/             # bin `wormhole`: CLI + daemon + local API
  wormholed/                # bin `wormholed`: relay server
  wormhole-e2e/             # integration harness (binaries spawned, real sockets)
docs/plan/                  # this plan
docs/                       # user docs (stage 09)
```

## Competitor intel (verified 2026-07, sources in stage files)

- **portless** (vercel-labs): assigns a free port itself and injects `PORT`/`HOST` env into the
  wrapped command; per-framework `--port` flag injection for Vite/Astro/Angular; worktree branch →
  subdomain naming; `alias` for already-running servers; `doctor`/`prune`. We steal all of this
  for `wormhole run` (stage 05).
- **LocalCan**: declarative per-project config with multiple endpoints per service (our
  `wormhole.toml` model); `--json` on every command; daemon `reload` without dropping
  connections; permanent URLs + offline behavior. We match and exceed via drivers.
- **ngrok**: local agent API on `127.0.0.1:4040/api` (tunnels CRUD, request capture, replay). Our
  local API (stage 05/07) is the same idea over a unix socket.
