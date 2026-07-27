# Stage 08 — Testing, hardening & fallback transport

**Goal:** prove the whole system end-to-end on real sockets, add the WebSocket fallback
transport, chaos-test reconnection, and close the security checklist. After this stage the
project is functionally complete; stage 09 only packages it.

**Depends on:** all previous stages.

## Tasks

- [ ] **H1 — e2e harness** (`crates/wormhole-e2e`). `harness.rs`:
  - Binary discovery: `cargo_bin("...")` does NOT build sibling packages — the harness runs
    `cargo build -p wormhole-cli -p wormholed` once per test-process (a `OnceLock` guard
    shelling out to `CARGO`), reads `target_directory` from `cargo metadata`, and uses its
    explicit `debug/{wormhole,wormholed}` paths. `make e2e` pre-builds first.
  - `TestRelay::start()` — tempdir data dir, self-signed config on random high ports
    (`quic_addr 127.0.0.1:0` support; harness reads actual bound addresses from the S8 admin
    socket's `GET /v1/status`, which must include them; with no external-port override,
    wormholed generates `Bound` URLs from the HTTPS listener's actual bound port), authorized
    test key.
  - `TestClient` — tempdir `WORMHOLE_CONFIG`/state dir, remote with `trusted_ca` at the
    relay's self-signed cert, isolated daemon socket.
  - `EchoServer` — local hyper server returning method/path/body-hash JSON.
  All e2e tests `#[ignore = "e2e"]`, run via `make e2e` and a dedicated CI job (`cargo test -p
  wormhole-e2e -- --ignored --test-threads=4`).
  Validation: the harness's own smoke test: relay starts, client binds, curl through edge hits
  echo, response matches.

- [ ] **H2 — e2e matrix.** One test per scenario, all through real binaries:
  1. http temporary: bind, hit, down, hit → 404.
  2. http persistent: bind, kill client daemon, hit → 503, restart daemon (auto-restore D2),
     hit → 200, hostname unchanged.
  3. multi-endpoint: one service, `wormhole` + mock driver, both Ready, closing one leaves the
     other serving.
  4. tcp forward: bind tcp to a local TCP echo, netcat-style round-trip via relay port.
  5. webhook buffer: full W2 flow through real binaries.
  6. inspection + replay: full W5 flow.
  7. multi-remote: two relays, one daemon, one service exposed to both, both URLs live.
  8. `wormhole run`: wrap the PORT-honoring script, URL serves child; child exit cleans up.
  9. auth: unauthorized key → exit 4 with `denied` in JSON error; revoked key same.
  10. HTTP semantics: duplicate `Set-Cookie`, streaming/chunked body, cancellation, forwarded
      client headers, and a WebSocket 101 upgrade survive the typed HTTP stream.
  11. failed webhook: seq 1 Nacks into server failed queue, seq 2 delivers, admin retry of seq 1
      delivers later.
  Validation: `make e2e` green locally (macOS) and in CI (linux).

- [ ] **H3 — WebSocket fallback transport.** For networks that drop UDP: client tries QUIC,
  on timeout (3s) falls back to `wss://<server_name>:443/_wormhole/ws`. The relay's :443 edge
  upgrades to WS **only** when SNI/Host equals a configured relay domain's apex (never on
  tunnel hostnames — no collision with customer paths, control transport not exposed on every
  domain), the path is exactly `/_wormhole/ws`, and `Origin` is absent (native client) or
  exactly `https://<server_name>`; anything else is rejected before upgrade. Auth is the
  normal protocol handshake over channel 0.
  **Mux (proper, not naive):** binary WS messages, each `4-byte channel id (BE) + payload`.
  Channel 0 = control stream. Data channels use framed control messages *inside* the channel-0
  stream: `MuxOpen { ch, header }` → `MuxAck { ch }`, `MuxFin { ch, dir }` (half-close per
  direction), `MuxReset { ch }`, and credit-based flow control `MuxWindow { ch, bytes }`
  (initial window 256 KiB per channel, sender stalls at 0 — preserves QUIC stream semantics:
  half-close, reset, per-stream backpressure, no head-of-line starvation beyond TCP itself).
  One serialized writer task owns the WS sink; per-channel bounded queues (64 msgs) feed it
  round-robin. Server allocates even channel ids, client odd (no collisions). `MuxReset` drops
  both directional queues and cancels that channel's proxy task; WS close/error cancels every
  channel task, closes all queues, and releases the session's bind/stream counters.
  Data payload messages are capped at 64 KiB and the connection has a 16 MiB aggregate queued
  byte cap; overflow resets the offending channel instead of allocating without bound.
  Spec these as a `mux` module in `wormhole-proto` with the same sans-IO testing treatment as
  P4. `remote.transport = "auto" | "quic" | "ws"` config.
  Validation: proto unit tests for open/ack/fin/reset/window sequencing, reset/socket-close
  cleanup, and starvation (one stalled channel doesn't block another); edge tests reject a
  wrong Origin and non-apex Host; e2e forcing `transport = "ws"` runs scenario H2.1 unchanged.

- [ ] **H4 — Chaos.** In the harness: drop the relay (SIGKILL) → client endpoint goes
  `Reconnecting`; restart it on the **same saved ports** → `Online`, persistent hostname
  reclaimed, new requests flow (gap < 15s). Kill -9 the client daemon → `wormhole status`
  auto-respawns and restores persistent services. Separately, kill the client daemon during an
  in-flight request while the relay stays alive → edge returns 502/no hang. Assert the target
  process's fd count is stable across 100 iterations (`/proc/<pid>/fd` Linux, `lsof -p` macOS).
  Validation: chaos tests green 10/10 consecutive runs (`for i in $(seq 10)` script).

- [ ] **H5 — Load smoke + perf guardrails.** Deterministic CI asserts zero errors for 1000
  sequential + 100 concurrent requests and streams a 100MB body without buffering it whole.
  Local-only benchmark records p50/p95/p99 and peak RSS; suggested targets (p99 < 150ms,
  daemon RSS < 150MB) are report-only to avoid noisy CI failures. `criterion` covers codec and
  HTTP head encode/decode (tracked, not gated). Validation: functional tests green; bench compiles.

- [ ] **H6 — Security checklist** (fix anything failing; record each as checked in this file):
  - [ ] key files 0600, dirs 0700, socket 0600 — tested, not just coded (H2 addendum).
  - [ ] server never logs request bodies or auth headers; grep-audit `tracing` calls.
  - [ ] handshake rate-limit per IP effective (test: 31st handshake in a minute refused).
  - [ ] max frame sizes enforced both sides (proto P2 + fuzz below).
  - [ ] slowloris: edge header timeout test (open conn, send 1 byte/s → closed ≤ 15s).
  - [ ] no `insecure`/`skip_verify` flag exists anywhere (`grep -ri "danger\|insecure" crates/`
        returns only `trusted_ca` docs).
  - [ ] TCP forwards bind only configured range; binding outside refused.
  - [ ] `cargo audit` and `cargo deny check` clean; both added to CI.
  - [ ] daemon local API: no TCP listener exists; requests without the bearer token → 401;
        stale-socket replacement happens only under the daemon flock.
  - [ ] edge: no-SNI rejected; ALPN offers http/1.1 only; Host↔SNI mismatch → 421; ECH not
        advertised (documented unsupported).
  - [ ] per-key limits enforced across sessions (2 sessions, same key, binds counted jointly).
  - [ ] edge auth: constant-time compares; secrets never in logs; auth precedes buffering;
        redb contains no raw basic/bearer secret; share tokens expire and cookies are secure.
  - [ ] capture is memory-only, capped at 20 eligible exchanges/endpoint, ignores static assets
        by default, respects the 32 MiB global budget, and tests replay/body truncation.
  - [ ] buffered webhook bodies capped, quota'd (per-key + global bytes) and TTL-pruned
        (W2 tests cover; re-verify).
- [ ] **H7 — Fuzz-ish.** In `wormhole-proto`, keep codec/frame proptests. In
  `crates/wormholed/tests/control_fuzz.rs`, feed the server's control-stream handler (pure async
  fn over `AsyncRead`) arbitrary bytes and mutated valid frames — wormholed depends on proto,
  never the reverse. Must never panic and must terminate cleanly. 60s proptest budget in CI.
- [ ] **H8 — Coverage gate.** Per-package thresholds need per-package runs (a single
  `--workspace` invocation can't scope `--fail-under-lines`): CI runs
  `cargo llvm-cov -p wormhole-proto --fail-under-lines 75` and
  `cargo llvm-cov -p wormhole-core --fail-under-lines 75`, plus one
  `cargo llvm-cov --workspace --html` artifact as report-only for the binaries.

## Acceptance gate

```bash
make lint && cargo test --workspace --locked && make e2e \
&& cargo audit && cargo deny check
```

All green + H6 boxes all ticked. Commit `test: e2e harness, chaos, hardening` (multiple commits
fine per task).
