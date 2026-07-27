# Stage 06 — Provider drivers (tailscale, cloudflare)

**Goal:** the external drivers behind the same `TunnelDriver` trait, so
`wormhole http 3000 --endpoint wormhole --endpoint tailscale --endpoint cloudflare` yields three
live URLs. Providers are the **free** backends only — ngrok is the competitor, not a driver.
Facts below were verified against provider docs on 2026-07-26 — trust them over
memory, and re-verify only if a command fails.

**Depends on:** 04, 05 (daemon registers these). **Blocks:** 08 full e2e.

## Provider facts (verified)

### Tailscale
- Use the documented CLI/config surface, not private LocalAPI endpoints:
  `tailscale serve get-config|set-config`, `tailscale serve status --json`, and exact
  `serve|funnel ... off` cleanup commands. This is stable across macOS app/socket layouts.
- Commands: `tailscale serve --bg localhost:3000`;
  `tailscale funnel --bg localhost:3000`; `... off` to remove; `tailscale serve status --json`.
- Node URL: `tailscale status --json` → `.Self.DNSName` (trailing dot — strip) →
  `https://<dnsname>`.
- **Funnel limits:** public ports 443/8443/10000 only; requires tailnet `funnel` node attribute,
  MagicDNS + HTTPS certs enabled. No custom domains — URL is always `<node>.<tailnet>.ts.net`.
- serve = tailnet-only (private), funnel = public internet. Expose both as
  `tailscale` (serve) and `tailscale:funnel`.

### cloudflared
- Quick tunnels: spawn `cloudflared tunnel --no-autoupdate --logformat json
  --url http://<target> --metrics 127.0.0.1:<free-port>`; discover the URL from the beta
  `/quicktunnel` metric when present and the structured stderr event as fallback.
  Limits: 200 in-flight requests, no SSE, dev-only stability.
- Named tunnels (persistent, custom domains): needs prior `cloudflared tunnel login`.
  `tunnel create <name>` (writes `~/.cloudflared/<UUID>.json`), `tunnel route dns <name>
  <host>`, then run with a generated config (`ingress:` rules, catch-all `http_status:404`
  required) or token mode. Health via metrics `/ready`.
- No local control API — subprocess + metrics polling is the driver contract.
- **Protocol limits (enforce in the driver):** quick tunnels are HTTP(S) only — no raw TCP, no
  SSE, 200 in-flight requests. Named tunnels can carry `tcp://` services, but arbitrary-TCP
  consumers need `cloudflared access` on the other end, which defeats "just a URL" — so the
  cloudflare driver supports **HTTP services only**; `proto = "tcp"` + cloudflare endpoint →
  config error telling the user to use the `wormhole` or `tailscale` driver.

## Module layout

```
crates/wormhole-core/src/drivers/
  mod.rs          # registry construction moves here: build_registry(config) -> DriverRegistry
  tailscale.rs
  cloudflare.rs
  process.rs      # shared child-process supervisor (spawn, health, kill-on-drop, restarts)
```

## Tasks

Passing `--endpoint tailscale`, `tailscale:funnel`, or `cloudflare:named` is explicit
authorization for that provider's scoped configuration changes. Do not add a second prompt;
preview exact changes in verbose/JSON output and preserve unrelated state. Plain `cloudflare`
creates only an unauthenticated quick-tunnel subprocess.

- [ ] **V1 — Process supervisor** (`process.rs`). One reusable piece: spawn a child with args/env,
  kill-on-drop (`tokio::process` + process-group kill via nix so grandchildren die), restart
  with the same backoff policy as C5, expose `wait_healthy(probe: impl Fn() -> Future<bool>)`.
  Validation: unit tests with `/bin/sleep` + a probe.

- [ ] **V2 — Tailscale driver.**
  - `check()`: binary discovery first (`which tailscale`, plus the macOS app path
    `/Applications/Tailscale.app/Contents/MacOS/Tailscale`); missing →
    `DriverHealth::Unavailable { hint: "install: https://tailscale.com/download (or brew install tailscale)" }`
    — and every tunnel command **preflights `check()` before use**, failing fast with that hint
    rather than a spawn error. Then `tailscale version` runs; `tailscale status --json` parses;
    logged-out / funnel-attr-missing → actionable `DriverHealth::Degraded(msg)`.
  - `run()`: use the documented CLI. Snapshot with `serve get-config <temp.json> --all`; invoke
    the exact `serve|funnel` command. Temporary endpoints run the foreground command under V1;
    persistent endpoints use `--bg` and daemon-state restore. On stop invoke the exact matching
    `... off` form only if current state still equals what Wormhole installed. Never `reset` or
    wholesale `set-config --all` during ordinary lifecycle.
  - Spec mapping: `EndpointSpec.host` unused (warn); `tailscale` → serve, `tailscale:funnel` →
    funnel (via `EndpointSpec.qualifier`). Funnel + target port not in {443,8443,10000} is
    fine (that limit is the *public* port; local target is proxied) — but reject explicit
    public-port requests outside that set with a clear error.
    Port/path conflicts with an existing Serve/Funnel entry fail with a diff; Wormhole never
    silently replaces or auto-selects a different public URL.
  - **TCP services** (`proto = Tcp`): map to `tailscale serve --tcp=<public_port>
    tcp://<target>` (funnel tcp restricted to the {443,8443,10000} public ports). Add an
    optional `EndpointSpec.public_port` for this; default = same as target port. This is the
    tailscale side of the "TCP goes through wormhole or tailscale" promise.
  - URL: from `status --json` `.Self.DNSName`.
  - `persist=true` → `--bg`/background entries (survive reboot per tailscale); `temporary` →
    remove on stop.
  Validation: unit tests against a **mock**: trait-object `TailscaleApi` with a fake
  implementation replaying captured JSON fixtures (record real outputs into
  `testdata/tailscale/*.json`). Real-binary test is `#[ignore = "requires tailscale"]`.

- [ ] **V3 — Cloudflare driver.**
  - `check()`: binary discovery (`which cloudflared`, `WORMHOLE_CLOUDFLARED_BIN` override);
    missing → `DriverHealth::Unavailable { hint: "install: brew install cloudflared" }`,
    preflighted before every use (same rule as V2). Then `cloudflared --version`; for named
    mode, `cert.pem`/account presence.
  - Quick mode (`cloudflare` / `cloudflare:quick`): V1 supervisor + metrics-port allocation via
    C4. Prefer `/quicktunnel` when present, but treat it as beta and fall back to parsing the
    structured JSON stderr event containing the generated URL; require both sources to agree
    when both appear. Health probe = `/ready`. `persist` errors: use named mode.
  - Named mode (`cloudflare:named`, requires `host` and `persist=true`): create/reuse one
    deterministic tunnel **per endpoint**, with one hostname rule + catch-all 404 and one
    connector process. This avoids shared-config/reload/replica routing complexity. The explicit
    endpoint flag authorizes idempotent `tunnel create` and `tunnel route dns`; log the exact
    tunnel/DNS record, never delete either automatically, and leave unrelated records untouched.
  - HTTP-only: any `proto = "tcp"` service mapped to a cloudflare endpoint fails fast at
    validation ("cloudflare driver is HTTP-only; use wormhole or tailscale for TCP").
  - stderr of children → `DriverEvent::Log(debug)`.
  Validation: unit test quick-mode URL discovery against a fake metrics HTTP server (spawn a
  tiny hyper server returning `/quicktunnel` JSON + a fake script standing in for cloudflared
  via `WORMHOLE_CLOUDFLARED_BIN` override env); log-only fallback; named mode creates two
  distinct endpoint tunnels/configs without touching unrelated fake DNS state. Real test
  `#[ignore]`.

- [ ] **V4 — Conformance suite.** One shared test harness
  (`drivers/conformance.rs`, `#[cfg(test)]`): given any driver + a locally spawned echo HTTP
  server as target, assert the lifecycle contract: emits `Ready` first, urls non-empty, `stop`
  cancellation returns within 5s, temporary endpoints clean up their provider state (mockable
  assertion hook). Run it over MockDriver + fixture-backed tailscale/cloudflare fakes.
  Validation: `cargo test -p wormhole-core drivers::` green.

- [ ] **V5 — Doctor + docs.** Extend `wormhole doctor` with provider checks (binary found,
  version, login state, funnel attr). `docs/providers.md`: setup guide per provider (exact
  commands to log in / grant funnel), the qualifier syntax table
  (`tailscale`, `tailscale:funnel`, `cloudflare`, `cloudflare:quick|named`), and a
  per-driver capability matrix (http/tcp, persist, custom domains, inspection).
  Validation: docs commands match implementation flags (manual pass).

## Acceptance gate

```bash
cargo test -p wormhole-core --locked \
&& cargo clippy -p wormhole-core --all-targets --locked -- -D warnings
```

Manual (documented, not CI): on a machine with tailscale + cloudflared installed,
`wormhole http 3000 --endpoint tailscale --endpoint cloudflare --json` returns two URLs; both
serve the local target; `wormhole down` removes the tailscale serve entry
(`tailscale serve status` clean) and kills cloudflared. Commit `feat(drivers): tailscale,
cloudflare`.
