# Stage 07 — Permanent forwards, webhook buffering, inspection & replay

**Goal:** the webhook story that makes wormhole better than grab-and-forget tunnels:
persistent reserved domains that survive reconnects/reboots, server-side buffering of webhook
deliveries while the client is offline (replayed on reconnect), and ngrok-style request
inspection + replay from the CLI/local API.

**Depends on:** 03, 05. **Blocks:** 08.

## Semantics (locked)

| | Temporary | Persistent |
|---|---|---|
| Created by | default | `--persist` / `persist = true` |
| Hostname/port | random, freed on disconnect | reserved to the client **key**; reclaimed on reconnect (S5) |
| Server keeps it | while session lives | in redb until `wormhole down --forget` or server-side revoke |
| Client offline | 404 (gone) | 503 page — or **buffering** if a `BufferPolicy` is set |
| Daemon restart | not restored | restored automatically (D2) |
| Reconnect backoff | 5 attempts | forever |

Webhook buffering (persistent + `buffer = {...}` only):
- While offline, the edge accepts the request **fully** (body up to `max_body_bytes`, read
  deadline 30s), commits it to redb `webhook_buffer` with a monotonically increasing seq, and
  responds `202 Accepted` + `Wormhole-Buffered: true` **only after the redb transaction is
  durably committed** — a crash can never lose an acknowledged webhook (crash-after-202 test
  required). Non-idempotent semantics are the user's opt-in choice.
- Caps enforced at ingress, atomically: per-bind `max_requests` (**reject new** with 503 —
  never silently drop old), `max_body_bytes` (413), `ttl` (pruned lazily + by the daily sweep),
  plus server-config global quotas: `buffer_max_bytes_per_key` and `buffer_max_bytes_total`
  (503 when exceeded) so buffering can't exhaust the disk.
- Stored record (versioned, serde_json in redb): `BufferedRequest { v: 1, method, uri,
  http_version, headers, body, seq, received_at }` (`http_version` is `HTTP/1.1` while the
  edge is h1-only) — reconstructed as an HTTP/1.1 request on replay. The
  offline edge path serves multiple sequential requests per keep-alive connection through the
  same hyper service (normal h1 semantics).
- Drain **starts per bind only after the `BindReady`/`BindActive` barrier** on the new session
  (never at handshake or merely after `Bound` — the client must install target routing). Then
  **serialized per bind** — one in-flight delivery, strict seq order, head-of-line blocks the
  rest. Each delivery goes over a normal data stream with
  `StreamHeader.buffered = Some(seq)`; the client forwards to the local app and sends
  `AckBuffered { bind, seq }` only after receiving the app's **complete response** (any status
  — an app-level 4xx/5xx still counts as delivered). The server deletes the row **only on
  ack**; transport failure mid-delivery → retry same seq on next reconnect (at-least-once,
  truly). Original caller already got 202; the app's response is discarded. Progress surfaces
  as `Event::BufferedDelivery` ("replayed 12 buffered webhooks").
- If local delivery exhausts its retry/deadline policy, the client sends `NackBuffered`; the
  server atomically moves that durable row to `webhook_failed` and continues with the next
  sequence. Failed rows never auto-retry. Keep management deliberately small:
  `wormholed webhooks failed ls|retry|rm` over the local admin socket; retry moves one row back
  to the active queue, rm requires its exact bind+seq. `Bound.failed_buffered` and an Event
  surface the count to the client without copying failed bodies into client storage.
  Failed rows continue counting against the same per-key/global byte quotas and original TTL,
  so the quarantine cannot grow without bound.
- Only for HTTP binds. TCP + buffer → config error.

Local delivery retries (client-side, wormhole-driver HTTP endpoints only — same scope as
inspection):
- Opt-in per endpoint: `retry = { attempts = 5, backoff = "500ms", max_backoff = "30s",
  on = ["connect-error", "5xx"], max_body = "1MiB", total_deadline = "60s" }`. Exponential
  backoff with full jitter, capped at `max_backoff`; `on` decides what counts as a failed
  delivery (connect-error always sensible; `5xx` opt-in for non-idempotent-tolerant apps).
- Applies to **both** live requests (the HTTP-aware client buffers the request body up to
  `max_body`, retries against the local target, and only
  then answers the caller — within `total_deadline`, else the last failure/504 goes back) and
  **buffered replays** (retries run before `AckBuffered`; exhaustion sends `NackBuffered`, so
  the server quarantines it durably and later sequence numbers continue).
- Requests with bodies over `max_body` are never retried (streamed through once, transparently).
- TCP endpoints: no retries (byte streams aren't replayable).

Edge auth (public-URL protection, enforced at the **relay edge**, HTTP binds only):
- Per endpoint: `auth = { basic = "user:pass" }` and/or `{ bearer = "<secret>" }` and/or signed
  share links. Checked **before** proxying and before webhook buffering; failures are 401
  (+`WWW-Authenticate: Basic` when basic is configured) or 403, constant-time compares, never
  logged with the presented secret. Webhook endpoints simply omit auth (Stripe can't do basic
  auth — their security is signature verification in your app).
- Signed links: the **client** generates a random `link_key` and mints
  `https://host/path?wh_token=b64(expiry_unix || hmac_sha256(link_key, host || expiry))`
  offline (`wormhole share <endpoint> --expires 24h`). Edge verifies token → sets a
  `wormhole_auth` HMAC-session cookie (scoped to the host, `Secure`, `HttpOnly`, expiry =
  link expiry, `SameSite=Lax`) → 302-redirects with `Cache-Control: no-store` and
  `Referrer-Policy: no-referrer` to the URL minus the token, and accepts the cookie thereafter
  (so assets/XHR on the page work). The grant is host-wide; `--path` only chooses the landing
  path. Expired/invalid → 403 static page.
- Any configured method grants access (basic OR bearer OR valid link/cookie).
- Server persistence never keeps raw basic passwords or bearer tokens: basic uses salted
  Argon2id, bearer uses SHA-256 + constant-time digest comparison. The link HMAC key must remain
  available to the edge and is protected by the redb file's service-user-only permissions.

Inspection (client-side, in the daemon; ngrok-4040 parity):
- Per-endpoint `inspect` flag (default from config; `--no-inspect` off). HTTP endpoints only.
- Memory-only ring: last **20 eligible exchanges per endpoint**, lost on daemon restart.
  Ignore GET/HEAD static assets by extension by default (`.js`, `.map`, `.css`, images, fonts,
  favicon); `capture_assets = true` / `--include-assets` opts in. The HTTP-aware driver already
  has typed heads/bodies: inspection adds bounded copies only, not another parser.
- A 32 MiB daemon-wide capture budget evicts the globally oldest records before per-endpoint
  count limits; capture can never grow with endpoint count.
- Retain the complete request body only up to `capture_body_max` (default 1 MiB) so replay is
  exact; larger requests store a 128 KiB prefix + `truncated=true` and cannot be replayed.
  Responses store heads + a 128 KiB prefix only.
- Provider drivers can't see traffic (it goes provider→app directly for tailscale/cloudflare
  quick? No — cloudflared/tailscale proxy to the local target themselves). Inspection therefore
  applies only to `wormhole`-driver endpoints. Document this loudly. (Optional parity trick —
  **excluded**, note in docs: route provider targets through a local intercepting proxy.)

## Tasks

- [x] **W1 — Server: persistent bind lifecycle** (`wormholed`). Implement reclaim-on-reconnect
  end-to-end (S5 defined it): `Bind { reservation: Some(id) }` with matching key fingerprint →
  adopt the Offline persisted row (works for random hostnames); an Online row rejects duplicate
  reclaim. Update `last_seen`. `Unbind { forget: true }` drops the reservation row. Offline persistent host →
  503 branch in `edge_https.rs` (already stubbed) gains the buffer check. Add
  `wormholed binds ls|rm [--json]` admin subcommand (via the S8 admin socket when serve runs,
  redb directly otherwise).
  Validation: integration test — bind persist (random host), drop connection, redb row
  survives, rebind by reservation reclaims the same hostname, other key's reservation refused,
  `binds ls` shows it, `forget` removes it.

- [x] **W2 — Server: webhook buffer.** `buffer.rs` in wormholed: store/drain per the semantics
  above (durable-commit-before-202, atomic quotas, serialized per-bind drain, delete-on-
  `AckBuffered`, quarantine-on-`NackBuffered`). Add `GET /v1/webhooks/failed`,
  `POST /v1/webhooks/failed/{bind}/{seq}/retry`, and matching DELETE to the local admin API +
  `wormholed webhooks failed ls|retry|rm`. Edge path: offline + policy → read full request
  (Hyper, body cap + deadline), commit, 202.
  Validation: integration tests — bind with buffer, disconnect, POST 3 webhooks (202s), 4th
  rejected at max_requests=3; reconnect → target receives the 3 **in order**, buffer empties
  only after acks; sever the connection mid-drain → un-acked seq redelivered on next connect;
  Nack seq 1 → it moves to failed while seq 2 delivers; retry seq 1 delivers once; kill -9 the
  server right after a 202 → webhook still present after restart; TTL expiry with 1s ttl;
  global byte quota rejection.

- [x] **W3 — Client: buffered delivery + ack.** The wormhole driver implements the ack side:
  forward buffered stream to the local app, await complete response, send
  `AckBuffered { bind, seq }`; retry/deadline exhaustion sends `NackBuffered`. Daemon counts
  deliveries per endpoint; expose in `GET /v1/endpoints` (`buffered_delivered`,
  `buffered_pending` from `Bound.pending_buffered`), print a line in `wormhole up` output
  ("replaying N buffered webhooks…").
  Validation: extend W2 e2e through the real client daemon (moves to stage 08 harness if
  simpler; leave a pointer).

- [x] **W4 — Inspection capture.** In the HTTP-aware `wormhole_driver.rs` path, collect from the
  typed request/response heads and bounded body taps into `CapturedRequest { id: uuid_v7,
  endpoint, ts, method, path, headers, body, body_truncated, resp_status, resp_headers,
  resp_body_prefix, resp_body_truncated, duration, delivery }`. Apply the static-asset filter
  before allocating body capture. A 101 captures the handshake and stops body capture while
  upgraded bytes continue untouched. Capture failure never breaks proxying.
  Records flow as `DriverEvent::Captured`; the daemon owns a `VecDeque` capped at 20 per
  endpoint. No JSONL sink and no restore.
  **Redaction:** header values for `authorization`, `cookie`, `set-cookie`, `x-api-key`
  replaced with `«redacted»` at capture time (raw never stored).
  Validation: typed-stream tests cover full replayable body, >1 MiB truncation/non-replayable,
  static asset ignored/default + included/override, header redaction, and 101 capture cutoff.

- [x] **W5 — Local API + CLI for requests.** Implement the stage-05 stubs: `GET /v1/requests`
  (filters: endpoint, since, limit), `GET /v1/requests/{id}` (bodies base64),
  `POST /v1/requests/{id}/replay` — daemon re-sends the captured request to the endpoint's
  current local target (Hyper client, 30s timeout), returns new status/duration. Reject replay
  with a clear `body_truncated` error unless the complete request body was retained. CLI:
  `wormhole requests [--follow]` (follow = poll with `since`), `wormhole replay <id>`,
  `wormhole requests clear`.
  Validation: NOT via mock driver (inspection is wormhole-driver-only) — use the in-process
  fake QUIC relay from C5's test infra: real wormhole-driver endpoint + local echo server,
  request through, appears in `wormhole requests --json`, replay returns 200 and the echo
  server saw it twice. Full-binary variant lands in the stage-08 harness.

- [x] **W6 — Docs.** `docs/webhooks.md`: the semantics table above, buffering guarantees
  (at-least-once on reconnect, original caller sees 202, ordering), retry semantics
  (when `5xx` retry is safe vs not — idempotency warning), inspection scope
  (wormhole driver only), worked Stripe-style example: persist + buffer + retry + `wormhole
  requests --follow` + replay loop for an agent.
  Validation: commands in doc exist.

- [x] **W7 — Local delivery retry engine** (client, `wormhole-core`). One reusable
  `RetryPolicy { attempts, backoff, max_backoff, on, max_body, total_deadline }` (serde,
  humantime durations) + `deliver_with_retry(req, target, policy)` used by both the live proxy
  path and the buffered-replay path in `wormhole_driver.rs`, per the "Local delivery retries"
  semantics above. Backoff = exponential with full jitter (share the implementation with C5's
  reconnect backoff — extract `core::backoff`). Retry outcomes feed the capture record
  (`delivery: ok | retried(n) | failed`) and a `DriverEvent::Log(warn)` per exhausted delivery.
  Config surface: `[defaults] retry` in global config, per-endpoint `retry` in `wormhole.toml`,
  `--retry "attempts=5,backoff=500ms"` CLI flag (compact form parsed with the same 20-line
  parser style as D6).
  Validation: unit tests with a flaky local server (fails N times then 200): connect-error
  retried to success; `5xx` only retried when opted in; deadline exceeded → 504 to caller;
  buffered replay exhaustion → `NackBuffered` + durable server failed row while later seq
  drains; oversized body streams once with no retry.

- [x] **W8 — Edge auth + signed share links.** Server: enforce `EdgeAuth` in `edge_https.rs`
  per the semantics above on **every** Hyper request (module `edge_auth.rs`; before buffering
  or opening a client stream). Convert wire auth secrets to `PersistedEdgeAuth` verifiers before
  writing redb; persisted bind specs contain no raw basic/bearer secret, and
  all API/debug serializers redact it. Client: `--auth basic:user:pass`,
  `--auth bearer:<secret>`, safer `--auth-file`/`WORMHOLE_AUTH`, and
  `auth = { basic = "...", links = true }` in `wormhole.toml` (`links = true` → generate and
  persist a `link_key` with the endpoint); `wormhole share <service|endpoint> [--expires 24h]
  [--path /] [--json]` mints and prints the signed URL locally (no server round-trip).
  Validation: integration tests — basic 401→200 with credentials; bearer; valid link →
  cookie → follow-up request without token succeeds; expired link 403; auth rejected before
  buffer (offline endpoint + bad creds → 401, nothing buffered); webhook endpoint without
  auth unaffected.

## Acceptance gate

```bash
cargo test -p wormholed -p wormhole-cli -p wormhole-core --locked \
&& cargo clippy --all-targets --locked -- -D warnings
```

Commit `feat: persistent forwards, webhook buffering, inspection & replay`.
