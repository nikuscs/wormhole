# Stage 05 — Daemon & CLI (`wormhole-cli`)

**Goal:** the whole user/agent surface: one `wormhole` binary that transparently auto-spawns a
per-user daemon, a token-authenticated local HTTP-over-unix-socket API (ngrok-4040-style), the
full CLI with `--json` everywhere, `wormhole run -- <cmd>` portless-style port
handling, and project `wormhole.toml` with `up`/`down`. Agents are the primary user: every
command must be scriptable, deterministic, and self-describing.

**Depends on:** 03, 04. **Blocks:** 06, 07.

## Process model (locked)

- **Headless by design.** The daemon has no UI and never will — its surface is the local API
  plus operational logs (request capture remains memory-only). Any future GUI/TUI is a separate
  client of that API.
- Socket: `$XDG_RUNTIME_DIR/wormhole/daemon.sock`, fallback
  `~/Library/Application Support/wormhole/daemon.sock` (macOS) /
  `~/.local/state/wormhole/daemon.sock`. Dir 0700 (owned, `lstat`-verified — refuse symlinked
  dirs), socket 0600.
- **Auto-spawn:** any CLI command needing the daemon tries the socket; on connect failure it
  spawns `current_exe() daemon run --detach` (double-fork + `setsid` via `nix`, stdio to
  `state_dir/daemon.log`), then waits for the socket (150ms poll, 3s cap). The daemon takes an
  exclusive `flock` on `daemon.lock` and **holds it for its lifetime**; a stale socket file is
  unlinked only while holding that lock (kills the stale-socket/symlink race). Spawn-race
  losers just connect.
- **Local API auth:** file permissions gate the socket, plus a bearer token: daemon writes a
  random token to `state_dir/api-token` (0600) at boot; every request needs
  `Authorization: Bearer <token>`. Trust boundary is explicit: any same-UID process that can
  read the token has full control — that is accepted and documented (agents run as you).
- `--foreground` on tunnel commands = run the tunnel manager **in-process**, no daemon, no
  socket, Ctrl-C tears down. For supervisors/one-offs.
- Daemon persistence: on graceful shutdown and every state change, persist desired services to
  `state_dir/state.redb`; `daemon run` restores persistent-marked services on boot (temporary
  ones are not restored).
- `daemon reload`: re-read config, apply diff without dropping live endpoints (LocalCan parity).

## Local API (HTTP over UDS; axum 0.8)

The CLI is a thin client of this API; agents may also `curl --unix-socket` it directly.
Document it in `docs/local-api.md` (task D8).

| method & path | body / query | returns |
|---|---|---|
| `GET /v1/status` | | daemon version, uptime, counts |
| `GET /v1/services` | | services + their endpoints (ActiveEndpoint JSON) |
| `POST /v1/services` | `{service, endpoints: [EndpointSpec]}` | created endpoints (waits for Ready, 30s cap) |
| `DELETE /v1/services/{name}` | `?forget=1` drops reservations too | closed |
| `DELETE /v1/endpoints/{id}` | `?forget=1` | closed |
| `GET /v1/endpoints` | `?service=` | flat endpoint list |
| `GET /v1/interfaces` | | alias list (C3) |
| `GET /v1/doctor` | | DoctorCheck list |
| `GET /v1/requests` | `?endpoint=&limit=&since=` | captured requests (stage 07) |
| `GET /v1/requests/{id}` | | captured request/response, bodies base64 + truncation flags |
| `POST /v1/requests/{id}/replay` | | replay result (stage 07) |
| `DELETE /v1/requests` | | clear memory-only capture ring |
| `POST /v1/shutdown` | | drains and exits |

Errors: `{"error": {"code": "conflict", "message": "..."}}` with proper HTTP status. All
timestamps jiff/RFC3339. Version the path (`/v1`) — never break it, add fields only.

**OpenAPI:** every route/type is annotated with `utoipa`; the daemon serves
`GET /v1/openapi.json` and a Scalar reference UI at `GET /docs` (UDS-only like everything else
— API docs don't violate the headless rule). The generated spec is also committed at
`docs/local-api.openapi.json` with a unit test asserting the committed file matches the
generated one (regenerate when it drifts). Same treatment applies to the `wormholed` admin API
(stage 03 S8).

## CLI surface

```
wormhole http <target> [flags]        # target: 3000 | host:3000 | alias:3000
wormhole tcp  <target> [flags]
wormhole run  [--name n] [--app-port p] -- <cmd> [args…]   # portless-style wrap
wormhole up   [service…]              # from wormhole.toml
wormhole down [service|endpoint-id…] [--forget]   # --forget also drops server-side
                                      # reservations (proto Unbind{forget}); no args =
                                      # everything in this project's wormhole.toml
wormhole ls   [--json] [--watch]
wormhole status [--json]
wormhole inspect|requests [--endpoint e] [--follow] [--json]     # stage 07
wormhole replay <request-id>                                     # stage 07
wormhole interfaces [--json]
wormhole remote add <name> <host:port> [--identity path] | ls | rm | test <name>
wormhole key show [--json] | rotate
wormhole doctor [--json]
wormhole daemon run [--detach] | stop | status | reload | logs [-f]
wormhole completions <shell>
```

Shared tunnel flags: `--endpoint <spec>` repeatable (`wormhole`, `wormhole:myvps`,
`tailscale`, `tailscale:funnel`, `cloudflare`, `cloudflare:quick`), `--host <name>`,
`--persist`, `--no-inspect`, `--buffer <n>`, `--retry "attempts=5,backoff=500ms"`,
`--auth basic:user:pass` / `--auth bearer:<secret>` (edge-enforced, stage 07 W8; also accept
`--auth-file` and `WORMHOLE_AUTH` so secrets need not appear in shell history/process args),
`--remote <r>` (shorthand for default wormhole endpoint), `--foreground`, `--json`,
`--name <service>`. Plus `wormhole share <service|endpoint> [--expires 24h]` (W8).
No `--endpoint` → `[defaults].drivers` from config.

Output contract (via F4 `output.rs`): human = comfy-table/plain lines; `--json` = stable serde
structs (the same ones the local API returns — reuse types). **Exit codes:** 0 ok; 1 generic;
2 usage; 3 daemon unreachable/spawn failed; 4 auth/denied by server; 5 endpoint failed to become
Ready; 6 partial (some endpoints Ready, some failed — body still lists all).

## `wormhole.toml` (project file)

```toml
# name inference when absent: package.json name > git repo dir name; subdomain gets
# git branch appended when not on the default branch:  web-fix-ui  (portless-style, worktree-first)
name = "myapp"

[[service]]
name = "web"
target = "3000"                  # or "tailscale:8080", "db-box:5432"
proto = "http"

  [[service.endpoint]]
  driver = "wormhole"
  remote = "myvps"
  host = "myapp"                 # -> myapp.tun.example.com ; branch suffix auto-added
  persist = true
  buffer = { max_requests = 200, max_body = "1MiB", ttl = "2h" }
  retry = { attempts = 5, backoff = "500ms", max_backoff = "30s", on = ["connect-error", "5xx"] }

  [[service.endpoint]]
  driver = "tailscale"

  [[service.endpoint]]
  driver = "cloudflare"          # quick tunnel by default

[[service]]
name = "db"
target = "5432"
proto = "tcp"
  [[service.endpoint]]
  driver = "wormhole"
  persist = true
```

## Tasks

- [ ] **D1 — clap tree + config wiring.** Derive-based command tree exactly as above (stub
  stage-07 commands with a "not yet implemented" error via a dedicated `Unimplemented` error —
  remember `todo!()` is denied). Global flags `--json`, `--config`, `-q/-v`. `tracing` to stderr
  only (`RUST_LOG`/`-v`), never stdout (stdout is data).
  Validation: `wormhole --help` snapshot test (insta); every subcommand `--help` renders.

- [ ] **D2 — Daemon runtime.** `daemon.rs`: build `DriverRegistry` (wormhole driver now; 06 adds
  more behind the same constructor), `TunnelManager`, axum-over-UDS server
  (`axum::serve(UnixListener...)`) with the bearer-token middleware, lock/socket hygiene per
  the process-model section, versioned state persistence + restore (same backup/temp/fsync/
  atomic-replace migration rule as server S2), SIGTERM drain, `daemon.log`
  rotation (simple: truncate at 10MB).
  Request capture is memory-only (stage 07): no JSONL body archive and nothing restored after a
  daemon restart.
  Validation: `wormhole daemon run` in foreground serves `GET /v1/status` (with token; 401
  without); kill -TERM exits cleanly; second `daemon run` refuses (lock held).

- [ ] **D3 — Auto-spawn client.** `client.rs`: `DaemonClient::ensure() -> Self` implementing the
  connect-or-spawn dance + typed methods per API route (reqwest is HTTP-over-TCP-oriented; use
  hyper-util client over UnixStream, or `reqwest` with its unix-socket support if available —
  check; otherwise a 60-line hyper client is fine).
  Validation: integration test in `crates/wormhole-cli/tests/`: with `WORMHOLE_STATE_DIR` in a
  tempdir, `wormhole status` auto-spawns daemon (assert_cmd), second call reuses it (same pid in
  status output), `wormhole daemon stop` ends it.

- [ ] **D4 — Tunnel commands.** `http`/`tcp`/`ls`/`down`/`status` against the client. `http 3000`
  default endpoint set → POST /v1/services → print urls (or JSON). `--foreground`: build
  manager in-process, print urls, wait for Ctrl-C. Partial failures → exit 6 with per-endpoint
  status. `ls --watch`: re-render on `subscribe()` events via long-poll `GET /v1/services?watch=1`
  (add `watch` query: hangs until change or 30s).
  Validation: e2e-lite test with mock driver registered in daemon under a hidden
  `WORMHOLE_ENABLE_MOCK_DRIVER=1` env (test-only escape hatch, documented in AGENTS.md).

- [ ] **D5 — `wormhole run`** (the portless steal). Use a stable local indirection listener so
  discovering a different child port never changes any public provider URL. Flow:
  1. `--app-port` given → skip alloc, just wrap + expose.
  2. Allocate `app_port` in 4000–4999 and a separate loopback `proxy_port`; expose providers to
     `proxy_port` first, then inject `PORT=app_port`, `HOST=127.0.0.1`, and the ready
     `WORMHOLE_URL`. The indirection listener initially targets `app_port`.
  3. Framework flag injection table (extend as needed):
     `vite|astro|ng serve|react-router dev` → append `--port <p> [--host 127.0.0.1]` when the
     user command matches and no explicit port flag present.
  4. Spawn child (inherit stdio), `wait_for_listener(port, 60s)`.
  5. If nothing listens on `app_port` but the child is alive → `detect_child_port(pid)` for 10s;
     atomically retarget only the local indirection listener. Never close/recreate providers.
  6. Child exit → close endpoints, mirror child's exit code.
  Name inference: `--name` > wormhole.toml `name` > package.json > dir name; branch suffix rule
  from the wormhole.toml section.
  Validation: integration test wrapping `python3 -m http.server` (ignores PORT env → exercises
  detection fallback) and a tiny script that honors `$PORT` (happy path).

- [ ] **D6 — `wormhole up`/`down` + project config.** Parse `wormhole.toml` (serde structs shared
  with C1 merge), `up` = expose all (or named) services, `down` = close this project's services
  by an exact `ProjectId` (hash of canonical worktree root, stored with desired state — never a
  name-prefix match). Humantime parsing for `ttl`, byte-size parsing for `max_body`
  (write a 20-line parser; don't add a dep).
  Validation: unit tests for parse + name/branch inference (fake git dir in tempdir);
  integration: up/ls/down round-trip with mock driver.

- [ ] **D7 — remotes/key/doctor/interfaces/completions.** Straight mapping onto core (C2/C3/C7)
  + `clap_complete` for `completions`. `remote test` = QUIC dial + full handshake, report
  latency. `key rotate`: generate new identity, print both fingerprints and a reminder to
  re-authorize on servers (do NOT auto-revoke anywhere).
  Validation: `wormhole interfaces --json` lists `localhost`; completions generate for
  zsh/bash/fish without panic (snapshot the zsh one).

- [ ] **D8 — Docs for agents.** `docs/local-api.md` (full route reference with curl examples
  incl. `curl --unix-socket`), `docs/agents.md`: recipes — "expose current worktree on 3 URLs",
  "wrap a dev server", "poll requests as JSON", each as copy-pasteable commands with expected
  JSON shapes.
  Validation: every documented command exists in `--help` output (grep script or by hand).

- [ ] **D9 — CLI polish (humans get pretty, agents get plain).** All through `output.rs`:
  colors via `owo-colors`, spinners/progress via `indicatif` (waiting for endpoints to become
  Ready), status glyphs (`✓` online, `✗` error, `↻` reconnecting, `⏸` offline, `🌀` for the
  wormhole banner line) and colorized URLs in `ls`/`up`/`http` output. Rules: auto-disable all
  styling when stdout is not a TTY or `NO_COLOR` is set (`--json` is always plain by
  definition); indicatif writes to stderr only, so piped stdout stays clean.
  Error rendering: one-line red `error:` + a gray `hint:` line when we have one (e.g. driver
  binary missing → install hint, stage 06). Before styling, skim xAI's open-source Grok Build
  (github.com/xai-org/grok-build, Apache-2.0 Rust TUI) for output/UX patterns worth copying —
  steal taste, not code. Note for a future `wormhole tui`: its separate-TUI-crate architecture
  (`xai-grok-pager` over the runtime) is the model — a ratatui crate consuming our local APIs,
  out of scope for this plan.
  Validation: `wormhole ls` piped to a file contains zero ANSI escapes; TTY snapshot test with
  forced `CLICOLOR_FORCE=1` (insta) for one representative command.

## Acceptance gate

```bash
cargo test -p wormhole-cli --locked \
&& cargo clippy -p wormhole-cli --all-targets --locked -- -D warnings
```

Manual smoke (scripted in stage 08): `wormhole http 3000 --foreground --endpoint wormhole:local`
against a local self-signed `wormholed` prints a working URL. Commit
`feat(cli): daemon, local API, full CLI`.
