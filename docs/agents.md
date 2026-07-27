# Wormhole recipes for agents

Every command is non-interactive and supports global `--json`. JSON is written to stdout;
diagnostics are written to stderr. A command that needs the daemon starts it automatically.

## Expose the current worktree on three URLs

```bash
wormhole http 3000 --name web \
  --endpoint wormhole:myvps \
  --endpoint tailscale:funnel \
  --endpoint cloudflare:quick \
  --persist --json
```

Shape:

```json
[
  {"id":"019...","service":"web","driver":"wormhole","urls":["https://web.example.com"],"status":"online","since":"..."},
  {"id":"019...","service":"web","driver":"tailscale","urls":["https://host.ts.net"],"status":"online","since":"..."},
  {"id":"019...","service":"web","driver":"cloudflare","urls":["https://random.trycloudflare.com"],"status":"online","since":"..."}
]
```

Provider drivers are added in Stage 06; until then, use the Wormhole endpoint.

## Wrap a development server

```bash
wormhole run --name web --endpoint wormhole:myvps -- npm run dev
```

Wormhole allocates and injects `PORT` and `HOST`, establishes the public URL before starting
the child, and sets `WORMHOLE_URL`. If the framework ignores `PORT`, Wormhole detects its
listener and retargets a stable loopback proxy without changing the public URL. The command
exits with the child's exit code and closes its endpoints.

## Bring up a project

Commit `wormhole.toml`, then run:

```bash
wormhole up --json
wormhole ls --json
wormhole down --json
```

`down` with no arguments closes only services whose exact worktree `ProjectId` matches the
current canonical worktree root.

## Poll captured requests as JSON

Request capture and replay are implemented in Stage 07. The stable commands are already
reserved:

```bash
wormhole requests --endpoint 019abc --json
wormhole replay 019request --json
```

The local API equivalent is:

```bash
STATE="${WORMHOLE_STATE_DIR:-$XDG_RUNTIME_DIR/wormhole}"
TOKEN=$(cat "$STATE/api-token")
curl --unix-socket "$STATE/daemon.sock" \
  -H "Authorization: Bearer $TOKEN" \
  'http://localhost/v1/requests?endpoint=019abc&limit=100'
```

Expected collection shape after Stage 07:

```json
[{"id":"019...","endpoint":"019abc","method":"POST","uri":"/hook","captured_at":"..."}]
```

## Health and discovery

```bash
wormhole status --json
wormhole doctor --json
wormhole interfaces --json
wormhole remote ls --json
wormhole key show --json
```

Use exit codes in automation: `0` success, `2` usage, `3` daemon unavailable, `4` denied,
`5` no endpoint ready, and `6` partial endpoint readiness.
