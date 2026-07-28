# Wormhole local API

The per-user `wormhole` daemon serves HTTP/1.1 over a private Unix socket. It has no TCP
listener and no UI. The CLI is a client of this API.

## Connection and authentication

Socket location:

- `$XDG_RUNTIME_DIR/wormhole/daemon.sock` when `XDG_RUNTIME_DIR` is set
- `~/Library/Application Support/wormhole/daemon.sock` on macOS
- `~/.local/state/wormhole/daemon.sock` on other Unix systems

Set `WORMHOLE_STATE_DIR` to override the directory. The directory is mode `0700`, and the
socket and `api-token` are mode `0600`. Every request requires the token:

```bash
STATE="${WORMHOLE_STATE_DIR:-$XDG_RUNTIME_DIR/wormhole}"
TOKEN=$(cat "$STATE/api-token")
curl --unix-socket "$STATE/daemon.sock" \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost/v1/status
```

Any same-UID process that can read `api-token` has full daemon control. This is intentional:
agents run with the user's authority. Never copy the token into logs or project files.

## Routes

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/status` | Version, uptime, PID, and counts |
| GET | `/v1/services` | Desired services and active endpoints |
| GET | `/v1/services?watch=1` | Wait up to 30 seconds for a status change |
| POST | `/v1/services` | Create a service and wait up to 30 seconds for endpoints |
| DELETE | `/v1/services/{name}?forget=1` | Close a service; optionally delete reservations |
| GET | `/v1/endpoints?service={name}` | Flat active endpoint list |
| DELETE | `/v1/endpoints/{id}?forget=1` | Close one endpoint |
| GET | `/v1/interfaces` | Refreshed interface aliases |
| GET | `/v1/doctor` | Structured diagnostic checks |
| GET | `/v1/requests` | Memory-only captures (implemented in Stage 07) |
| GET | `/v1/requests/{id}` | One capture (Stage 07) |
| POST | `/v1/requests/{id}/replay` | Replay one capture (Stage 07) |
| DELETE | `/v1/requests` | Clear memory-only captures |
| POST | `/v1/reload` | Reload configuration without dropping live endpoints |
| POST | `/v1/shutdown` | Gracefully drain and stop |
| GET | `/v1/openapi.json` | OpenAPI document |
| GET | `/docs` | Scalar API reference over the same UDS |

The committed specification is [`local-api.openapi.json`](local-api.openapi.json).

## Create a service

```bash
curl --unix-socket "$STATE/daemon.sock" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "project_id": "agent-worktree",
    "service": {"name":"web","target":{"kind":"port","value":3000},"proto":"http"},
    "endpoints": [{
      "proto":"http","driver":"wormhole","remote":"myvps","host":"web",
      "persist":"persistent","inspect":false
    }]
  }' \
  http://localhost/v1/services
```

Successful responses are JSON. Errors use a stable envelope and appropriate HTTP status:

```json
{"error":{"code":"conflict","message":"service already exists: web"}}
```

Timestamps, when present, are RFC 3339 values generated with `jiff`. The `/v1` contract is
additive: existing fields and meanings are not changed.

See [agent integration](agents.md), the [configuration reference](config-reference.md), and
[webhook inspection and replay](webhooks.md).
