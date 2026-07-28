# Wormhole

**ngrok for agents and worktrees: simple, fast, and secure.** Wormhole exposes local HTTP(S)
and TCP services through your own relay, Tailscale, Cloudflare, or all three at once. It is a
CLI-first tool with deterministic JSON and local APIs, built for automation rather than a web UI.

## Quickstart

Install the relay on the VPS:

```console
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/nikuscs/wormhole/releases/latest/download/wormholed-installer.sh | sh
```

Run it after pointing `tun.example.com` and `*.tun.example.com` at the VPS:

```console
wormholed init
wormholed key authorize "$(pbpaste)" --name laptop
wormholed serve
```

Install and configure a client, then expose services:

```console
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/nikuscs/wormhole/releases/latest/download/wormhole-cli-installer.sh | sh
wormhole remote add myvps tun.example.com:443
wormhole http 3000
wormhole http 3000 --endpoint wormhole --endpoint tailscale --endpoint cloudflare
wormhole run -- bun run dev
wormhole up
```

The first HTTP command prints a URL such as
`https://misty-otter-3f2a.tun.example.com`. `wormhole run` allocates and injects `PORT` before
starting the process; `wormhole up` starts services from the current worktree's `wormhole.toml`.

## Why Wormhole?

| Capability | Wormhole | ngrok | LocalCan | portless |
| --- | --- | --- | --- | --- |
| Self-hosted public relay | Yes | Enterprise offering | No | No |
| HTTP and raw TCP forwarding | Yes | Yes | Yes | HTTP-focused |
| One command, multiple providers | Wormhole + Tailscale + Cloudflare | ngrok endpoints | LocalCan tunnel | ngrok/Tailscale integrations |
| Worktree-scoped declarative services | Yes | No | No | Worktree-friendly local routing |
| Request inspection and replay | Local, CLI/API | Hosted inspector | Desktop tooling | No |
| Durable offline webhook buffering | Yes | No | No | No |
| Deterministic JSON and local Unix APIs | Yes | CLI/API | CLI | CLI |

The comparison reflects publicly documented features and intentionally does not compare pricing
or enterprise-only limits.

## Documentation

- [Install and operate a relay](docs/server-setup.md)
- [Configuration reference](docs/config-reference.md)
- [Provider drivers](docs/providers.md)
- [Webhook buffering, inspection, and replay](docs/webhooks.md)
- [Local daemon API](docs/local-api.md)
- [Agent integration](docs/agents.md)
- [Implementation plan and security decisions](docs/plan/00-overview.md)

## Development

Rust 1.97 or newer is required. Run the repository gates with:

```console
make lint
make test
make e2e
```

The staged implementation plan lives in [`docs/plan`](docs/plan/00-overview.md).
