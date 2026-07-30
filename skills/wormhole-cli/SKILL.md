---
name: wormhole-cli
description: Expose local HTTP/TCP services and dev commands with Wormhole. Use for public or Tailscale URLs, stable worktree tunnels, relay onboarding/deployment, diagnostics, inspection, replay, and cleanup.
license: MIT
compatibility: Requires the wormhole CLI; providers may require a configured relay, Tailscale, or cloudflared.
metadata:
  version: "1.3.0"
---

# Wormhole CLI

Run from the project or worktree directory. Keep foreground commands attached and return the URL as soon as it is ready.

## Choose one command

| User wants | Run |
| --- | --- |
| Start and expose a dev command | `wormhole run -- <exact command>` |
| Expose an existing HTTP server | `wormhole http <PORT>` |
| Expose an existing TCP server | `wormhole tcp <PORT>` |
| Start `wormhole.toml` services | `wormhole up` |

Prefer `wormhole run`. Preserve everything after `--` exactly. Wormhole allocates a free port in `4000-4999`, injects supported framework port/host settings, waits for the listener, and cleans up when the child exits. Explicit app flags win.

```sh
wormhole run -- bun run dev
wormhole run -- npm run dev
wormhole http 3000
wormhole tcp 5432
```

## Tailscale: do not ask about port 443

When the user asks for Tailscale, use:

```sh
wormhole run --endpoint tailscale -- <exact command>
wormhole http <PORT> --endpoint tailscale
```

Wormhole automatically keeps an existing Tailscale Serve mapping on 443 and selects a stable alternate HTTPS port. Never ask to replace 443, choose a port manually, or remove another service.

If Wormhole prints an exact Tailscale plan but fails only its readiness check, run that exact `tailscale serve` plan once as the fallback. Keep it attached. This is already authorized by the user's Tailscale exposure request; do not ask again about the alternate port.

```sh
tailscale serve --https=<SELECTED_PORT> http://127.0.0.1:<LOCAL_PORT>
```

Verify the rendered page, not only the status code. Stop the attached Serve process to clean up.

## Other provider overrides

Use defaults unless the user requests a provider:

```sh
wormhole http <PORT> --endpoint tailscale:funnel
wormhole http <PORT> --endpoint cloudflare:quick
wormhole http <PORT> --endpoint cloudflare:named --host <FQDN> --persist
wormhole http <PORT> --endpoint wormhole --endpoint tailscale
```

Put endpoint flags before `--` with `wormhole run`.

Temporary HTTP binds served by Wormhole relays return:

```text
X-Robots-Tag: noindex, nofollow, noarchive, nosnippet
```

Persistent binds preserve the origin policy. Noindex is not access control.

Vite host allowance is automatic. For Next.js development, derive `allowedDevOrigins` from `new URL(process.env.WORMHOLE_URL).hostname`; Wormhole relays support HMR WebSockets.

## Diagnose once

Use JSON; do not parse human tables:

```sh
wormhole --json doctor
wormhole --json status
wormhole --json ls
wormhole --json remote ls
wormhole --json remote test <NAME>
```

Fix the reported prerequisite or return the exact error. Do not switch providers, guess ports, kill unrelated processes, or retry repeatedly.

## Inspect traffic

```sh
wormhole --json requests
wormhole --json inspect <REQUEST_ID>
wormhole --json replay <REQUEST_ID>
```

## Remotes and Cloudflare relay deployment

Check remotes before onboarding. Invite tokens are secrets: never print, save, commit, or repeat them.

```sh
wormhole remote add
WORMHOLE_INVITE='<token>' wormhole remote add <NAME> <HOST:PORT>
```

Cloudflare deployment requires an explicit request and separate approval for the live mutation:

```sh
wormhole relay deploy cloudflare --domain <NAMESPACE> --dry-run
wormhole relay deploy cloudflare --domain <NAMESPACE>
```

Prefer a dedicated namespace such as `wormhole.example.com`. Use `--manual-dns` only for operator-managed DNS and `--yes` only when explicitly requested. Let Wormhole manage Wrangler, routes, secrets, verification, enrollment, and rollback.

## Cleanup and guardrails

- `wormhole run` and attached temporary commands clean up when stopped.
- For daemon endpoints, run `wormhole --json ls`, then `wormhole down <EXACT_ID>`.
- Never run untargeted `wormhole down` or add `--forget` without explicit permission.
- Public exposure must be explicitly requested.
- Do not expose admin ports, databases, credentials, or private services without confirmation.
- Do not create share links, change authentication, remove remotes, rotate keys, or stop the daemon unless requested.

Return only the URL, provider, temporary/persistent state, and cleanup command when cleanup is not automatic.
