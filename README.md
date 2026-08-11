<p align="center">
  <img src=".github/assets/app-icon.svg" width="128" height="128" alt="Wormhole">
</p>

<h1 align="center">Wormhole</h1>

<p align="center">
  <strong>Secure tunnels for agents, automation, and worktrees.</strong><br><br>
  Expose local HTTP(S) and TCP services through your own relay, Tailscale, Cloudflare,<br>
  or all three at once—with stable worktree URLs and automation-first APIs.
</p>

<p align="center">
  <a href="#development"><img src="https://img.shields.io/github/checks-status/nikuscs/wormhole/main?branch=main&style=flat-square&label=Signoff" alt="Latest main signoff status"></a>
  <img src="https://img.shields.io/badge/Rust-1.97%2B-orange?style=flat-square" alt="Rust 1.97+">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT license">
</p>

## Start in 2 minutes

### 1. Install

Homebrew adds `nikuscs/tap` automatically. Wormhole is a formula; the unrelated `wormhole` cask is
not this project.

```console
brew install nikuscs/tap/wormhole
```

Update or remove it:

```console
brew upgrade wormhole
brew uninstall wormhole
```

Standalone installer:

```console
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/nikuscs/wormhole/releases/latest/download/wormhole-cli-installer.sh | sh
```

Build both binaries from source:

```console
make install
```

### 2. Install the agent skill

```console
npx skills add nikuscs/wormhole --skill wormhole-cli
```

Use `--global` for all projects. Update either installation with:

```console
npx skills update wormhole-cli
npx skills update wormhole-cli --global
```

Works with Claude Code, Codex, Cursor, GitHub Copilot, Pi, and other Agent Skills clients.

### 3. Connect to a relay

Show or create this machine's identity:

```console
wormhole key show
```

Create an invite on the relay, then add it on the client:

```console
# On the relay server (single use, 10-minute default expiry):
wormholed invite create --name laptop

# On the client:
wormhole remote add myvps tun.example.com:443 --invite <token>
wormhole domains
```

Run `wormhole remote add` alone for the interactive wizard. Scripts must pass `NAME`, `ADDR`, and
the invite. Useful relay commands:

- Reusable invite: `wormholed invite create --name personal-devices --reusable`
- Inspect invites: `wormholed invite ls`
- Revoke one: `wormholed invite revoke <invite-id>`
- Break-glass authorization: `wormholed key authorize "<public-key>" --name laptop`

Invites are shown once and stored only as digests. The first relay becomes the default;
`wormhole domains` lists its public domains. Control uses QUIC with secure WebSocket fallback.
Config lives at `~/.config/wormhole/config.toml`; keys live at
`~/.config/wormhole/keys/`. Override config with `WORMHOLE_CONFIG` or `--config PATH`.

### 4. Expose something

Existing service:

```console
wormhole http 3000
```

Example result: `https://misty-otter-3f2a.tun.example.com`.

Development command:

```console
wormhole run -- bun run dev
```

`wormhole run` sets `PORT`, starts the child, detects its listener, exposes it, and cleans up on exit.
It injects `WORMHOLE_URL`, `APP_URL`, and `VITE_APP_URL`, plus detected framework aliases:
`NEXT_PUBLIC_{APP,SITE}_URL`, `NUXT_PUBLIC_{APP,SITE}_URL`, `PUBLIC_{APP,SITE}_URL`, or
`EXPO_PUBLIC_APP_URL`. Injected values override project `.env` files. Compatible `--port` and
`--host` flags are supplied for common frameworks; explicit flags win.
Temporary relay endpoints set `X-Robots-Tag` to `noindex, nofollow, noarchive, nosnippet`. This is
not access control.

Declarative worktree project:

```console
wormhole up
```

This starts the current worktree's `wormhole.toml` services.

## Provider commands

A Wormhole relay is optional for Tailscale and Cloudflare:

```console
wormhole http 3000 --endpoint tailscale
wormhole http 3000 --endpoint tailscale:funnel
wormhole http 3000 --endpoint cloudflare:quick
wormhole http 3000 --endpoint cloudflare:named --host app.example.com --persist
wormhole http 3000 --endpoint local
wormhole http 3000 --endpoint local --tld test
wormhole http 3000 --endpoint wormhole --endpoint tailscale --endpoint cloudflare
```

Local endpoints default to `*.localhost`, which browsers resolve to loopback with no DNS or hosts
entry, and treat as a secure context so service workers and `crypto.subtle` work over plain HTTP.

On Linux this applies to browsers only: glibc resolves `localhost` but not `app.localhost`, so
`curl` and other command-line clients need a hosts entry even on the default suffix.

`--tld` takes any suffix, including a multi-segment domain:

```console
wormhole http 3000 --endpoint local --tld test
wormhole http 3000 --endpoint local --tld internal
wormhole http 3000 --endpoint local --tld dev.example.com
```

`.test` (RFC 2606) and `.internal` (ICANN-reserved) are recommended because neither can ever be
delegated. A domain you own is safer still. Avoid inventing an undelegated suffix, which starts
shadowing a real domain if it is ever registered. `.local` conflicts with mDNS/Bonjour (RFC 6762)
and emits a warning if selected.

Any suffix other than `.localhost` needs one `/etc/hosts` entry per hostname, because hosts files
have no wildcards. Wormhole prints the exact `wormhole local hosts sync <hostname>` command when its
managed block is missing the name, and never edits the hosts file on its own.

Tailscale uses the local `tailscaled` login. Cloudflare quick tunnels need no login; named tunnels
use `cloudflared tunnel login`.

## Framework allowlists

Vite receives the public host through `__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS`.

For Next.js, derive `allowedDevOrigins` in `next.config.js` from the injected `WORMHOLE_URL`:

```js
const wormholeHost = process.env.WORMHOLE_URL
  ? new URL(process.env.WORMHOLE_URL).hostname
  : undefined

module.exports = {
  // Preserve any existing Next.js configuration here.
  allowedDevOrigins: wormholeHost ? [wormholeHost] : [],
}
```

Or allow a dedicated static namespace:

```js
module.exports = {
  allowedDevOrigins: ['*.wormhole.example.com'],
}
```

Merge with existing entries. Use only a Wormhole preview namespace. See the
[Next.js documentation](https://nextjs.org/docs/app/api-reference/config/next-config-js/allowedDevOrigins).

## Stable worktree URLs

Stable identities require no config. Wormhole derives them from the Git repository name, service,
and branch:

```json
{
  "scripts": {
    "dev:app": "vite",
    "dev": "wormhole run -- bun run dev:app"
  }
}
```

`tun.example.com` below represents your relay domain:

| Checkout/worktree | Command | Generated URL |
| --- | --- | --- |
| Dashboard `main` | `wormhole run -- bun run dev` | `https://dashboard.tun.example.com` |
| Dashboard `feat/theme-editor` | `wormhole run -- bun run dev` | `https://dashboard-feat-theme-editor.tun.example.com` |
| Dashboard `fix/mobile-nav` | `wormhole http 3000` | `https://dashboard-fix-mobile-nav.tun.example.com` |
| Docs site `main` | `wormhole run -- npm run dev` | `https://docs-site.tun.example.com` |
| Rust API `feat/health-check` | `wormhole run -- cargo run` | `https://rust-api-feat-health-check.tun.example.com` |

The default branch suffix and port are omitted. The relay reserves the label, Tailscale gets a
deterministic HTTPS port, and Cloudflare named tunnels use the same label.

Names resolve in order: `--host`, the nearest `wormhole.toml` `name`, the Git repository name, the
`package.json` name, then the folder. `wormhole.toml` is read from the current directory upwards,
stopping at the repository root, so every package in a monorepo inherits one project name. A
repository-derived name gains the subdirectory as a suffix, keeping `apps/web` and `apps/api`
distinct.

The `name` accepts `{repo}`, `{branch}`, `{service}`, `{dir}`, and `{worktree}` placeholders. Using
`{branch}` or `{service}` suppresses the automatic suffix so the template controls the whole label:

```toml
name = "{repo}-{branch}"
```

Set the Cloudflare DNS zone in the environment or `.env`:

```dotenv
WORMHOLE_DOMAIN=preview.example.com
```

Optional defaults:

```toml
[defaults]
domain = "preview.example.com"
drivers = ["tailscale", "cloudflare:named"]
tailscale_https_port_range = { start = 20000, end = 49999 }
# Set false to opt out of automatic stable identities.
stable_worktree_urls = false
```

Priority: explicit `--host`/`--public-port`/`wormhole.toml`, then `WORMHOLE_DOMAIN`, `.env`, and
shared config. Use `wormhole.toml` for multi-service `wormhole up` projects.

## Deploy a Cloudflare Worker relay

The Worker relay in [`crates/wormholed-cloudflare`](crates/wormholed-cloudflare) provides signed
WebSocket control, invite enrollment, stable HTTP hosts, streaming, edge auth, and Durable Object
state.

Deploy to a dedicated namespace:

```console
wormhole relay deploy cloudflare --domain wormhole.example.com
```

`--domain` selects the namespace. This example uses `relay.wormhole.example.com` for control and
`myapp.wormhole.example.com` for apps without touching `example.com`, `www.example.com`, or
`stuff.example.com`. Using `--domain example.com` creates `myapp.example.com` but can intercept
existing `*.example.com` hosts.

The command verifies its versioned bundle, runs pinned Wrangler, sends generated secrets through
stdin, and rolls back failed deployment/onboarding. Use `--dry-run` or `--bundle PATH` for local or
offline validation. Production needs a Cloudflare API token, active zone, Node.js/npm, and Durable
Objects. Workers Logs are off by default.

### Manual DNS

Custom Domains do not support the wildcard needed for generated app hosts. For
`--domain wormhole.example.com`, create:

| Type | Name | Target | Proxy status |
| --- | --- | --- | --- |
| A | `relay.wormhole` | `192.0.2.1` | Proxied |
| A | `*.wormhole` | `192.0.2.1` | Proxied |

`192.0.2.1` is an originless documentation placeholder; the Worker Route handles requests. Then run:

```console
wormhole relay deploy cloudflare --domain wormhole.example.com --manual-dns
```

Manual mode skips zone/DNS APIs but still deploys the Worker, routes, migration, secrets, health
check, and onboarding. Use VPS `wormholed` for QUIC, raw TCP, arbitrary upgrades, WebSocket
extensions/raw bytes, or offline webhook buffering. See the
[Cloudflare Worker guide](docs/CLOUDFLARE_DEPLOY.md).

Deployment does not configure WAF rate limiting. Public hostname traffic invokes the Durable Object,
so add a rate limiting rule for the wildcard hosts before real use. See
[Cost and abuse controls](docs/CLOUDFLARE_DEPLOY.md#cost-and-abuse-controls).

## Run a VPS relay

After pointing apex and wildcard DNS at Debian/Ubuntu:

```console
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nikuscs/wormhole/releases/latest/download/wormholed-bootstrap.sh \
  | sudo sh
```

Noninteractive Cloudflare DNS-01 install:

```console
sudo chmod 600 /root/cloudflare.token
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nikuscs/wormhole/releases/latest/download/wormholed-bootstrap.sh \
  | sudo sh -s -- --domain tun.example.com --email ops@example.com \
      --cloudflare-token-file /root/cloudflare.token -y
```

`-y` accepts the plan. UFW and overwrite still require `--configure-ufw` and `--force`. Secrets are
never accepted as arguments. Without a client key, bootstrap prints one single-use invite. See the
[server deployment guide](docs/DEPLOY.md).

## What you get

- One command for Wormhole, Tailscale, Cloudflare, or all three
- HTTP(S), raw TCP, stable worktree URLs, and declarative projects
- Process supervision, inspection/replay, retries, and durable webhook buffering
- Self-hosted VPS and Cloudflare Worker relays
- Deterministic JSON and a local Unix-socket API; no web UI required

| Capability | Wormhole | ngrok | Others | portless |
| --- | --- | --- | --- | --- |
| Self-hosted public relay | Yes | Enterprise offering | Varies | No |
| HTTP and raw TCP forwarding | Yes | Yes | Varies | Local HTTP routing |
| One command, multiple providers | Wormhole + Tailscale + Cloudflare | ngrok network | Usually one provider | Local routing + integrations |
| Worktree-scoped services | Yes | No | Varies | Yes |
| Request inspection and replay | Local CLI/API | Hosted inspector | Varies | No |
| Durable offline webhook buffering | Yes | No | Varies | No |
| Deterministic JSON and local APIs | Yes | CLI/API | Varies | CLI |

Alternatives: [LocalCan](https://www.localcan.com/) for native macOS and `.local` domains,
[Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/),
[ngrok](https://ngrok.com/docs/guides/share-localhost/tunnels/),
[Tailscale Funnel](https://tailscale.com/docs/reference/tailscale-cli/funnel),
[zrok](https://github.com/openziti/zrok), [portless](https://github.com/vercel-labs/portless), and
[LocalTunnel](https://localtunnel.github.io/www/).

## API and documentation

With the daemon running, open [http://127.0.0.1:52731/docs](http://127.0.0.1:52731/docs). Management
uses the daemon bearer token. Remote onboarding is available through `GET /v1/remotes`,
`POST /v1/remotes`, and `DELETE /v1/remotes/{name}`; invite values are never returned or persisted.

- [Optional macOS menu-bar companion](apps/macos/README.md)
- [Server deployment](docs/DEPLOY.md)
- [Cloudflare Worker deployment](docs/CLOUDFLARE_DEPLOY.md)
- [Local releases](docs/RELEASING.md)
- [Wire protocol](docs/PROTOCOL.md)

## License

Wormhole is [MIT licensed](LICENSE). Release archives and container images include the license and
generated [third-party notices](THIRD_PARTY_NOTICES). Cloudflare and Tailscale tools are separate products
subject to their own licenses and terms; Wormhole is not affiliated with either company.

## Development

Requires Rust 1.97+.

```console
make lint
make test
make e2e
```

After a clean push, `make signoff` runs formatting, lint, size, build, tests, E2E, shell/bootstrap,
and dependency policy before recording `gh-signoff`. Cloud CI runs only with a PR's `run-ci` label
or `workflow_dispatch`; macOS and coverage remain manual.

`make coverage` writes workspace coverage. `make coverage-e2e` adds ignored local-socket E2E flows
and writes HTML to `target/llvm-cov/html`.

---

<p align="center">
  <sub>Worm icon from <a href="https://github.com/twitter/twemoji">Twemoji</a>, licensed under <a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>.</sub>
</p>

> [!WARNING]
> This project was developed with AI assistance. Review it before production or security-sensitive use.
