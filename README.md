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

---

## Features

- **One command, multiple providers** — Publish through Wormhole, Tailscale, and Cloudflare
- **Stable worktree URLs** — Keep provider URLs while local app ports change
- **Self-hosted relays** — Run the full VPS relay or an HTTP/WebSocket relay on Cloudflare Workers
- **Provider-only mode** — Use Tailscale or Cloudflare without a Wormhole relay
- **Process supervision** — Allocate `PORT`, start a child process, detect its listener, and clean up
- **Declarative projects** — Start multiple worktree services from `wormhole.toml`
- **Request inspection and replay** — Capture traffic through the local CLI and API
- **Durable webhooks** — Buffer requests while a target is offline and replay them later
- **Agent-friendly interfaces** — Deterministic JSON, local Unix sockets, and no required web UI

---

## Quick start

### Install

```console
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/nikuscs/wormhole/releases/latest/download/wormhole-cli-installer.sh | sh
```

Or build and install both binaries from source:

```console
make install
```

### Install the agent skill

Teach compatible coding agents the shortest safe Wormhole workflows:

```console
npx skills add nikuscs/wormhole --skill wormhole-cli
```

Add `--global` to make it available across projects. Update a project or global installation with:

```console
npx skills update wormhole-cli
npx skills update wormhole-cli --global
```

The skill supports Claude Code, Codex, Cursor, GitHub Copilot, Pi, and other agents compatible with
the open Agent Skills format.

### Connect to a relay

Create or display the client identity:

```console
wormhole key show
```

Create an enrollment invite on the relay, then redeem it from the client:

```console
# On the relay server (single use, 10-minute default expiry):
wormholed invite create --name laptop

# On the client:
wormhole remote add myvps tun.example.com:443 --invite <token>
wormhole domains
```

Run `wormhole remote add` without positional arguments on an interactive terminal to use the setup
wizard. Scripts and JSON/non-TTY calls must provide `NAME`, `ADDR`, and any invite explicitly. For
multiple independently keyed machines, create a reusable credential with
`wormholed invite create --name personal-devices --reusable`; inspect or revoke it with
`wormholed invite ls` and `wormholed invite revoke <invite-id>`. Invite tokens are shown once,
stored only as digests by the relay, and never written to client configuration. Manual
`wormholed key authorize "<public-key>" --name laptop` remains available as a break-glass flow.

The first added relay becomes the default. Wormhole authenticates with the local identity key and
uses QUIC with an automatic secure WebSocket fallback. `wormhole domains` connects to every
configured relay and lists the public domains each one advertises.

Client configuration is stored in `~/.config/wormhole/config.toml`; `WORMHOLE_CONFIG` and
`--config PATH` override it. Client identity keys live under `~/.config/wormhole/keys/`.

### Expose a local service

```console
wormhole http 3000
```

Wormhole prints a URL such as `https://misty-otter-3f2a.tun.example.com`.

### Run a development process

```console
wormhole run -- bun run dev
```

`wormhole run` allocates and injects `PORT`, detects the child listener, publishes it, and removes
temporary provider state when the process exits. Temporary endpoints served by a Wormhole relay
also override `X-Robots-Tag` with `noindex, nofollow, noarchive, nosnippet`; persistent endpoints
preserve the origin's indexing policy. This discourages search indexing but is not access control.
Frameworks that ignore `PORT`—including Vite, Astro, Angular, React Router, Rsbuild, Expo, and
React Native—receive compatible `--port` and `--host` flags automatically, including through common
package runners and `package.json` scripts.
Explicit flags always win, and listener detection remains the fallback.

#### Framework development-host allowlists

Vite receives the public hostname automatically through its supported
`__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS` environment variable.

Next.js blocks tunneled access to development-only assets unless the public hostname appears in
`allowedDevOrigins`. Next.js has no native environment variable or CLI flag for this setting, but
`next.config.js` can derive it from the `WORMHOLE_URL` that `wormhole run` injects:

```js
const wormholeHost = process.env.WORMHOLE_URL
  ? new URL(process.env.WORMHOLE_URL).hostname
  : undefined

module.exports = {
  // Preserve any existing Next.js configuration here.
  allowedDevOrigins: wormholeHost ? [wormholeHost] : [],
}
```

This follows each worktree's generated hostname without per-worktree edits. For a dedicated static
Wormhole namespace, a single wildcard also works for every worktree:

```js
module.exports = {
  allowedDevOrigins: ['*.wormhole.example.com'],
}
```

Use only a namespace dedicated to Wormhole previews, and merge either form with existing
`allowedDevOrigins` entries. See the [Next.js `allowedDevOrigins` documentation](https://nextjs.org/docs/app/api-reference/config/next-config-js/allowedDevOrigins).

### Start a worktree project

```console
wormhole up
```

`wormhole up` starts the services declared by the current worktree's `wormhole.toml`.

---

## Use providers directly

A Wormhole relay is optional when using Tailscale or Cloudflare:

```console
wormhole http 3000 --endpoint tailscale
wormhole http 3000 --endpoint tailscale:funnel
wormhole http 3000 --endpoint cloudflare:quick
wormhole http 3000 --endpoint cloudflare:named --host app.example.com --persist
wormhole http 3000 --endpoint wormhole --endpoint tailscale --endpoint cloudflare
```

Tailscale uses the local `tailscaled` login. Cloudflare quick tunnels require no login; named
tunnels use credentials created by `cloudflared tunnel login`.

---

## Stable worktree URLs

Stable worktree identities are automatic and require no `wormhole.toml`. Wormhole derives a label
from the current directory's `package.json` name (falling back to the directory), service name, and
Git branch:

```json
{
  "scripts": {
    "dev:app": "vite",
    "dev": "wormhole run -- bun run dev:app"
  }
}
```

These anonymous examples illustrate the naming rules. `tun.example.com` stands in for the domain
advertised by your relay:

| Checkout/worktree | Command | Generated URL |
| --- | --- | --- |
| Dashboard `main` | `wormhole run -- bun run dev` | `https://dashboard.tun.example.com` |
| Dashboard `feat/theme-editor` | `wormhole run -- bun run dev` | `https://dashboard-feat-theme-editor.tun.example.com` |
| Dashboard `fix/mobile-nav` | `wormhole http 3000` | `https://dashboard-fix-mobile-nav.tun.example.com` |
| Docs site `main` | `wormhole run -- npm run dev` | `https://docs-site.tun.example.com` |
| Rust API `feat/health-check` (no `package.json`) | `wormhole run -- cargo run` | `https://rust-api-feat-health-check.tun.example.com` |

The default branch suffix is omitted. Both `wormhole http 3000` and `wormhole run` use the
inferred project/worktree name; port numbers never appear in automatic HTTP URLs.

The self-hosted relay receives the derived label and reserves it persistently. Tailscale receives a
deterministic HTTPS port. Cloudflare named tunnels use the same label but also need a DNS zone; set
it in the process environment or the project's existing `.env` file:

```dotenv
WORMHOLE_DOMAIN=preview.example.com
```

`WORMHOLE_DOMAIN` takes priority over `.env`, which takes priority over optional global/project
configuration. Configuration remains available for shared defaults and overrides:

```toml
[defaults]
domain = "preview.example.com"
drivers = ["tailscale", "cloudflare:named"]
tailscale_https_port_range = { start = 20000, end = 49999 }
# Set false to opt out of automatic stable identities.
stable_worktree_urls = false
```

Explicit `--host`, `--public-port`, and `wormhole.toml` endpoint values still take priority where
applicable. Use `wormhole.toml` only when declarative multi-service `wormhole up` behavior is useful.

---

## Cloudflare Worker relay

Wormhole includes a separate, deployable relay for Cloudflare Workers in
[`crates/wormholed-cloudflare`](crates/wormholed-cloudflare). It uses Cloudflare-managed HTTPS and a
SQLite-backed Durable Object to provide:

- the existing CLI's signed WebSocket control transport and invite enrollment;
- stable or generated HTTP hostnames with persistent reservations;
- streamed HTTP request and response bodies;
- Basic, Bearer, and share-link edge authentication; and
- bearer-protected invite creation, listing, and revocation.

Deploy, verify, create a one-use invite, and configure this machine's remote in one command. A
dedicated subdomain is the safest default when the main domain already has websites or services:

```console
wormhole relay deploy cloudflare --domain wormhole.example.com
```

Here, clients connect through `relay.wormhole.example.com`, exposed apps receive names such as
`myapp.wormhole.example.com`, and existing hosts such as `example.com`, `www.example.com`, or
`stuff.example.com` remain unaffected. The `--domain` value is Wormhole's public namespace, not the
client connection hostname.

Using `--domain example.com` instead produces shorter names such as `myapp.example.com`, but the
required wildcard Worker route can intercept existing `*.example.com` services. Use the apex only
when that entire subdomain namespace is available to Wormhole.

The CLI verifies its version-matched Worker bundle, runs pinned Wrangler, configures only the relay
and wildcard DNS/routes, uploads generated secrets through stdin, and rolls back changes after a
failed health check or enrollment. Use `--dry-run` for local validation and `--bundle PATH` for an
audited or offline artifact. Production deployment requires a suitable Cloudflare API token, an
active zone, Node.js/npm, and a Durable Objects plan. Workers Logs remain disabled by default;
operators can opt into 1%-sampled invocation logging as documented in the deployment guide.

### Why Cloudflare DNS records are required

Wrangler Custom Domains automatically create DNS and TLS for one exact hostname. Wormhole also needs
a wildcard hostname for dynamically named apps, and Cloudflare Custom Domains do not support
wildcards. The deploy command therefore creates proxied DNS plus Worker Routes for both the control
hostname and the public wildcard.

If DNS is managed manually for `--domain wormhole.example.com`, create these records in the
`example.com` Cloudflare zone before deploying:

| Type | Name | Target | Proxy status |
| --- | --- | --- | --- |
| A | `relay.wormhole` | `192.0.2.1` | Proxied |
| A | `*.wormhole` | `192.0.2.1` | Proxied |

`192.0.2.1` is a reserved documentation address used only as an originless placeholder; matching
requests are handled by the Worker Route before reaching it. Do not change the zone apex. After the
records resolve, deploy through an existing Wrangler login without creating an API token:

```console
wormhole relay deploy cloudflare --domain wormhole.example.com --manual-dns
```

Manual-DNS mode skips Cloudflare's zone and DNS APIs. Wrangler still deploys the Worker, routes,
Durable Object migration, and secrets; Wormhole then verifies health and completes local onboarding.

The Worker relay supports HTTP/HTTPS targets and bounded public WebSocket message bridging rather
than full transport parity. Use the VPS `wormholed` relay when you need QUIC control, raw TCP, other
public upgrade protocols, WebSocket extensions/raw upgrade bytes, or offline webhook buffering. See
the [Cloudflare Worker guide](docs/CLOUDFLARE_DEPLOY.md) for architecture,
configuration, security boundaries, and the explicit deployment command.

## Run a relay

After pointing apex and wildcard DNS records at a Debian/Ubuntu server, run the interactive
bootstrap directly from the latest GitHub release:

```console
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nikuscs/wormhole/releases/latest/download/wormholed-bootstrap.sh \
  | sudo sh
```

For a single noninteractive Cloudflare DNS-01 installation, store a narrowly scoped token in a
root-only file and pass every required input explicitly:

```console
sudo chmod 600 /root/cloudflare.token
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nikuscs/wormhole/releases/latest/download/wormholed-bootstrap.sh \
  | sudo sh -s -- --domain tun.example.com --email ops@example.com \
      --cloudflare-token-file /root/cloudflare.token -y
```

`-y` accepts the displayed plan but never enables UFW or overwrites an installation. Those require
separate `--configure-ufw` and `--force` flags. Raw secrets are never accepted as arguments. When no
client public key is supplied, bootstrap prints a single-use initial enrollment invite once.
See the [deployment guide](docs/DEPLOY.md) for static TLS, client authorization, DNS, firewall,
rollback, and container setup.

---

## Comparison

| Capability | Wormhole | ngrok | Others | portless |
| --- | --- | --- | --- | --- |
| Self-hosted public relay | Yes | Enterprise offering | Varies | No |
| HTTP and raw TCP forwarding | Yes | Yes | Varies | Local HTTP routing |
| One command, multiple providers | Wormhole + Tailscale + Cloudflare | ngrok network | Usually one provider | Local routing + integrations |
| Worktree-scoped services | Yes | No | Varies | Yes |
| Request inspection and replay | Local CLI/API | Hosted inspector | Varies | No |
| Durable offline webhook buffering | Yes | No | Varies | No |
| Deterministic JSON and local APIs | Yes | CLI/API | Varies | CLI |

---

## Alternatives

Wormhole focuses on self-hosting, worktree identity, multiple exposure providers, and
agent-friendly local APIs. Other excellent tools may fit a narrower workflow better:

- [LocalCan](https://www.localcan.com/) — A polished native macOS experience for `.local` domains,
  public URLs, and traffic inspection. A great fit for desktop-first local development.
- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/) —
  Managed ingress through Cloudflare, with quick tunnels available for temporary sharing.
- [ngrok](https://ngrok.com/docs/guides/share-localhost/tunnels/) — A mature hosted tunneling
  platform with a broad edge feature set and hosted inspection.
- [Tailscale Funnel](https://tailscale.com/docs/reference/tailscale-cli/funnel) — Public HTTPS
  exposure directly from a device already connected to a tailnet.
- [zrok](https://github.com/openziti/zrok) — Open-source, self-hostable sharing for web services,
  files, and other network resources.
- [portless](https://github.com/vercel-labs/portless) — Stable named localhost URLs for local apps,
  monorepos, and worktrees without requiring a public relay.
- [LocalTunnel](https://localtunnel.github.io/www/) — A lightweight way to share a local HTTP
  service through a hosted public URL.

---

## Local API

With the daemon running, the Scalar API reference is available at
[http://127.0.0.1:52731/docs](http://127.0.0.1:52731/docs). Operational routes remain protected by
the daemon bearer token. Typed `GET /v1/remotes`, `POST /v1/remotes`, and
`DELETE /v1/remotes/{name}` operations support future onboarding UIs; invite values are accepted
only by the add request and are never returned or persisted.

---

## Documentation

- [Optional macOS menu-bar companion](apps/macos/README.md)
- [Server deployment](docs/DEPLOY.md)
- [Wire protocol](docs/PROTOCOL.md)

---

## Development

Rust 1.97 or newer is required.

```console
make lint
make test
make e2e
```

After committing and pushing a clean tree, `make signoff` runs formatting, lint, size, build, the
full workspace suite, E2E, shell/bootstrap checks, and dependency policy checks before recording a
`gh-signoff` status on that exact commit. It never signs off after a failed or partial run.

Cloud CI does not run on every push. Apply the `run-ci` label to a pull request to approve one cloud
run for its current head, or use `workflow_dispatch`; remove and reapply the label after later commits
when another run is wanted. macOS and coverage jobs remain manual-dispatch only.

`make coverage` generates the workspace report. `make coverage-e2e` also runs ignored local-socket
E2E flows and writes merged HTML coverage to `target/llvm-cov/html`.

---

<p align="center">
  <sub>Worm icon from <a href="https://github.com/twitter/twemoji">Twemoji</a>, licensed under <a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>.</sub>
</p>

> [!WARNING]
> This project was developed with the assistance of AI. Please review and validate the code carefully before using it in production or security-sensitive environments.
