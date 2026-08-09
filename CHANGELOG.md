# Changelog

All notable changes to Wormhole are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A `local` driver, selected with `--endpoint local`, serves HTTP services on local hostnames through
  a single Host-routing loopback proxy, so many services share one port instead of each taking its
  own. The default `.localhost` suffix resolves in browsers without DNS, a hosts entry, or elevation.
- HTTPS for local endpoints, from a generated local certificate authority stored with owner-only
  permissions that issues and caches one certificate per hostname through SNI. The authority is valid
  for ten years and leaf certificates for 397 days, reissued within thirty days of expiry.
- `wormhole local trust` and `wormhole local untrust` install and remove the local authority in the
  system trust store, printing every privileged command before running it and requiring an
  interactive confirmation or `--yes`.
- `wormhole local hosts sync` and `wormhole local hosts clear` maintain a marked block in `/etc/hosts`
  for suffixes other than `.localhost`. Wormhole never edits the hosts file on its own; an endpoint
  whose hostname is missing from the block prints the exact command to run.
- `wormhole local elevate` and `wormhole local unelevate` install and remove a root-owned forwarding
  service so local endpoints answer on ports 80 and 443. Elevation refuses to proceed when the
  executable or any parent directory is writable by a non-root user, installs a root-owned copy of
  the binary, and the service drops to the invoking user once the privileged ports are bound.
- `--tld`, `defaults.local_tld`, `defaults.local_http_port`, and `defaults.local_https_port` select
  the local suffix and the loopback ports. `.test` is recommended for a suffix other than
  `.localhost`; `.local` is reported as conflicting with mDNS and Bonjour.
- `wormhole doctor` reports local certificate trust, the state of the managed hosts block, and
  listener reachability.
- Endpoints carry `hints` and `warnings`, both omitted from JSON output when empty.

## [0.1.2] - 2026-08-05

### Added

- `name` templates in `wormhole.toml` accepting `{repo}`, `{branch}`, `{service}`, `{dir}`, and
  `{worktree}`, where `{branch}` or `{service}` suppresses the matching automatic suffix.
- Idle persistent binds are released after `BIND_IDLE_TTL_SECONDS` on the Cloudflare relay,
  defaulting to a day and disabled with `0`, so abandoned worktree reservations do not accumulate.

### Changed

- Service names derive from the Git repository rather than `package.json`, with the subdirectory
  appended so packages in a monorepo stay distinct. Existing generated hostnames change.
- `wormhole.toml` is discovered from the current directory upwards to the repository root, so every
  package in a monorepo inherits one project configuration.

### Fixed

- `wormhole.toml` `name` was never read, because a document was parsed as a bare TOML value, so
  every project silently fell back to its `package.json` name.
- A hostname held by a bind whose connection had vanished could never be reclaimed, and the client
  received a suffixed hostname instead, breaking OAuth redirects and webhooks configured against it.
- Concurrent tunnels sharing one client key evicted each other's connections, leaving parallel
  worktrees permanently reconnecting.
- `wormhole run` now exits cleanly on `SIGTERM` and `SIGHUP` as well as an interrupt, and supersedes
  a registration left behind by a predecessor instead of refusing to start.
- Restarting a stopped service under a different hostname releases the superseded reservation
  instead of failing until `down --forget` is run by hand.
- Reconnect backoff no longer grows to tens of seconds before a first connection succeeds, which
  turned a hostname released moments earlier into a failed startup.

## [0.1.1] - 2026-08-04

### Added

- Framework-aware public URL environment aliases for Next.js, Nuxt, SvelteKit, Astro, Rsbuild,
  and Expo commands launched through `wormhole run`.
- MIT licensing and generated third-party notices in every release archive and container image.

### Changed

- Local release builds now default to a patch version bump.

## [0.1.0] - 2026-08-03

### Install

```sh
brew install nikuscs/tap/wormhole
```

### Added

- Self-hosted QUIC relay with authenticated WebSocket fallback.
- HTTP, HTTPS, and TCP forwarding with persistent reservations.
- Tailscale and Cloudflare quick/named tunnel providers and multi-provider endpoints.
- Worktree-scoped projects, command wrapping, daemon lifecycle, JSON output, and local Unix APIs.
- Durable offline webhook buffering, request inspection, replay, retries, and edge authentication.
- Shell and Homebrew installers, distroless relay image, systemd unit, and release automation.

### Security

- Strict Ed25519 identities, bounded protocol frames and mux queues, per-key quotas, hardened TLS,
  Unix-socket administration, secure state permissions, and provider ownership checks.

[Unreleased]: https://github.com/nikuscs/wormhole/compare/v0.1.2...HEAD
[0.1.0]: https://github.com/nikuscs/wormhole/releases/tag/v0.1.0
[0.1.1]: https://github.com/nikuscs/wormhole/releases/tag/v0.1.1
[0.1.2]: https://github.com/nikuscs/wormhole/releases/tag/v0.1.2
