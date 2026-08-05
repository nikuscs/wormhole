# Changelog

All notable changes to Wormhole are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/nikuscs/wormhole/compare/v0.1.1...HEAD
[0.1.0]: https://github.com/nikuscs/wormhole/releases/tag/v0.1.0
[0.1.1]: https://github.com/nikuscs/wormhole/releases/tag/v0.1.1
