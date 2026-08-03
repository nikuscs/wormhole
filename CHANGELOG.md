# Changelog

All notable changes to Wormhole are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- MIT licensing and generated third-party notices in every release archive and container image.

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

[Unreleased]: https://github.com/nikuscs/wormhole/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nikuscs/wormhole/releases/tag/v0.1.0
