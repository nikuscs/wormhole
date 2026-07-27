# Wormhole Agent Guide

## Scope

Wormhole is ngrok for agents and worktrees: simple, fast, and secure. It exposes local HTTP(S)
and TCP services through the self-hosted relay, Tailscale, and Cloudflare drivers. There is no
web UI; use the CLI, JSON output, and local Unix-socket APIs.

## Plan

- The implementation plan lives in `docs/plan/`; execute stages in index order.
- Within a stage, execute tasks top-to-bottom.
- Tick a task only after its validation passes. Tick a stage only after its acceptance gate passes.
- Never mark partial work complete. Record `> BLOCKED:` beneath a blocked task and stop.
- Do not add an unlisted dependency without adding it to `[workspace.dependencies]` and the Stage
  01 dependency table with a one-line justification.

Stage order: 01 Foundation, 02 Protocol, 03 Relay server, 04 Client core, 05 Daemon & CLI,
06 Provider drivers, 07 Forwards & webhooks, 08 Testing & hardening, 09 Release. Stages 03 and 04
may proceed in parallel after Stage 02.

## Rust conventions

- Rust stable 1.97+, edition 2024, `rust-version = "1.97"`.
- Pure Rust TLS only. OpenSSL is forbidden.
- Use `jiff`, never `chrono`. Use TOML, never `serde_yaml`.
- Libraries use `thiserror`; `anyhow` is limited to the two binary crates.
- Every dependency comes from `[workspace.dependencies]`.
- Keep the crate graph acyclic: proto has no internal dependencies; core and wormholed depend only
  on proto; CLI depends on core and proto.
- `unsafe` is forbidden. Clippy all, pedantic, nursery, and cargo lints are enforced as warnings,
  with CI treating warnings as errors.
- Never use `todo!`, `unimplemented!`, `dbg!`, or direct printing.
- `crates/wormhole-cli/src/output.rs` is the only module allowed to print; all commands honor its
  human/JSON format contract.
- Unit tests live in sibling `*_tests.rs` files referenced with `#[cfg(test)]` and `#[path = ...]`.
  Never add inline `mod tests { ... }` blocks.
- Source files have a 400-line soft cap and 500-line hard cap; `*_tests.rs` files cap at 800 lines.
- Functions cap at 80 lines and cognitive complexity 20. Split by responsibility before limits.
- Test-only escape hatches must be absent from release builds.

## Required checks

Run at the end of every stage:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
make size
cargo build --workspace --locked
cargo test --workspace --locked
```

Useful targets: `make fmt`, `make lint`, `make check`, `make test`, `make build`, `make coverage`,
`make e2e`, and `make size`.
