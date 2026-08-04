# Wormhole Agent Guide

## Scope

Wormhole securely exposes local HTTP(S) and TCP services for agents, automation, and worktrees
through the self-hosted relay, Tailscale, and Cloudflare drivers. There is no
web UI; use the CLI, JSON output, and local Unix-socket APIs.

## Work protocol

- A question is not an edit request. Review feedback is discussion until fixes are approved.
- Before a non-trivial or destructive change, state the plan and assumptions. Explicit instructions
  to do or ship the work authorize the stated scope without staged pauses.
- After two failed attempts, stop and ask. Fix only the requested path and mention unrelated issues.
- At the start of each task, read `.agents/scratchpad.md` for pending cross-worktree work, integration
  constraints, and follow-ups. Add concise pending items when discovered and remove them when resolved;
  the scratchpad records coordination context and does not authorize otherwise unrequested work.
- Commit or push only when requested. Never create or open a pull request without explicit permission.
- An unqualified release request means the documented local-first flow: `scripts/release-local.sh build`
  followed by `publish` of those exact artifacts. Dispatch `.github/workflows/release.yml` only when
  the user explicitly asks for a GitHub-hosted release.

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
- Each binary may print only through its dedicated `output.rs`; all commands honor the shared
  human/JSON format contract.
- Unit tests live in sibling `*_tests.rs` files referenced with `#[cfg(test)]` and `#[path = ...]`.
  Never add inline `mod tests { ... }` blocks.
- Source files have a 400-line soft cap and 500-line hard cap; `*_tests.rs` files cap at 800 lines.
- Functions cap at 80 lines and cognitive complexity 20. Split by responsibility before limits.
- Test-only escape hatches must be absent from release builds. The CLI's
  `WORMHOLE_ENABLE_MOCK_DRIVER=1` integration-test driver and the
  `WORMHOLE_RUN_{LISTEN,DETECT}_TIMEOUT_MS` test timeouts are compiled only with
  `debug_assertions` and are absent from release binaries.

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

`gh-signoff` is attestation only; it runs nothing itself. After a commit is pushed and the tree is
clean, use `make signoff` to run the complete local gate and sign only if every command succeeds.
Sign off substantial changes, including cross-crate work, protocol or security changes, dependency
updates, CI/release/deployment changes, and large feature or refactor commits. Small documentation,
comment, formatting, or narrowly mechanical commits do not require signoff. Never run bare
`gh signoff` or use `-f` to bypass dirty/unpushed/full-suite checks. Cloud CI runs only when a pull
request receives the `run-ci` label or through manual dispatch.

`.agents/` is authoritative. Keep root `AGENTS.md` and `CLAUDE.md` linked to
`.agents/AGENTS.md`.
