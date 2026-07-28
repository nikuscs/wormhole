# Stage 09 — Release & docs

**Goal:** installable, documented, reproducible releases: `curl | sh` installer, Homebrew,
Docker image for `wormholed`, complete user docs, and a manual-dispatch release workflow
matching the crauler house style.

**Depends on:** 08.

## Tasks

**Implementation order within this stage:** R1 → R3 → R4 → R5 → R6 → R2. R2 is the sole
owner of version mutation, tagging, and release publication; the earlier tasks only prepare
and validate an untagged tree.

- [x] **R1 — cargo-dist.** cargo-dist is the sole artifact builder/release engine. Tool is
  `dist` (repo `axodotdev/cargo-dist`, community-maintained, v0.32 as of 2026-05).
  `dist init` configured for: both binaries, targets
  {aarch64-apple-darwin, x86_64-apple-darwin, x86_64-unknown-linux-gnu (musl if aws-lc allows;
  else gnu), aarch64-unknown-linux-gnu}, shell installer + Homebrew formula artifacts, GitHub
  Releases upload. Extend its generated workflow in R2; do not maintain a second hand-rolled
  artifact matrix. If dist cannot represent a required target, record a blocker with its exact
  error before changing release architecture.
  Validation: `dist build` produces runnable artifacts for the host platform.

- [ ] **R2 — Release workflow.** Extend cargo-dist's single `.github/workflows/release.yml` with
  `workflow_dispatch` and
  `version_bump` choice (patch/minor/major) exactly like crauler's; jobs: checks (fmt, clippy,
  test, deny, audit) → bump versions in workspace + tag `vX.Y.Z` → cargo-dist build → macOS
  signing/notarization → GitHub Release + GHCR image. Add release-workflow concurrency so two
  dispatches cannot race. `permissions: {}` default-deny, per-job grants. The
  workspace begins at unreleased `0.0.0`; the first approved dispatch uses **minor** and
  therefore creates exactly `v0.1.0`. Reject a dispatch if the target tag already exists or
  the checked-out commit is not the default branch head. The workflow is the only place that
  edits the workspace version or creates a tag.

  - macOS: on macOS runners, sign both Mach-O binaries with a Developer ID Application
    certificate, package signed `.zip` artifacts, submit each with `xcrun notarytool --wait`,
    and upload only after Apple returns Accepted. Required GitHub environment secrets:
    certificate p12 + password and App Store Connect notary credentials. Never echo them.
    Verification: `codesign --verify --strict --verbose=2`, `spctl --assess --type execute`,
    and `xcrun notarytool history`/submission result.

  **Confirmation gate:** do not configure/read Apple credentials or dispatch the workflow
  (which pushes the version commit/tag, creates the GitHub Release/GHCR image, and publishes
  artifacts) without explicit user approval.
  Validation before approval: YAML parses and a no-write script/unit test proves
  `0.0.0 + minor → 0.1.0`; after approval: the workflow succeeds and the `v0.1.0` release
  contains both binaries and checksums.

- [x] **R3 — Docker.** `deploy/Dockerfile` finalized (S9 stub): multi-stage, distroless/static,
  `wormholed` entrypoint, example `docker-compose.yml` with volumes for `/var/lib/wormhole` +
  `/etc/wormhole`, ports 80/tcp, 443/tcp+udp, 10000-20000/tcp. Push target documented (ghcr) but pushing
  happens only from release workflow — gated, not automatic on merge.
  Validation: `docker compose up` locally with self-signed mode serves `wormholed status`.

  > WAIVED (macOS): the local Docker daemon was unavailable. Compose parsing and Dockerfile
  > build checks passed; the project-level macOS Docker-runtime waiver applies.

- [x] **R4 — README.** Real README: 30-second pitch (the scope mantra), animated-less quickstart:

  ```console
  # server (once, on a VPS with *.tun.example.com → this box)
  curl -fsSL https://wormhole.sh/install | sh
  wormholed init && wormholed key authorize "$(pbpaste)" --name laptop && wormholed serve

  # client
  wormhole remote add myvps tun.example.com:443
  wormhole http 3000                          # → https://misty-otter-3f2a.tun.example.com
  wormhole http 3000 --endpoint wormhole --endpoint tailscale --endpoint cloudflare
  wormhole run -- bun run dev                 # portless-style: injects PORT, exposes it
  wormhole up                                 # wormhole.toml in this worktree
  ```

  Feature table vs ngrok/LocalCan/portless (honest), links into docs/. Validation: every
  command in README exists and flags are correct (script: extract fenced `console` blocks,
  grep against `--help`).

  > IMPLEMENTATION: until the vanity domain is provisioned, README uses cargo-dist's valid,
  > per-binary GitHub Release installer URLs rather than claiming a nonexistent `/install` URL.

- [x] **R5 — Docs sweep.** Ensure `docs/` contains and cross-links: `server-setup.md` (S9),
  `local-api.md` + `agents.md` (D8), `providers.md` (V5), `webhooks.md` (W6). Add
  `docs/config-reference.md` generated-by-hand from the serde structs (every key, default,
  example) — keep in sync check: a unit test deserializes every fenced TOML block in the docs
  (walk `docs/*.md`, extract ```toml blocks, parse against the config structs).
  Validation: that unit test passes.

- [ ] **R6 — Prepare v0.1.0 metadata (untagged).** Keep the single workspace version at the
  unreleased `0.0.0` baseline. Add `CHANGELOG.md` (Keep a Changelog) with a populated
  `[Unreleased]` section whose comparison link targets the future `v0.1.0`; R2 converts that
  section to `[0.1.0] - YYYY-MM-DD` while performing its minor bump. Do not edit versions or
  create any tag here. **Do not push, publish to crates.io, create the GitHub repo, open any
  PR, or dispatch R2 without explicit approval — stop and ask.**
  Validation: `cargo metadata --no-deps` reports `0.0.0` for every publishable workspace
  package, `git tag --list v0.1.0` is empty, and `git status` is clean.

## Acceptance gate

```bash
make lint && cargo test --workspace --locked && make e2e
```

plus R4's README-command check and R5's docs test. Project complete — final review pass against
`docs/plan/00-overview.md` stage list; every stage box ticked.
