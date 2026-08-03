# Local releases

Wormhole uses one workspace version and one `vX.Y.Z` tag for every release. A complete release
contains both native executables (`wormhole` and `wormholed`) for macOS and Linux, plus the
platform-independent `wormholed-cloudflare` Worker bundle.

The local release command deliberately separates building from publishing. `build` does not move
`main`, create a tag, push, attest, or create a GitHub release. `publish` accepts only the exact
signed build recorded by `build`.

## Prerequisites

Install and authenticate:

- Rust 1.97 with `rustup`;
- cargo-dist 0.32.0 as `dist`;
- Docker Desktop with `linux/arm64` and `linux/amd64` container support;
- Node.js 24 and npm;
- Xcode command-line tools, including `codesign` and `notarytool`;
- `jq`, `gh`, and `shellcheck`;
- a clean, synchronized `nikuscs/homebrew-tap` checkout at `~/projects/homebrew-tap`; and
- the dependencies required by the complete `make signoff` gate.

Set `WORMHOLE_HOMEBREW_TAP` when the tap checkout lives elsewhere.

Import a `Developer ID Application` certificate and its private key into an isolated local
keychain. Do not add the release keychain to the user keychain search list. Unlock it and point the
release command at it explicitly:

```bash
export WORMHOLE_SIGNING_KEYCHAIN="$HOME/.apple-signing/TEAMID/wormhole-release.keychain-db"
security unlock-keychain "$WORMHOLE_SIGNING_KEYCHAIN"
export WORMHOLE_CODESIGN_IDENTITY='Developer ID Application: Example (TEAMID)'
```

Store notarization credentials in that same keychain once. The Apple account and private key are
never uploaded to GitHub:

```bash
xcrun notarytool store-credentials wormhole-release \
  --apple-id you@example.com \
  --team-id TEAMID \
  --keychain "$WORMHOLE_SIGNING_KEYCHAIN"
```

The release command passes `WORMHOLE_SIGNING_KEYCHAIN` to both `codesign` and `notarytool`. Set
`WORMHOLE_NOTARY_PROFILE` only if a profile name other than `wormhole-release` is used.

## Build

Start from a clean `main` that exactly matches `origin/main`:

```bash
scripts/release-local.sh build minor
```

Use `patch`, `minor`, or `major`. The first release must use `minor`, producing `v0.1.0`.

The command creates a detached worktree, updates the version and changelog there, commits the exact
source being built, runs the repository gate, and produces:

- `wormhole` and `wormholed` ZIP archives for macOS arm64 and x86_64;
- signed and notarized macOS executables;
- `wormhole` and `wormholed` ZIP archives for Linux arm64 and x86_64, built in matching Docker
  containers;
- `LICENSE` and generated `THIRD_PARTY_NOTICES` files inside every archive and as release assets;
- shell and Homebrew installers;
- an inspectable `release-notes.md` generated from the versioned changelog section;
- the `wormhole.rb` formula generated from the final platform checksums;
- the source archive and checksums;
- `wormholed-bootstrap.sh`; and
- `wormholed-cloudflare-worker.tar.gz` and its checksum.

Artifacts and build state are written under `target/release-local/vX.Y.Z/`. The exact unpushed
release commit is preserved under `refs/wormhole-release/vX.Y.Z`. After dependency changes, run
`make notices`; the policy gate rejects a stale `THIRD_PARTY_NOTICES` file.

For toolchain validation without Apple signing or the full gate:

```bash
scripts/release-local.sh build minor --unsigned --skip-gate
```

Unsigned build state is intentionally rejected by `publish`.

## Publish

Inspect the artifacts first, then run the separate publish command:

```bash
scripts/release-local.sh publish v0.1.0
```

After confirmation, it:

1. verifies checksums, signed build state, source commit, branch, and remote state;
2. fast-forwards `main` to the exact release commit that produced the artifacts;
3. creates an annotated tag and atomically pushes `main` and the tag;
4. runs `make signoff` from the clean, pushed release commit;
5. creates the GitHub release with the generated notes and uploads all public artifacts; and
6. commits and pushes the generated formula to `nikuscs/homebrew-tap`.

`--yes` suppresses only the final interactive confirmation. It does not bypass any validation.

The GHCR image remains the responsibility of `.github/workflows/release.yml`; the local command
covers the native executables, installers, and Cloudflare Worker bundle requested for local
artifact releases.
