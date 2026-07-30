# Wormhole menu-bar companion

A small, optional native macOS companion for the normally installed `wormhole` CLI. It contains no
Rust CLI, daemon, tunnel driver, or networking implementation.

## Requirements

- macOS 13 or newer
- Xcode 16 or newer
- Wormhole installed with the standard installer:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/nikuscs/wormhole/releases/latest/download/wormhole-cli-installer.sh | sh
```

## Build and run

For development:

```sh
cd apps/macos
swift run WormholeMenuBar
```

To create an independently launchable, ad-hoc-signed app bundle:

```sh
cd apps/macos
./scripts/build-app.sh
open "build/Wormhole Menu Bar.app"
```

Pass an output directory as the first script argument if desired. The app is not copied into
`/Applications`; move the bundle there before enabling **App → Launch at Login**. macOS may require
one-time approval in **System Settings → General → Login Items**, which the app links to directly.
The local bundle is ad-hoc signed; Developer ID signing, notarization, and automatic updates remain
release-distribution prerequisites rather than development-build behavior.

Run focused non-UI tests with:

```sh
cd apps/macos
swift test
```

## Integration boundary

The companion locates `wormhole` through `WORMHOLE_CLI_PATH`, the process `PATH`, and common normal
installer locations (`~/.local/bin`, `~/.cargo/bin`, Homebrew). It checks the standard per-user daemon
socket and uses only stable `wormhole --json` commands for authenticated operations. The CLI remains
the authority and handles its private bearer token; the app never reads, displays, or logs that token.

The native macOS menu refreshes every five seconds and shows daemon status plus each active
endpoint's service, provider, lifecycle state, and URLs. It supports copying/opening HTTP URLs,
stopping an individual endpoint without forgetting its reservation, starting/stopping/reloading the
daemon, opening daemon
logs, toggling Launch at Login, and quitting. Operations show progress, disable conflicting actions,
and retain actionable command failures until dismissed.

A daemon restart action is intentionally omitted: current Wormhole restore behavior retains only
persistent endpoints, so presenting restart as harmless could silently discard temporary tunnels.
Stopping the daemon therefore requires confirmation with the same warning.
