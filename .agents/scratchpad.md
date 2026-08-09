# Pending Work

## Local domains (`local` driver) — follow-ups after v0.1.2

Landed on `main` as `e58b8dd..6147991`. Two known gaps, neither a regression:

- **No end-to-end coverage.** `crates/wormhole-e2e` and `crates/wormhole-cli/tests/` have no case for
  `--endpoint local`. Unit coverage is real (the router tests proxy over live TCP sockets), but the
  CLI-level path has never been executed. The privileged paths — `local trust`, `local elevate`, and
  `local hosts sync` — are exercised only against the injected `CommandRunner` fake and temp paths, so
  no real trust-store, LaunchDaemon/systemd, or `/etc/hosts` mutation has ever been performed.
- **Unreproduced test flake.** Before the determinism fixes in `b92f239`, `cargo test -p wormhole-core`
  failed roughly 2 in 6 runs in `ports::tests::reservation_holds_port_until_child_spawn` and
  `wormhole_stream::tests::retries_when_local_listener_appears_after_initial_connect_failure`, both
  pre-existing port/timing races. After the fixes it did not reproduce in 35 consecutive runs, but the
  root cause was never confirmed. If either test goes red intermittently in CI, start there.

Note that `b92f239` traded a little coverage for determinism: `ports_tests.rs` no longer asserts that a
reserved port is released on drop, because that assertion was the race.
