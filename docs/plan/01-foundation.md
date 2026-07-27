# Stage 01 — Foundation

**Goal:** compiling empty workspace with all conventions, lints, CI, and tooling locked, so every
later stage only adds code, never build scaffolding.

**Depends on:** nothing. **Blocks:** everything.

**Status legend:** tick a box only after its validation command passes.

## Toolchain & conventions (normative for the whole repo)

- Rust stable **1.97+** (latest stable as of 2026-07 is 1.97.1), **edition 2024**,
  `rust-version = "1.97"`.
- `unsafe_code = "forbid"`. Clippy `all` + `pedantic` + `nursery` + `cargo` at `warn`, CI runs
  with `-D warnings`. `todo!`/`unimplemented!`/`dbg!`/`print_stdout`/`print_stderr` are `deny` —
  the CLI prints through one dedicated output module that locally allows it.
- rustfmt: `edition 2024`, `max_width = 100`, `use_small_heuristics = "Max"`.
- Pure-Rust TLS everywhere (`rustls`); never OpenSSL. No `chrono` — use `jiff`. No `serde_yaml`
  (deprecated) — TOML only.
- Errors: `thiserror` v2 in libraries, `anyhow` only in the two binary crates.
- Every dependency comes from `[workspace.dependencies]`. Adding one = add it there + a row to
  the table below with justification.
- **Tests live in sibling files, never inline.** A file `foo.rs` needing unit tests ends with
  `#[cfg(test)] #[path = "foo_tests.rs"] mod tests;` and the tests go in `foo_tests.rs` next to
  it (child module — `use super::*;` still reaches private items). No inline
  `mod tests { ... }` blocks anywhere. Integration tests go in `crates/<c>/tests/`.
- **File size caps (AI-friendly).** Source files: soft cap 400 lines, hard cap 500 —
  `make size` fails CI above it (`*_tests.rs` files get 800). One module = one responsibility;
  split into submodules before hitting the cap, never golf code to stay under it.
- **Function complexity.** `/clippy.toml` sets `too-many-lines-threshold = 80` and
  `cognitive-complexity-threshold = 20`; with `-D warnings` both are hard gates.
- **No cycles, by layers.** Crate graph is a DAG and cargo enforces it — never add a reverse
  edge (`proto` depends on nothing internal; `core` and `wormholed` depend only on `proto`;
  `cli` on `core`+`proto`). Inside a crate, `error.rs`/`model.rs`-style leaf modules never
  `use` sibling feature modules — dependencies point downward only.
- Test-only escape hatches (e.g. `WORMHOLE_ENABLE_MOCK_DRIVER`) must be compiled out of release
  builds (`#[cfg(debug_assertions)]` or a `test-support` cargo feature that release profiles
  never enable).

## Tasks

- [x] **F1 — Workspace root.** Create `/Cargo.toml`:

  ```toml
  [workspace]
  resolver = "3"
  members = ["crates/*"]

  [workspace.package]
  version = "0.0.0"            # unreleased development baseline; R2's first minor bump owns v0.1.0
  edition = "2024"
  rust-version = "1.97"
  license = "MIT"
  repository = "https://github.com/nikuscs/wormhole"

  [workspace.lints.rust]
  unsafe_code = "forbid"

  [workspace.lints.clippy]
  all = { level = "warn", priority = -1 }
  pedantic = { level = "warn", priority = -1 }
  nursery = { level = "warn", priority = -1 }
  cargo = { level = "warn", priority = -1 }
  module_name_repetitions = "allow"
  must_use_candidate = "allow"
  missing_errors_doc = "allow"
  missing_panics_doc = "allow"
  needless_pass_by_value = "allow"
  future_not_send = "allow"
  cast_possible_truncation = "allow"
  cast_possible_wrap = "allow"
  cast_sign_loss = "allow"
  return_self_not_must_use = "allow"
  cargo_common_metadata = "allow"
  multiple_crate_versions = "allow"
  dbg_macro = "deny"
  todo = "deny"
  unimplemented = "deny"
  print_stdout = "deny"
  print_stderr = "deny"

  [workspace.dependencies]
  # runtime
  tokio = { version = "1.53", features = ["full"] }
  tokio-util = { version = "0.7", features = ["codec"] }
  futures = "0.3"
  bytes = "1.12"
  # transport / tls
  quinn = "0.11"
  rustls = "0.23"
  tokio-rustls = "0.26"
  rustls-pki-types = "1.15"
  rcgen = "0.14"
  instant-acme = "0.8"
  tokio-tungstenite = { version = "0.30", features = ["rustls-tls-webpki-roots"] }
  # http
  hyper = { version = "1.11", features = ["full"] }
  hyper-util = { version = "0.1", features = ["full"] }
  http-body-util = "0.1"
  http = "1.4"
  axum = "0.8"
  tower = "0.5"
  utoipa = { version = "5", features = ["axum_extras", "uuid"] }   # verify latest major
  utoipa-axum = "0.2"                                              # verify latest
  utoipa-scalar = { version = "0.3", features = ["axum"] }         # verify latest
  reqwest = { version = "0.13", default-features = false, features = ["json", "rustls"] }
  # crypto / identity
  ed25519-dalek = { version = "3", features = ["rand_core", "pkcs8"] }
  sha2 = "0.10"             # key fingerprints (P3), share-link HMAC (W8 uses hmac too)
  hmac = "0.12"
  argon2 = "0.5"            # stable Argon2id verifier for human basic-auth passwords
  subtle = "2.6"            # constant-time edge-auth credential comparison
  webpki-roots = "1"        # client trust anchors; verify latest major
  rand = "0.10"
  zeroize = { version = "1.9", features = ["derive"] }
  base64 = "0.23"
  # serde / config
  serde = { version = "1", features = ["derive"] }
  serde_json = "1"
  toml = "1.1"
  # cli
  clap = { version = "4.6", features = ["derive", "env"] }
  clap_complete = "4.6"
  comfy-table = "7.2"
  owo-colors = "4"          # verify latest major on crates.io when adding
  indicatif = "0.18"
  # observability
  tracing = "0.1"
  tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
  # storage / paths
  redb = "4"
  directories = "6"
  camino = { version = "1.2", features = ["serde1"] }
  # errors
  thiserror = "2"
  anyhow = "1"
  # ids / time / misc
  uuid = { version = "1.24", features = ["v7", "serde"] }
  jiff = { version = "0.2", features = ["serde"] }
  humantime = "2.4"
  dashmap = "6"
  parking_lot = "0.12"
  governor = "0.10"
  async-trait = "0.1"
  # system: interfaces, ports, processes
  if-addrs = "0.15"
  netdev = "0.45"
  listeners = "0.6"
  sysinfo = "0.39"          # process tree for descendant-pid discovery (C4)
  socket2 = "0.6"
  nix = { version = "0.31", features = ["process", "signal", "fs"] }   # fs = flock
  # dev/test
  tempfile = "3.27"
  assert_cmd = "2.2"
  predicates = "3.1"
  insta = { version = "1.48", features = ["json"] }
  proptest = "1.11"
  criterion = "0.8"

  [profile.dev]
  debug = 1

  [profile.dev.package."*"]
  opt-level = 1

  [profile.release]
  lto = true
  codegen-units = 1
  strip = true
  ```

  Versions above were verified against crates.io on 2026-07-26. If `cargo update` pulls a newer
  **major**, stay on the listed major unless the newer one compiles cleanly with no code changes.
  Validation: file exists; `cargo metadata -q >/dev/null` succeeds after F3.

- [x] **F2 — Repo hygiene files.**
  - `/rustfmt.toml`:
    ```toml
    edition = "2024"
    max_width = 100
    use_small_heuristics = "Max"
    ```
  - `/rust-toolchain.toml`:
    ```toml
    [toolchain]
    channel = "stable"
    components = ["rustfmt", "clippy"]
    ```
  - `/.gitignore`: `target/`, `dist/`, `*.pem`, `*.key`, `.env`, `.DS_Store`, `wormhole.toml.local`
  - `/deny.toml` (cargo-deny): licenses allow `MIT`, `Apache-2.0`, `Apache-2.0 WITH LLVM-exception`,
    `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Unicode-3.0`, `Zlib`, `CDLA-Permissive-2.0`;
    `[advisories]` deny unmaintained+vulnerabilities; `[bans]` `multiple-versions = "warn"`.
  - `/clippy.toml`:
    ```toml
    too-many-lines-threshold = 80
    cognitive-complexity-threshold = 20
    ```
  - `/Makefile` mirroring crauler: `fmt`, `lint` (`cargo clippy --all-targets -- -D warnings`),
    `check`, `test`, `build`, `coverage` (`cargo llvm-cov --workspace --html`),
    `e2e` (`cargo test -p wormhole-e2e -- --ignored`), and `size`:
    ```make
    size:
	@fail=0; \
	for f in $$(find crates -path '*/src/*' -name '*.rs'); do \
	  n=$$(wc -l < "$$f"); cap=500; case "$$f" in *_tests.rs) cap=800;; esac; \
	  if [ "$$n" -gt "$$cap" ]; then echo "$$f: $$n lines (cap $$cap)"; fail=1; fi; \
	done; exit $$fail
    ```

  Validation: `make lint` and `make size` run (fail only on code, not on the Makefile).

- [x] **F3 — Crate skeletons.** Create the five crates. Every crate's `Cargo.toml` sets
  `lints.workspace = true` and inherits `edition/version/license/rust-version/repository` via
  `.workspace = true`. Library crates start as:

  ```
  crates/wormhole-proto/src/lib.rs      # pub mod placeholder; doc comment describing the crate
  crates/wormhole-core/src/lib.rs
  crates/wormhole-cli/src/main.rs       # fn main() { } for now; [[bin]] name = "wormhole"
  crates/wormholed/src/lib.rs           # ALL relay logic lives in the lib...
  crates/wormholed/src/main.rs          # ...bin is a thin wrapper; [[bin]] name = "wormholed"
  crates/wormhole-e2e/src/lib.rs        # empty; tests live in crates/wormhole-e2e/tests/
  ```

  `wormholed` is lib+bin on purpose: tests can embed the relay in-process, and a future
  combined single-binary (`wormhole serve` / multicall) stays a trivial option instead of a
  refactor.

  Dependency edges (enforce — nothing else): `core → proto`, `cli → {core, proto}`,
  `wormholed → proto`, `e2e → dev-deps on nothing (drives binaries via assert_cmd)`.
  Each `lib.rs`/`main.rs` gets `//!` crate-level docs (2–4 lines, from stage 00 architecture).
  Validation: `cargo build --workspace` and `cargo clippy --all-targets -- -D warnings` pass.

- [x] **F4 — CLI output module (lint escape hatch).** `crates/wormhole-cli/src/output.rs`:
  the **only** place allowed to print. Everything user-visible goes through it, and it owns the
  `--json` contract used by every command.

  ```rust
  //! All terminal output. The only module allowed to print.
  #![allow(clippy::print_stdout, clippy::print_stderr)]

  use serde::Serialize;

  pub enum Format { Human, Json }

  pub fn emit<T: Serialize + HumanRender>(format: Format, value: &T) {
      match format {
          Format::Json => println!("{}", serde_json::to_string_pretty(value).expect("serialize")),
          Format::Human => println!("{}", value.render()),
      }
  }

  pub trait HumanRender { fn render(&self) -> String; }
  ```

  Validation: `cargo clippy -p wormhole-cli --all-targets -- -D warnings` passes with a dummy
  caller.

- [x] **F5 — CI.** `/.github/workflows/ci.yml`, same shape as
  `~/projects/crauler/.github/workflows/ci.yml` (read it): trigger `workflow_dispatch` **and**
  `pull_request` (this repo wants CI on PRs), `RUSTFLAGS: -Dwarnings`, `CC: clang`/`CXX: clang++`
  (aws-lc-sys), jobs: fmt-check, clippy `--locked`, `make size`, test `--locked` on ubuntu-latest + macos-14,
  `cargo deny check` (via `EmbarkStudios/cargo-deny-action@v2`), release-build matrix
  {x86_64-linux, aarch64-linux (ubuntu-24.04-arm), aarch64-darwin} building both binaries.
  Validation: `actionlint` if available, else YAML parses (`python3 -c "import yaml,sys;yaml.safe_load(open('.github/workflows/ci.yml'))"`).

- [x] **F6 — AGENTS.md.** Root `/AGENTS.md` (+ `CLAUDE.md` symlink to it): condensed rules —
  scope mantra, conventions above, "plan lives in docs/plan, tick boxes only after validation",
  make targets, forbidden deps (openssl, chrono, serde_yaml), the F4 print rule, the
  sibling-`_tests.rs` test rule, file-size caps, and the stage index. Keep under 120 lines.
  Validation: file exists, symlink resolves.

- [x] **F7 — README stub.** One-paragraph description + install placeholder + `docs/plan` pointer.
  Full README is stage 09; don't spend time here.

## Acceptance gate

```bash
cargo fmt --all -- --check \
&& cargo clippy --all-targets --locked -- -D warnings \
&& make size \
&& cargo build --workspace --locked \
&& cargo test --workspace --locked
```

All pass on a clean checkout. Commit as `feat: workspace foundation` (single commit; do not push
unless asked).
