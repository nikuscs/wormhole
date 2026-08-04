COVERAGE_TARGET_ROOT ?= $(CURDIR)/target
LLVM_COV_TARGET_DIR := $(COVERAGE_TARGET_ROOT)/llvm-cov-target

.PHONY: fmt lint check test build install coverage coverage-e2e e2e cloudflare-semantics shell size notices notices-check policy ci signoff

fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --workspace --all-targets --locked -- -D warnings

check:
	cargo check --workspace --all-targets --locked

test:
	cargo test --workspace --locked

build:
	cargo build --workspace --locked

install:
	cargo install --path crates/wormhole-cli --locked --force
	cargo install --path crates/wormholed --locked --force

coverage:
	cargo llvm-cov --workspace --html --locked

coverage-e2e:
	CARGO_TARGET_DIR="$(COVERAGE_TARGET_ROOT)" cargo llvm-cov --workspace --no-report --locked
	CARGO_TARGET_DIR="$(COVERAGE_TARGET_ROOT)" WORMHOLE_E2E_BIN_DIR="$(LLVM_COV_TARGET_DIR)/debug" cargo llvm-cov -p wormhole-e2e --no-clean --summary-only --locked -- --ignored --test-threads=4
	CARGO_TARGET_DIR="$(COVERAGE_TARGET_ROOT)" cargo llvm-cov report --html

e2e:
	cargo build -p wormhole-cli -p wormholed --locked
	cargo test -p wormhole-cli --test run_command run_vite_app_exposes_public_url_to_client --locked -- --ignored --test-threads=1
	WORMHOLE_E2E_BIN_DIR="$(CURDIR)/target/debug" cargo test -p wormhole-e2e --locked -- --ignored --test-threads=4

cloudflare-semantics:
	@test -n "$(CF_REMOTE)" -a -n "$(CF_DOMAIN)" || { echo "set CF_REMOTE and CF_DOMAIN" >&2; exit 2; }
	scripts/test-cloudflare-semantics.sh "$(CF_REMOTE)" "$(CF_DOMAIN)"

shell:
	shellcheck scripts/*.sh
	python3 -m py_compile tests/cloudflare/semantics_server.py tests/cloudflare/websocket_client.py
	cargo build -p wormholed --locked
	WORMHOLE_TEST_REAL_BINARY=target/debug/wormholed scripts/test-wormholed-bootstrap.sh

notices:
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; \
		cargo about generate --workspace --locked --fail --output-file "$$tmp" about.hbs; \
		sed 's/[[:space:]]*$$//' "$$tmp" > THIRD_PARTY_NOTICES

notices-check:
	@raw=$$(mktemp); tmp=$$(mktemp); trap 'rm -f "$$raw" "$$tmp"' EXIT; \
		cargo about generate --workspace --locked --fail --output-file "$$raw" about.hbs; \
		sed 's/[[:space:]]*$$//' "$$raw" > "$$tmp"; \
		cmp -s THIRD_PARTY_NOTICES "$$tmp" || { \
			echo "THIRD_PARTY_NOTICES is stale; run make notices" >&2; exit 1; \
		}

policy: notices-check
	cargo deny check
	cargo audit

ci: fmt lint size build test policy

signoff: fmt lint size build test e2e shell policy
	gh signoff

size:
	@fail=0; \
	for f in $$(find crates -path '*/src/*' -name '*.rs'); do \
	  n=$$(wc -l < "$$f"); cap=500; case "$$f" in *_tests.rs) cap=800;; esac; \
	  if [ "$$n" -gt "$$cap" ]; then echo "$$f: $$n lines (cap $$cap)"; fail=1; fi; \
	done; exit $$fail
