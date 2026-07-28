.PHONY: fmt lint check test build coverage e2e size policy ci

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

coverage:
	cargo llvm-cov --workspace --html --locked

e2e:
	cargo build -p wormhole-cli -p wormholed --locked
	cargo test -p wormhole-e2e --locked -- --ignored --test-threads=4

policy:
	cargo deny check
	cargo audit

ci: fmt lint size build test policy

size:
	@fail=0; \
	for f in $$(find crates -path '*/src/*' -name '*.rs'); do \
	  n=$$(wc -l < "$$f"); cap=500; case "$$f" in *_tests.rs) cap=800;; esac; \
	  if [ "$$n" -gt "$$cap" ]; then echo "$$f: $$n lines (cap $$cap)"; fail=1; fi; \
	done; exit $$fail
