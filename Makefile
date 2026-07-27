.PHONY: fmt lint check test build coverage e2e size

fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets -- -D warnings

check:
	cargo check --workspace

test:
	cargo test --workspace

build:
	cargo build --workspace

coverage:
	cargo llvm-cov --workspace --html

e2e:
	cargo build -p wormhole-cli -p wormholed
	cargo test -p wormhole-e2e -- --ignored --test-threads=4

size:
	@fail=0; \
	for f in $$(find crates -path '*/src/*' -name '*.rs'); do \
	  n=$$(wc -l < "$$f"); cap=500; case "$$f" in *_tests.rs) cap=800;; esac; \
	  if [ "$$n" -gt "$$cap" ]; then echo "$$f: $$n lines (cap $$cap)"; fail=1; fi; \
	done; exit $$fail
