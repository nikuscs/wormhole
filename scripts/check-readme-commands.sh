#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
readme="$root/README.md"
commands=$(awk '
  /^```console$/ { console = 1; next }
  /^```$/ { console = 0; next }
  console && ($1 == "wormhole" || $1 == "wormholed") { print }
' "$readme")

require_line() {
  printf '%s\n' "$commands" | grep -F -- "$1" >/dev/null
}

check_help() {
  binary=$1
  shift
  "$root/target/debug/$binary" "$@" --help >/dev/null
}

cargo build --workspace --locked --quiet
require_line 'wormholed init'
require_line 'wormholed key authorize'
require_line 'wormholed serve'
require_line 'wormhole remote add'
require_line 'wormhole http 3000'
require_line '--endpoint wormhole --endpoint tailscale --endpoint cloudflare'
require_line 'wormhole run -- bun run dev'
require_line 'wormhole up'
check_help wormholed init
check_help wormholed key authorize
check_help wormholed serve
check_help wormhole remote add
check_help wormhole http
check_help wormhole run
check_help wormhole up
