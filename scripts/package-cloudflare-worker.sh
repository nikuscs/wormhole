#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CRATE_DIR="$ROOT/crates/wormholed-cloudflare"
VERSION=
OUTPUT_DIR=

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION=${2:?missing --version value}; shift 2 ;;
    --output-dir) OUTPUT_DIR=${2:?missing --output-dir value}; shift 2 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done
[[ -n "$VERSION" && -n "$OUTPUT_DIR" ]] || {
  printf 'usage: package-cloudflare-worker.sh --version VERSION --output-dir DIR\n' >&2
  exit 2
}

OUTPUT_DIR=$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)
STAGING="$OUTPUT_DIR/wormholed-cloudflare-worker"
ASSET="$OUTPUT_DIR/wormholed-cloudflare-worker.tar.gz"
rm -rf "$STAGING"
mkdir -p "$STAGING/build/worker"

sed '/^[[:space:]]*\/\//d' "$CRATE_DIR/wrangler.jsonc" \
  | jq 'del(."$schema", .build)' >"$STAGING/wrangler.jsonc"
WRANGLER_VERSION=$(jq -er '.packages["node_modules/wrangler"].version' \
  "$CRATE_DIR/package-lock.json")
jq -n --arg version "$VERSION" --arg wrangler "$WRANGLER_VERSION" \
  '{schema: 1, wormhole_version: $version, wrangler_version: $wrangler}' \
  >"$STAGING/manifest.json"
install -m 0644 "$CRATE_DIR/build/index.js" "$STAGING/build/index.js"
install -m 0644 "$CRATE_DIR/build/index_bg.wasm" "$STAGING/build/index_bg.wasm"
install -m 0644 "$CRATE_DIR/build/package.json" "$STAGING/build/package.json"
install -m 0644 "$CRATE_DIR/build/worker/shim.mjs" "$STAGING/build/worker/shim.mjs"
install -m 0644 "$ROOT/LICENSE" "$STAGING/LICENSE"
install -m 0644 "$ROOT/THIRD_PARTY_NOTICES" "$STAGING/THIRD_PARTY_NOTICES"
find "$STAGING" -exec touch -t 198001010000 {} +

LIST=$(mktemp)
ARCHIVE=$(mktemp)
trap 'rm -f "$LIST" "$ARCHIVE"' EXIT
(
  cd "$STAGING"
  find . -print | LC_ALL=C sort >"$LIST"
  COPYFILE_DISABLE=1 tar --no-recursion --format ustar --uid 0 --gid 0 --numeric-owner \
    -cf "$ARCHIVE" -T "$LIST"
)
gzip -n -c "$ARCHIVE" >"$ASSET"
CHECKSUM=$(shasum -a 256 "$ASSET" | awk '{print $1}')
printf '%s  %s\n' "$CHECKSUM" "$(basename "$ASSET")" >"$ASSET.sha256"
