#!/usr/bin/env bash
set -euo pipefail

REMOTE=${1:?usage: test-cloudflare-semantics.sh REMOTE DOMAIN}
DOMAIN=${2:?usage: test-cloudflare-semantics.sh REMOTE DOMAIN}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
ORIGIN_PID=
TUNNEL_PID=
cleanup() {
  if [[ -n "$TUNNEL_PID" ]]; then kill "$TUNNEL_PID" 2>/dev/null || true; fi
  if [[ -n "$ORIGIN_PID" ]]; then kill "$ORIGIN_PID" 2>/dev/null || true; fi
  if [[ -n "$TUNNEL_PID" ]]; then wait "$TUNNEL_PID" 2>/dev/null || true; fi
  if [[ -n "$ORIGIN_PID" ]]; then wait "$ORIGIN_PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM
assert_equal() {
  local actual=$1 expected=$2 label=$3
  if [[ "$actual" != "$expected" ]]; then
    printf '%s: expected %q, got %q\n' "$label" "$expected" "$actual" >&2
    exit 1
  fi
}

python3 "$ROOT/scripts/cloudflare-semantics-server.py" >"$TMP/port" 2>"$TMP/origin.log" &
ORIGIN_PID=$!
for _ in {1..100}; do
  [[ -s "$TMP/port" ]] && break
  kill -0 "$ORIGIN_PID" 2>/dev/null || { cat "$TMP/origin.log" >&2; exit 1; }
  sleep 0.05
done
PORT=$(cat "$TMP/port")
HOST="wormhole-semantics-$$"
URL="https://${HOST}.${DOMAIN}"

wormhole http "$PORT" --foreground --remote "$REMOTE" --host "$HOST" >"$TMP/tunnel.log" 2>&1 &
TUNNEL_PID=$!
READY=0
for _ in {1..100}; do
  if curl --fail --silent --show-error --max-time 5 "$URL/" >"$TMP/index" 2>/dev/null; then READY=1; break; fi
  kill -0 "$TUNNEL_PID" 2>/dev/null || { cat "$TMP/tunnel.log" >&2; exit 1; }
  sleep 0.2
done
if [[ "$READY" != 1 ]]; then
  cat "$TMP/tunnel.log" >&2
  exit 1
fi
grep -q '<!doctype html>' "$TMP/index"

gzip_body=$(curl --fail --silent --show-error --max-time 20 --compressed "$URL/gzip")
assert_equal "$gzip_body" "compressed hello" "compressed response"
curl --fail --silent --show-error --max-time 20 --head "$URL/head" >"$TMP/head"
grep -qi '^content-length: 7' "$TMP/head"
grep -qi '^x-robots-tag: noindex, nofollow, noarchive, nosnippet' "$TMP/head"
for status in 204 205 304; do
  actual=$(curl --silent --show-error --max-time 20 --output /dev/null --write-out '%{http_code}' "$URL/status/$status")
  assert_equal "$actual" "$status" "status $status"
done
events=$(curl --fail --silent --show-error --max-time 20 "$URL/sse")
assert_equal "$events" $'data: first\n\ndata: second' "SSE response"
range=$(curl --fail --silent --show-error --max-time 20 --header 'Range: bytes=2-5' "$URL/range")
assert_equal "$range" "2345" "range response"
curl --fail --silent --show-error --max-time 20 --dump-header "$TMP/cookies.headers" --output /dev/null "$URL/cookies"
cookies=$(grep -ci '^set-cookie:' "$TMP/cookies.headers")
assert_equal "$cookies" "2" "duplicate cookies"
curl --fail --silent --show-error --max-time 20 "$URL/large" >"$TMP/large"
large_size=$(wc -c <"$TMP/large" | tr -d ' ')
assert_equal "$large_size" "2097152" "large download"
python3 -c 'import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b"u" * (2 * 1024 * 1024))' "$TMP/upload"
uploaded=$(curl --fail --silent --show-error --max-time 20 --request POST --data-binary "@$TMP/upload" "$URL/upload")
assert_equal "$uploaded" "2097152" "large upload"
seq 1 24 | xargs -P 24 -I '{}' sh -c \
  "curl --fail --silent --show-error --max-time 20 \"\$1/slow/\$3\" >\"\$2/parallel-\$3\"" \
  _ "$URL" "$TMP" '{}'
for index in {1..24}; do
  parallel=$(cat "$TMP/parallel-$index")
  assert_equal "$parallel" "$index" "parallel request $index"
done
python3 "$ROOT/scripts/cloudflare-websocket-client.py" "${URL/https:/wss:}/websocket"
if curl --fail --silent --show-error --max-time 20 "$URL/disconnect" >"$TMP/disconnect" 2>/dev/null; then
  disconnect_size=$(wc -c <"$TMP/disconnect" | tr -d ' ')
  assert_equal "$disconnect_size" "5" "truncated response"
fi
curl --fail --silent --show-error --max-time 20 "$URL/" >/dev/null

printf 'Cloudflare semantics passed: %s\n' "$URL"
