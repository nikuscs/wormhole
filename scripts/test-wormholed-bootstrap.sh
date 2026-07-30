#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
SCRIPT="$ROOT/scripts/wormholed-bootstrap.sh"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/wormholed-bootstrap-tests.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

FAKE_BIN="$TMP/fake-bin"
mkdir -p "$FAKE_BIN"
cat >"$FAKE_BIN/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$WORMHOLE_TEST_SYSTEMCTL_LOG"
if [ "${WORMHOLE_TEST_SYSTEMCTL_FAIL_RESTART:-0}" -eq 1 ] && [ "$1" = restart ]; then
    exit 1
fi
exit 0
EOF
chmod +x "$FAKE_BIN/systemctl"

FAKE_WORMHOLED="$TMP/fake-wormholed"
cat >"$FAKE_WORMHOLED" <<'EOF'
#!/bin/sh
case "$1" in
    serve)
        [ "$2" = "--check" ]
        [ "$3" = "--config" ]
        [ -s "$4" ]
        if [ -n "${WORMHOLE_TEST_REAL_BINARY:-}" ]; then
            "$WORMHOLE_TEST_REAL_BINARY" "$@"
        fi
        ;;
    key)
        [ "$2" = "authorize" ]
        ;;
    invite)
        [ "$2" = "create" ]
        printf 'Invite ID: test-invite\nToken: whi_test_token\n'
        ;;
    status)
        printf '{"status":"ok"}\n'
        ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$FAKE_WORMHOLED"

run_bootstrap() {
    root=$1
    shift
    WORMHOLE_BOOTSTRAP_ROOT="$root" \
    WORMHOLE_BOOTSTRAP_TEST_BINARY="$FAKE_WORMHOLED" \
    WORMHOLE_TEST_SYSTEMCTL_LOG="$TMP/systemctl.log" \
    WORMHOLE_TEST_SYSTEMCTL_FAIL_RESTART="${WORMHOLE_TEST_SYSTEMCTL_FAIL_RESTART:-0}" \
    PATH="$FAKE_BIN:$PATH" \
        sh "$SCRIPT" "$@"
}

INSTALL_ROOT="$TMP/root-self-signed"
run_bootstrap "$INSTALL_ROOT" \
    --domain tun.example.com --self-signed --skip-dns-check -y >"$TMP/self-signed.out"

test -x "$INSTALL_ROOT/usr/local/bin/wormholed"
test -f "$INSTALL_ROOT/etc/systemd/system/wormholed.service"
test -f "$INSTALL_ROOT/etc/wormhole/wormholed.toml"
grep -F 'domains = ["tun.example.com"]' "$INSTALL_ROOT/etc/wormhole/wormholed.toml" >/dev/null
grep -F 'mode = "self-signed"' "$INSTALL_ROOT/etc/wormhole/wormholed.toml" >/dev/null
grep -F 'DynamicUser=yes' "$INSTALL_ROOT/etc/systemd/system/wormholed.service" >/dev/null
grep -F 'ProtectSystem=strict' "$INSTALL_ROOT/etc/systemd/system/wormholed.service" >/dev/null
grep -F 'Token: whi_test_token' "$TMP/self-signed.out" >/dev/null
grep -F 'wormhole remote add personal tun.example.com:443 --invite <token>' \
    "$TMP/self-signed.out" >/dev/null

if run_bootstrap "$INSTALL_ROOT" \
    --domain tun.example.com --self-signed --skip-dns-check -y >"$TMP/reinstall.out" 2>&1; then
    echo 'bootstrap unexpectedly overwrote an installation without --force' >&2
    exit 1
fi
grep -F 'rerun with --force' "$TMP/reinstall.out" >/dev/null

run_bootstrap "$INSTALL_ROOT" \
    --domain tun.example.com --self-signed --skip-dns-check --force -y >"$TMP/force.out"
find "$INSTALL_ROOT/etc/wormhole/backups" -name wormholed.toml -type f | grep . >/dev/null

TOKEN="$TMP/cloudflare.token"
printf '%s' 'super-secret-token-value' >"$TOKEN"
chmod 600 "$TOKEN"
ACME_ROOT="$TMP/root-acme"
run_bootstrap "$ACME_ROOT" \
    --domain edge.example.com --email ops@example.com \
    --cloudflare-token-file "$TOKEN" --skip-dns-check -y >"$TMP/acme.out"

credential_mode=$(stat -c '%a' "$ACME_ROOT/etc/wormhole/credentials/cloudflare_token" 2>/dev/null \
    || stat -f '%Lp' "$ACME_ROOT/etc/wormhole/credentials/cloudflare_token")
test "$credential_mode" = 600
grep -F 'mode = "acme-dns01"' "$ACME_ROOT/etc/wormhole/wormholed.toml" >/dev/null
grep -F 'LoadCredential=cloudflare_token:' "$ACME_ROOT/etc/systemd/system/wormholed.service" >/dev/null
if grep -F 'super-secret-token-value' "$TMP/acme.out" \
    "$ACME_ROOT/etc/wormhole/wormholed.toml" \
    "$ACME_ROOT/etc/systemd/system/wormholed.service" >/dev/null; then
    echo 'secret leaked into output or non-secret configuration' >&2
    exit 1
fi

if command -v openssl >/dev/null 2>&1; then
    STATIC_CERT="$TMP/static-cert.pem"
    STATIC_KEY="$TMP/static-key.pem"
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -subj '/CN=static.example.com' \
        -addext 'subjectAltName=DNS:static.example.com,DNS:*.static.example.com' \
        -keyout "$STATIC_KEY" -out "$STATIC_CERT" >/dev/null 2>&1
    chmod 600 "$STATIC_KEY"
    STATIC_ROOT="$TMP/root-static"
    run_bootstrap "$STATIC_ROOT" \
        --domain static.example.com --static-cert-file "$STATIC_CERT" \
        --static-key-file "$STATIC_KEY" --skip-dns-check -y >"$TMP/static.out"
    grep -F 'mode = "static"' "$STATIC_ROOT/etc/wormhole/wormholed.toml" >/dev/null
    grep -F 'LoadCredential=tls_key:' \
        "$STATIC_ROOT/etc/systemd/system/wormholed.service" >/dev/null
fi

INSECURE_TOKEN="$TMP/insecure.token"
printf '%s' token >"$INSECURE_TOKEN"
chmod 644 "$INSECURE_TOKEN"
if run_bootstrap "$TMP/root-insecure" \
    --domain bad.example.com --email ops@example.com \
    --cloudflare-token-file "$INSECURE_TOKEN" --skip-dns-check -y >"$TMP/insecure.out" 2>&1; then
    echo 'bootstrap accepted a group/world-readable secret' >&2
    exit 1
fi
grep -F 'must not be group- or world-readable' "$TMP/insecure.out" >/dev/null

ROLLBACK_ROOT="$TMP/root-rollback"
if WORMHOLE_TEST_SYSTEMCTL_FAIL_RESTART=1 run_bootstrap "$ROLLBACK_ROOT" \
    --domain rollback.example.com --self-signed --skip-dns-check -y \
    >"$TMP/rollback.out" 2>&1; then
    echo 'bootstrap unexpectedly succeeded after service restart failure' >&2
    exit 1
fi
test ! -e "$ROLLBACK_ROOT/etc/wormhole/wormholed.toml"
test ! -e "$ROLLBACK_ROOT/etc/systemd/system/wormholed.service"
grep -F 'disable --now wormholed' "$TMP/systemctl.log" >/dev/null

if run_bootstrap "$TMP/root-incomplete" \
    --domain incomplete.example.com --skip-dns-check -y >"$TMP/incomplete.out" 2>&1; then
    echo 'bootstrap accepted incomplete noninteractive options' >&2
    exit 1
fi
grep -F 'select Cloudflare, static, or self-signed' "$TMP/incomplete.out" >/dev/null

printf 'wormholed bootstrap tests passed\n'
