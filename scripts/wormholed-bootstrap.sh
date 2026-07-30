#!/bin/sh
set -eu

REPOSITORY=${WORMHOLE_BOOTSTRAP_REPOSITORY:-nikuscs/wormhole}
ROOT=${WORMHOLE_BOOTSTRAP_ROOT:-}
CONFIG_DIR="$ROOT/etc/wormhole"
CONFIG_PATH="$CONFIG_DIR/wormholed.toml"
CREDENTIAL_DIR="$CONFIG_DIR/credentials"
BACKUP_DIR="$CONFIG_DIR/backups"
DATA_DIR="$ROOT/var/lib/wormhole"
UNIT_PATH="$ROOT/etc/systemd/system/wormholed.service"
BINARY_PATH="$ROOT/usr/local/bin/wormholed"
INSTALLER_URL="https://github.com/$REPOSITORY/releases/latest/download/wormholed-installer.sh"

DOMAINS=
EMAIL=
TLS_MODE=
TOKEN_FILE=
CERT_FILE=
KEY_FILE=
CLIENT_KEY_FILE=
CLIENT_NAME=laptop
YES=0
FORCE=0
CONFIGURE_UFW=0
SKIP_DNS=0
TMP=
HAD_CONFIG=0
HAD_UNIT=0
HAD_BINARY=0
BACKUP_PATH=

usage() {
    cat <<'EOF'
Usage: wormholed-bootstrap.sh [OPTIONS]

Securely install and configure a Wormhole relay on Debian/Ubuntu with systemd.
Interactive by default. Noninteractive mode requires -y and complete TLS inputs.

Required:
  --domain DOMAIN                 Public relay domain; repeat for additional domains

Production TLS (choose one):
  --email ADDRESS                 ACME contact email
  --cloudflare-token-file PATH    File containing a scoped Cloudflare DNS API token
  --static-cert-file PATH         PEM chain covering every configured domain/wildcard
  --static-key-file PATH          Matching PEM private key

Development TLS:
  --self-signed                   Explicitly use development-only certificates

Optional:
  --client-key-file PATH          Authorize a client public-key file after startup
  --client-name NAME              Authorized client name (default: laptop)
  --configure-ufw                 Install/configure UFW after allowing SSH and relay ports
  --skip-dns-check                Continue without resolving apex and wildcard probe names
  --force                         Back up and replace an existing installation
  -y, --yes                       Accept the displayed plan; never implies --force or UFW
  -h, --help                      Show this help

Examples:
  curl --proto '=https' --tlsv1.2 -LsSf \
    https://github.com/nikuscs/wormhole/releases/latest/download/wormholed-bootstrap.sh \
    | sudo sh -s -- --domain tun.example.com \
        --email ops@example.com --cloudflare-token-file /root/cloudflare.token -y

  sudo sh wormholed-bootstrap.sh --domain tun.example.com \
    --static-cert-file /root/fullchain.pem --static-key-file /root/privkey.pem -y
EOF
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

say() {
    printf '%s\n' "$*"
}

cleanup() {
    if [ -n "$TMP" ] && [ -d "$TMP" ]; then
        rm -rf "$TMP"
    fi
}
trap cleanup EXIT HUP INT TERM

append_domain() {
    if [ -z "$DOMAINS" ]; then
        DOMAINS=$1
    else
        DOMAINS="$DOMAINS
$1"
    fi
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --domain)
            [ "$#" -ge 2 ] || fail "--domain requires a value"
            append_domain "$2"
            shift 2
            ;;
        --email)
            [ "$#" -ge 2 ] || fail "--email requires a value"
            EMAIL=$2
            shift 2
            ;;
        --cloudflare-token-file)
            [ "$#" -ge 2 ] || fail "--cloudflare-token-file requires a path"
            TOKEN_FILE=$2
            shift 2
            ;;
        --static-cert-file)
            [ "$#" -ge 2 ] || fail "--static-cert-file requires a path"
            CERT_FILE=$2
            shift 2
            ;;
        --static-key-file)
            [ "$#" -ge 2 ] || fail "--static-key-file requires a path"
            KEY_FILE=$2
            shift 2
            ;;
        --client-key-file)
            [ "$#" -ge 2 ] || fail "--client-key-file requires a path"
            CLIENT_KEY_FILE=$2
            shift 2
            ;;
        --client-name)
            [ "$#" -ge 2 ] || fail "--client-name requires a value"
            CLIENT_NAME=$2
            shift 2
            ;;
        --self-signed)
            [ -z "$TLS_MODE" ] || fail "choose exactly one TLS mode"
            TLS_MODE=self-signed
            shift
            ;;
        --configure-ufw)
            CONFIGURE_UFW=1
            shift
            ;;
        --skip-dns-check)
            SKIP_DNS=1
            shift
            ;;
        --force)
            FORCE=1
            shift
            ;;
        -y|--yes)
            YES=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) fail "unknown option: $1" ;;
    esac
done

if [ -n "$TOKEN_FILE" ]; then
    [ -z "$TLS_MODE" ] || fail "choose exactly one TLS mode"
    TLS_MODE=acme-dns01
fi
if [ -n "$CERT_FILE" ] || [ -n "$KEY_FILE" ]; then
    [ -z "$TLS_MODE" ] || fail "choose exactly one TLS mode"
    TLS_MODE=static
fi

prompt() {
    message=$1
    default=${2:-}
    [ -r /dev/tty ] || fail "interactive input unavailable; pass complete options with -y"
    if [ -n "$default" ]; then
        printf '%s [%s]: ' "$message" "$default" >/dev/tty
    else
        printf '%s: ' "$message" >/dev/tty
    fi
    IFS= read -r answer </dev/tty || fail "input cancelled"
    if [ -z "$answer" ]; then
        answer=$default
    fi
    printf '%s' "$answer"
}

if [ "$YES" -eq 0 ]; then
    if [ -z "$DOMAINS" ]; then
        append_domain "$(prompt 'Public relay domain (for example tun.example.com)')"
    fi
    if [ -z "$TLS_MODE" ]; then
        mode=$(prompt 'TLS mode: cloudflare, static, or self-signed' cloudflare)
        case "$mode" in
            cloudflare)
                TLS_MODE=acme-dns01
                EMAIL=$(prompt 'ACME contact email')
                TOKEN_FILE=$(prompt 'Path to Cloudflare API token file')
                ;;
            static)
                TLS_MODE=static
                CERT_FILE=$(prompt 'Path to wildcard certificate chain')
                KEY_FILE=$(prompt 'Path to wildcard private key')
                ;;
            self-signed) TLS_MODE=self-signed ;;
            *) fail "unsupported TLS mode: $mode" ;;
        esac
    fi
fi

[ -n "$DOMAINS" ] || fail "at least one --domain is required"
[ -n "$TLS_MODE" ] || fail "select Cloudflare, static, or self-signed TLS inputs"

valid_domain() {
    domain=$1
    [ "${#domain}" -le 253 ] || return 1
    case "$domain" in
        *[!a-z0-9.-]*|.*|*..*|*.) return 1 ;;
    esac
    old_ifs=$IFS
    IFS=.
    # Domain labels are intentionally split after the character whitelist above.
    # shellcheck disable=SC2086
    set -- $domain
    IFS=$old_ifs
    [ "$#" -ge 2 ] || return 1
    for label in "$@"; do
        [ -n "$label" ] && [ "${#label}" -le 63 ] || return 1
        case "$label" in -*|*-) return 1 ;; esac
    done
}

for domain in $DOMAINS; do
    valid_domain "$domain" || fail "invalid lowercase DNS domain: $domain"
done
case "$CLIENT_NAME" in ''|*[!a-zA-Z0-9._-]*) fail "invalid --client-name" ;; esac

regular_private_input() {
    path=$1
    description=$2
    [ -f "$path" ] || fail "$description is not a regular file: $path"
    [ ! -L "$path" ] || fail "$description must not be a symbolic link: $path"
}

private_secret_input() {
    path=$1
    description=$2
    regular_private_input "$path" "$description"
    mode=$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null) \
        || fail "cannot inspect $description permissions"
    [ $((mode % 100)) -eq 0 ] || fail "$description must not be group- or world-readable"
}

case "$TLS_MODE" in
    acme-dns01)
        case "$EMAIL" in
            *@*.*) ;;
            *) fail "--email must be a valid email address" ;;
        esac
        case "$EMAIL" in
            *[!a-zA-Z0-9._%+@-]*) fail "--email contains unsupported characters" ;;
        esac
        private_secret_input "$TOKEN_FILE" "Cloudflare token file"
        [ -s "$TOKEN_FILE" ] || fail "Cloudflare token file is empty"
        ;;
    static)
        regular_private_input "$CERT_FILE" "certificate file"
        private_secret_input "$KEY_FILE" "private-key file"
        if [ ! -s "$CERT_FILE" ] || [ ! -s "$KEY_FILE" ]; then
            fail "static TLS files must not be empty"
        fi
        ;;
    self-signed) ;;
    *) fail "unsupported TLS mode: $TLS_MODE" ;;
esac
if [ -n "$CLIENT_KEY_FILE" ]; then
    regular_private_input "$CLIENT_KEY_FILE" "client public-key file"
fi

if [ -z "$ROOT" ]; then
    [ "$(id -u)" -eq 0 ] || fail "run as root (for example: curl ... | sudo sh)"
    [ -r /etc/os-release ] || fail "cannot identify this Linux distribution"
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in debian|ubuntu) ;; *) fail "supported distributions: Debian and Ubuntu" ;; esac
    command -v systemctl >/dev/null 2>&1 || fail "systemd is required"
fi
for command_name in curl install mktemp stat; do
    command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
done

if [ -e "$CONFIG_PATH" ] || [ -e "$UNIT_PATH" ]; then
    [ "$FORCE" -eq 1 ] || fail "existing installation found; rerun with --force to back it up and replace it"
fi
[ -e "$CONFIG_PATH" ] && HAD_CONFIG=1
[ -e "$UNIT_PATH" ] && HAD_UNIT=1
[ -e "$BINARY_PATH" ] && HAD_BINARY=1

if [ "$SKIP_DNS" -eq 0 ]; then
    command -v getent >/dev/null 2>&1 || fail "getent is required for DNS checks (or use --skip-dns-check)"
    for domain in $DOMAINS; do
        getent ahosts "$domain" >/dev/null 2>&1 || fail "DNS does not resolve: $domain"
        getent ahosts "wormhole-bootstrap-check.$domain" >/dev/null 2>&1 \
            || fail "wildcard DNS does not resolve: *.$domain"
    done
fi

say "Wormhole relay installation plan"
say "  domains: $(printf '%s' "$DOMAINS" | tr '\n' ' ')"
say "  TLS: $TLS_MODE"
say "  config: /etc/wormhole/wormholed.toml"
say "  binary: /usr/local/bin/wormholed"
say "  service: wormholed.service"
[ "$CONFIGURE_UFW" -eq 1 ] && say "  firewall: configure and enable UFW (SSH allowed first)"
[ "$FORCE" -eq 1 ] && say "  replacement: back up existing files before restart"

if [ "$YES" -eq 0 ]; then
    answer=$(prompt 'Proceed with these root-level changes?' no)
    case "$answer" in y|Y|yes|YES) ;; *) fail "cancelled" ;; esac
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/wormholed-bootstrap.XXXXXX")
chmod 700 "$TMP"
mkdir -p "$TMP/data/authorized_keys" "$TMP/home" "$TMP/cargo/bin"
chmod 700 "$TMP/data" "$TMP/data/authorized_keys"

if [ -n "${WORMHOLE_BOOTSTRAP_TEST_BINARY:-}" ]; then
    [ -n "$ROOT" ] || fail "test binary override requires WORMHOLE_BOOTSTRAP_ROOT"
    cp "$WORMHOLE_BOOTSTRAP_TEST_BINARY" "$TMP/wormholed"
else
    curl --proto '=https' --tlsv1.2 -LsSf "$INSTALLER_URL" -o "$TMP/installer.sh"
    HOME="$TMP/home" CARGO_HOME="$TMP/cargo" sh "$TMP/installer.sh"
    [ -x "$TMP/cargo/bin/wormholed" ] || fail "release installer did not produce wormholed"
    cp "$TMP/cargo/bin/wormholed" "$TMP/wormholed"
fi
chmod 755 "$TMP/wormholed"

write_config() {
    output=$1
    data_dir=$2
    credential_base=$3
    {
        say '[server]'
        printf 'domains = ['
        separator=
        for domain in $DOMAINS; do
            printf '%s"%s"' "$separator" "$domain"
            separator=', '
        done
        say ']'
        say 'public_https_port = 443'
        say 'quic_addr = "0.0.0.0:443"'
        say 'https_addr = "0.0.0.0:443"'
        say 'http_addr = "0.0.0.0:80"'
        say "data_dir = \"$data_dir\""
        say
        say '[tls]'
        say "mode = \"$TLS_MODE\""
        case "$TLS_MODE" in
            acme-dns01)
                say
                say '[tls.acme]'
                say "contact = \"mailto:$EMAIL\""
                say 'directory = "https://acme-v02.api.letsencrypt.org/directory"'
                say 'dns_provider = "cloudflare"'
                say "cloudflare_token_file = \"$credential_base/cloudflare_token\""
                ;;
            static)
                for domain in $DOMAINS; do
                    say
                    say '[[tls.static.certs]]'
                    say "domain = \"$domain\""
                    say "cert = \"$credential_base/tls_cert\""
                    say "key = \"$credential_base/tls_key\""
                done
                ;;
        esac
        say
        say '[tcp.port_range]'
        say 'start = 10000'
        say 'end = 20000'
        say
        say '[limits]'
        say 'max_binds_per_key = 32'
        say 'max_sessions_per_key = 8'
        say 'max_streams_per_session = 1024'
        say 'handshake_per_ip_per_min = 30'
        say 'buffer_max_bytes_per_key = "100MiB"'
        say 'buffer_max_bytes_total = "1GiB"'
        say
        say '[auth]'
        say "authorized_keys = \"$data_dir/authorized_keys\""
    } >"$output"
    chmod 600 "$output"
}

case "$TLS_MODE" in
    acme-dns01) cp "$TOKEN_FILE" "$TMP/cloudflare_token" ;;
    static)
        cp "$CERT_FILE" "$TMP/tls_cert"
        cp "$KEY_FILE" "$TMP/tls_key"
        ;;
esac
chmod 600 "$TMP"/cloudflare_token "$TMP"/tls_key 2>/dev/null || true
chmod 644 "$TMP"/tls_cert 2>/dev/null || true
write_config "$TMP/check.toml" "$TMP/data" "$TMP"
"$TMP/wormholed" serve --check --config "$TMP/check.toml" >/dev/null

write_unit() {
    {
        say '[Unit]'
        say 'Description=Wormhole relay server'
        say 'Documentation=https://github.com/nikuscs/wormhole'
        say 'After=network-online.target'
        say 'Wants=network-online.target'
        say
        say '[Service]'
        say 'Type=simple'
        say 'DynamicUser=yes'
        say 'StateDirectory=wormhole'
        say 'StateDirectoryMode=0700'
        say 'RuntimeDirectory=wormhole'
        say 'RuntimeDirectoryMode=0700'
        say 'ExecStart=/usr/local/bin/wormholed serve --config /etc/wormhole/wormholed.toml'
        [ "$TLS_MODE" = acme-dns01 ] && say 'LoadCredential=cloudflare_token:/etc/wormhole/credentials/cloudflare_token'
        if [ "$TLS_MODE" = static ]; then
            say 'LoadCredential=tls_cert:/etc/wormhole/credentials/tls_cert'
            say 'LoadCredential=tls_key:/etc/wormhole/credentials/tls_key'
        fi
        say 'Restart=on-failure'
        say 'RestartSec=2s'
        say 'AmbientCapabilities=CAP_NET_BIND_SERVICE'
        say 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE'
        say 'NoNewPrivileges=yes'
        say 'PrivateDevices=yes'
        say 'PrivateTmp=yes'
        say 'ProtectClock=yes'
        say 'ProtectControlGroups=yes'
        say 'ProtectHome=yes'
        say 'ProtectHostname=yes'
        say 'ProtectKernelLogs=yes'
        say 'ProtectKernelModules=yes'
        say 'ProtectKernelTunables=yes'
        say 'ProtectSystem=strict'
        say 'ReadWritePaths=/var/lib/wormhole'
        say 'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX'
        say 'RestrictNamespaces=yes'
        say 'RestrictRealtime=yes'
        say 'SystemCallArchitectures=native'
        say 'UMask=0077'
        say 'TimeoutStopSec=35s'
        say
        say '[Install]'
        say 'WantedBy=multi-user.target'
    } >"$TMP/wormholed.service"
}
write_unit

if [ "$CONFIGURE_UFW" -eq 1 ]; then
    if ! command -v ufw >/dev/null 2>&1; then
        command -v apt-get >/dev/null 2>&1 || fail "apt-get is required to install UFW"
        DEBIAN_FRONTEND=noninteractive apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y ufw
    fi
    ssh_port=$(printf '%s\n' "${SSH_CONNECTION:-}" | awk '{print $4}')
    case "$ssh_port" in
        ''|*[!0-9]*)
            if ufw app info OpenSSH >/dev/null 2>&1; then
                ufw allow OpenSSH
            else
                ufw allow 22/tcp
            fi
            ;;
        *) ufw allow "$ssh_port/tcp" ;;
    esac
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 443/udp
    ufw allow 10000:20000/tcp
    ufw --force enable
fi

install -d -m 0755 "$CONFIG_DIR" "$(dirname "$UNIT_PATH")" "$(dirname "$BINARY_PATH")"
install -d -m 0700 "$CREDENTIAL_DIR" "$DATA_DIR" "$DATA_DIR/authorized_keys"
if [ "$FORCE" -eq 1 ] && { [ "$HAD_CONFIG" -eq 1 ] || [ "$HAD_UNIT" -eq 1 ] || [ "$HAD_BINARY" -eq 1 ]; }; then
    timestamp=$(date -u +%Y%m%dT%H%M%SZ)
    BACKUP_PATH="$BACKUP_DIR/$timestamp"
    install -d -m 0700 "$BACKUP_PATH"
    [ "$HAD_CONFIG" -eq 1 ] && cp -p "$CONFIG_PATH" "$BACKUP_PATH/wormholed.toml"
    [ "$HAD_UNIT" -eq 1 ] && cp -p "$UNIT_PATH" "$BACKUP_PATH/wormholed.service"
    [ "$HAD_BINARY" -eq 1 ] && cp -p "$BINARY_PATH" "$BACKUP_PATH/wormholed"
    [ -d "$CREDENTIAL_DIR" ] && cp -Rp "$CREDENTIAL_DIR" "$BACKUP_PATH/credentials"
fi

install -m 0755 "$TMP/wormholed" "$BINARY_PATH"
case "$TLS_MODE" in
    acme-dns01) install -m 0600 "$TMP/cloudflare_token" "$CREDENTIAL_DIR/cloudflare_token" ;;
    static)
        install -m 0644 "$TMP/tls_cert" "$CREDENTIAL_DIR/tls_cert"
        install -m 0600 "$TMP/tls_key" "$CREDENTIAL_DIR/tls_key"
        ;;
esac
write_config "$TMP/final.toml" "/var/lib/wormhole" "/run/credentials/wormholed.service"
install -m 0644 "$TMP/final.toml" "$CONFIG_PATH"
install -m 0644 "$TMP/wormholed.service" "$UNIT_PATH"

rollback() {
    say "service startup failed; restoring the previous installation" >&2
    if [ -n "$BACKUP_PATH" ]; then
        if [ "$HAD_CONFIG" -eq 1 ]; then
            cp -p "$BACKUP_PATH/wormholed.toml" "$CONFIG_PATH"
        else
            rm -f "$CONFIG_PATH"
        fi
        if [ "$HAD_UNIT" -eq 1 ]; then
            cp -p "$BACKUP_PATH/wormholed.service" "$UNIT_PATH"
        else
            rm -f "$UNIT_PATH"
        fi
        if [ "$HAD_BINARY" -eq 1 ]; then
            cp -p "$BACKUP_PATH/wormholed" "$BINARY_PATH"
        else
            rm -f "$BINARY_PATH"
        fi
        rm -rf "$CREDENTIAL_DIR"
        [ -d "$BACKUP_PATH/credentials" ] && cp -Rp "$BACKUP_PATH/credentials" "$CREDENTIAL_DIR"
    else
        rm -f "$CONFIG_PATH" "$UNIT_PATH" "$BINARY_PATH"
        rm -rf "$CREDENTIAL_DIR"
    fi
    systemctl daemon-reload || true
    if [ "$HAD_UNIT" -eq 1 ]; then
        systemctl restart wormholed || true
    else
        systemctl disable --now wormholed || true
    fi
    exit 1
}

systemctl daemon-reload || rollback
systemctl enable wormholed >/dev/null || rollback
systemctl restart wormholed || rollback
systemctl is-active --quiet wormholed || rollback
"$BINARY_PATH" status --json --require-online --config "$CONFIG_PATH" >/dev/null || rollback

if [ -n "$CLIENT_KEY_FILE" ]; then
    "$BINARY_PATH" key authorize "$CLIENT_KEY_FILE" --name "$CLIENT_NAME" --config "$CONFIG_PATH" \
        || fail "relay is running, but client-key authorization failed"
else
    say "Initial client enrollment invite (shown once, valid for 10 minutes):"
    "$BINARY_PATH" invite create --name initial-device --config "$CONFIG_PATH" \
        || fail "relay is running, but initial invite creation failed"
fi

say "Wormhole relay is running."
say "Check: sudo systemctl status wormholed --no-pager"
say "Domains: $(printf '%s' "$DOMAINS" | tr '\n' ' ')"
if [ -z "$CLIENT_KEY_FILE" ]; then
    say "Next (client): wormhole remote add personal $(printf '%s\n' "$DOMAINS" | sed -n '1p'):443 --invite <token>"
    say "Break glass: sudo wormholed key authorize /path/to/client.pub --name laptop --config /etc/wormhole/wormholed.toml"
fi
if [ -n "$BACKUP_PATH" ]; then
    say "Backup: ${BACKUP_PATH#"$ROOT"}"
fi
