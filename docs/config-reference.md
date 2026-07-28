# Configuration reference

Wormhole reads three TOML formats: the client config, a worktree project file, and the relay
config. Paths are UTF-8. Durations accept units such as `ms`, `s`, `m`, and `h`; byte sizes accept
`B`, `KiB`, `MiB`, and `GiB` where noted.

## Client config

The client config is `~/.config/wormhole/config.toml`, or `WORMHOLE_CONFIG` when set. A project
file and command-line overrides are layered over it. Unknown keys are retained with a warning.

```toml
default_remote = "production"

[remotes.production]
transport = "auto"
addr = "tun.example.com:443"
https_addr = "tun.example.com:443"
server_name = "tun.example.com"
trusted_ca = "/etc/wormhole/development-ca.pem"
identity = "/home/alice/.config/wormhole/identities/production.key"

[aliases]
loopback = "127.0.0.1"

[defaults]
drivers = ["wormhole"]
inspect = false
retry = { attempts = 3, backoff = "250ms", max_backoff = "5s", on = ["connect-error", "5xx"], max_body = "1MiB", total_deadline = "30s" }
```

- `default_remote`: named remote used when a command omits `--remote`; default: unset.
- `remotes.<name>.transport`: `auto`, `quic`, or `ws`; default: `auto`. Automatic mode tries QUIC
  before WebSocket fallback.
- `remotes.<name>.addr`: required QUIC UDP authority.
- `remotes.<name>.https_addr`: WebSocket HTTPS authority; default: `<server_name>:443`.
- `remotes.<name>.server_name`: required TLS SNI and handshake server name.
- `remotes.<name>.trusted_ca`: optional development-only CA certificate.
- `remotes.<name>.identity`: optional identity key override; default: the managed identity.
- `aliases.<name>`: interface alias used in local targets; default map: empty.
- `defaults.drivers`: endpoint drivers; default: `["wormhole"]`.
- `defaults.inspect`: capture request metadata by default; default: `false`.
- `defaults.retry`: optional local HTTP retry policy. `attempts` and `backoff` are required when
  present. `max_backoff` defaults to `30s`, `on` defaults to `connect-error`, `max_body` defaults
  to `1MiB`, and `total_deadline` defaults to `60s`.

## Worktree project

A `wormhole.toml` in the worktree root declares services. `name` is optional. Each service requires
`name`, `target`, and `proto` (`http` or `tcp`). Endpoints default to temporary, uninspected
forwards.

```toml
name = "payments"

[[service]]
name = "api"
target = "127.0.0.1:3000"
proto = "http"

[[service.endpoint]]
driver = "wormhole"
remote = "production"
host = "payments-api"
domain = "tun.example.com"
public_port = 10443
persist = true
inspect = true
capture_assets = false
capture_body_max = "1MiB"
buffer = { max_requests = 100, max_body = "1MiB", ttl = "24h" }
auth = { basic = "user:password", links = false }
retry = { attempts = 5, backoff = "500ms", max_backoff = "5s", on = ["connect-error", "5xx"], max_body = "1MiB", total_deadline = "30s" }
```

- `service[].target`: `PORT`, `HOST:PORT`, or `ALIAS:PORT`.
- `service[].endpoint[].driver`: `wormhole`, `tailscale`, `cloudflare`, or a qualified driver such
  as `cloudflare:quick`.
- `remote`, `host`, `domain`, and `public_port`: optional driver-specific endpoint selection.
- `persist`: retain and reclaim a relay reservation; default: `false`.
- `buffer`: durable offline HTTP queue. All three keys are required when present.
- `auth.basic` / `auth.bearer`: edge credential policy; use one. `links` enables signed links and
  defaults to `false`.
- `retry`: local HTTP delivery retry policy; defaults match the client retry policy when optional
  keys are omitted.
- `inspect`: request capture; default: the client `defaults.inspect` value.
- `capture_assets`: include static assets in capture; default: `false`.
- `capture_body_max`: largest complete captured body; default: `1MiB`.

Buffering, retries, edge authentication, and inspection apply only where documented in
[webhooks](webhooks.md).

## Relay config

`wormholed` reads `/etc/wormhole/wormholed.toml` unless `--config` selects another path.

```toml
[server]
domains = ["tun.example.com"]
public_https_port = 443
quic_addr = "0.0.0.0:443"
https_addr = "0.0.0.0:443"
http_addr = "0.0.0.0:80"
data_dir = "/var/lib/wormhole"

[tls]
mode = "acme-dns01"

[tls.acme]
contact = "mailto:ops@example.com"
directory = "https://acme-v02.api.letsencrypt.org/directory"
dns_provider = "cloudflare"
cloudflare_token_file = "/run/credentials/wormholed.service/cloudflare_token"

[tcp.port_range]
start = 10000
end = 20000

[limits]
max_binds_per_key = 32
max_sessions_per_key = 8
max_streams_per_session = 1024
handshake_per_ip_per_min = 30
buffer_max_bytes_per_key = "100MiB"
buffer_max_bytes_total = "1GiB"

[auth]
authorized_keys = "/var/lib/wormhole/authorized_keys"
```

- `server.domains`: required relay apex domains; the first is the default.
- `server.public_https_port`: advertised port behind NAT; default: the bound HTTPS port.
- `server.quic_addr`, `https_addr`, and `http_addr`: required UDP/TCP listeners.
- `server.data_dir`: required database, certificate cache, and admin-socket directory.
- `tls.mode`: `self-signed`, `static`, or `acme-dns01`; required.
- `tls.static.certs[]`: for static mode, each entry requires `domain`, `cert`, and `key` paths.
- `tls.acme`: for ACME mode, requires `contact`, `directory`, `dns_provider = "cloudflare"`, and
  `cloudflare_token_file`.
- `tcp.port_range.start` / `end`: inclusive non-zero public TCP allocation range.
- `limits.*`: defaults are exactly the values shown above.
- `auth.authorized_keys`: import-only directory containing padded public-key files.

See [relay server setup](server-setup.md) for certificate, systemd, container, DNS, and firewall
instructions.
