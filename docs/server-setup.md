# Relay server setup

## DNS and firewall

For a relay domain such as `tun.example.com`, create `A` and/or `AAAA` records for both the apex and wildcard:

```text
tun.example.com    A     203.0.113.10
*.tun.example.com  A     203.0.113.10
```

Allow inbound `80/tcp`, `443/tcp`, and `443/udp` (QUIC), plus the configured TCP-forward range (default `10000-20000/tcp`). All listener addresses and the forward range are configurable.

## Install

Install the `wormholed` binary at `/usr/local/bin/wormholed`, then initialize a configuration:

```sh
sudo install -d -m 0755 /etc/wormhole
sudo wormholed init --config /etc/wormhole/wormholed.toml
sudo editor /etc/wormhole/wormholed.toml
sudo chmod 0644 /etc/wormhole/wormholed.toml
```

Set `server.domains`, listener addresses, `server.data_dir = "/var/lib/wormhole"`, and `auth.authorized_keys = "/var/lib/wormhole/authorized_keys"`. Do not leave the generated state paths under root-owned `/etc/wormhole`. The generated self-signed mode is for local development only.

Install and start the hardened systemd unit:

```sh
sudo install -m 0644 deploy/wormholed.service /etc/systemd/system/wormholed.service
sudo systemctl daemon-reload
sudo systemctl enable --now wormholed
sudo wormholed key authorize /path/to/id_ed25519.pub \
  --name first-client \
  --config /etc/wormhole/wormholed.toml
sudo wormholed status --json --config /etc/wormhole/wormholed.toml
```

Starting the service first lets its dynamic user create the database; the root CLI then authorizes the first client through the administration socket instead of creating root-owned state files. The unit uses `DynamicUser=yes`, so its root-owned configuration must be readable but must contain only settings and paths, never secret values. It stores durable state under `/var/lib/wormhole`. The local administration API is available only through `/var/lib/wormhole/admin.sock` with mode `0600`.

## Certificates

Choose one TLS mode in `wormholed.toml`:

- **Static wildcard certificate:** configure one PEM certificate/key pair per relay domain. Each certificate must cover the apex and `*.domain`. `SIGHUP` atomically reloads valid replacement files.
- **Built-in ACME DNS-01:** configure the ACME directory and Cloudflare credentials. Grant the token only DNS-record edit/read access for the required zones. Wormhole creates and removes `_acme-challenge` TXT records and renews cached certificates. For systemd, pass the token with `LoadCredential=cloudflare_token:/secure/source` in a service drop-in and set `cloudflare_token_file = "/run/credentials/wormholed.service/cloudflare_token"`; use the same credential pattern for static private keys.
- **Self-signed:** development and private testing only; clients must explicitly trust the generated certificate.

Never place Cloudflare token contents or private keys in command arguments, logs, or the administration API.

## Container

Build the statically linked distroless image:

```sh
docker build -f deploy/Dockerfile -t wormholed .
```

Mount configuration read-only and state read-write, and publish TCP and UDP separately:

```sh
docker run --rm \
  -v "$PWD/wormholed.toml:/etc/wormhole/wormholed.toml:ro" \
  -v wormhole-state:/var/lib/wormhole \
  -p 80:80/tcp -p 443:443/tcp -p 443:443/udp \
  -p 10000-20000:10000-20000/tcp \
  wormholed
```

Adjust `server.data_dir` and listener addresses for the container (`0.0.0.0`). Restrict the published forward range to the configured range.
