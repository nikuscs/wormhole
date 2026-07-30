# Server deployment

Commands below assume Ubuntu, SSH access, a Wormhole source checkout, and the default relay
ports. Replace the domain, client-key path, and TCP range before running.

## Bootstrap from GitHub

The release bootstrap supports Debian/Ubuntu with systemd. It installs the latest signed/checksummed
cargo-dist binary, validates configuration before replacing files, installs the hardened service,
starts it, and verifies online status. Interactive mode prompts through `/dev/tty`. Unless a
client public key is supplied, the completed install prints a single-use, 10-minute enrollment
invite exactly once:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nikuscs/wormhole/releases/latest/download/wormholed-bootstrap.sh \
  | sudo sh
```

A production Cloudflare DNS-01 setup can run without prompts:

```sh
sudo install -m 0600 /path/to/cloudflare.token /root/cloudflare.token
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nikuscs/wormhole/releases/latest/download/wormholed-bootstrap.sh \
  | sudo sh -s -- --domain tun.example.com --email ops@example.com \
      --cloudflare-token-file /root/cloudflare.token \
      --client-key-file /path/to/client.pub --client-name laptop -y
```

Static wildcard certificates are also supported:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nikuscs/wormhole/releases/latest/download/wormholed-bootstrap.sh \
  | sudo sh -s -- --domain tun.example.com \
      --static-cert-file /root/fullchain.pem --static-key-file /root/privkey.pem -y
```

Safety behavior:

- `-y` only accepts the printed plan; it does not imply `--force`, `--configure-ufw`, or
  `--skip-dns-check`;
- existing config, unit, or binary files are never replaced without `--force`; replacements are
  backed up under `/etc/wormhole/backups/` and restored if startup fails;
- raw tokens and private keys are never accepted as argument values—only regular, non-symlinked,
  non-group/world-readable files are accepted;
- credentials are copied with owner-only permissions and exposed to the dynamic service through
  systemd `LoadCredential`;
- apex and wildcard DNS must resolve before changes are applied unless `--skip-dns-check` is
  explicitly provided;
- UFW is untouched unless `--configure-ufw` is explicit; the active SSH server port is allowed
  before UFW is enabled;
- `--self-signed` is explicit and intended only for development/private testing.

Run `wormholed-bootstrap.sh --help` for the complete flag list. Provider firewalls/security groups
and DNS records remain external infrastructure and cannot be safely inferred by the script.

## Firewall

Allow SSH before enabling UFW so the current server is not locked out:

```sh
sudo apt-get update && sudo apt-get install -y ufw curl ca-certificates && sudo ufw allow OpenSSH && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw allow 443/udp && sudo ufw allow 10000:20000/tcp && sudo ufw --force enable && sudo ufw status verbose
```

The VPS provider firewall/security group must allow the same ports. Omit
`10000:20000/tcp` when raw TCP forwarding is not needed.

## DNS

Create both records at the DNS provider:

```text
tun.example.com    A/AAAA    VPS_ADDRESS
*.tun.example.com  A/AAAA    VPS_ADDRESS
```

Check them from any machine:

```sh
dig +short tun.example.com && dig +short test.tun.example.com
```

## Install and initialize

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/nikuscs/wormhole/releases/latest/download/wormholed-installer.sh | sh && sudo install -d -m 0755 /etc/wormhole && sudo wormholed init --config /etc/wormhole/wormholed.toml && sudo editor /etc/wormhole/wormholed.toml && sudo chmod 0644 /etc/wormhole/wormholed.toml
```

Set the domain, listener addresses, state paths, TLS mode, and TCP range in
`/etc/wormhole/wormholed.toml`:

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

## TLS

Choose one certificate mode:

- `acme-dns01`: automatic wildcard certificates through a narrowly scoped Cloudflare DNS token;
- `static`: certificate and key files covering the apex and wildcard domains;
- `self-signed`: local/private testing only; clients must explicitly trust it.

For systemd, provide ACME tokens or private keys with `LoadCredential`; never place secrets in
arguments, logs, or the administration API.

## Start with systemd

From a Wormhole source checkout:

```sh
sudo install -m 0644 deploy/wormholed.service /etc/systemd/system/wormholed.service && sudo systemctl daemon-reload && sudo systemctl enable --now wormholed && sudo systemctl status wormholed --no-pager
```

## Enroll clients

Create a default single-use invite, copy its one-time token to the client, and redeem it while adding
the relay:

```sh
sudo wormholed invite create --name laptop --config /etc/wormhole/wormholed.toml
wormhole remote add myvps tun.example.com:443 --invite <token>
```

Each client generates and retains its own private key. The relay stores only the invite digest and
atomically records successful uses after the client proves private-key possession. Create a
credential for multiple machines with `--reusable`, or constrain one explicitly with `--ttl` and
`--uses`:

```sh
sudo wormholed invite create --name personal-devices --reusable --config /etc/wormhole/wormholed.toml
sudo wormholed invite ls --config /etc/wormhole/wormholed.toml
sudo wormholed invite revoke <invite-id> --config /etc/wormhole/wormholed.toml
```

Reusable invites remain valid until revoked. The relay's per-IP handshake limiter also bounds
invalid enrollment attempts. As a break-glass alternative, copy a client's public key to the server
and authorize it manually:

```sh
sudo wormholed key authorize /path/to/client.pub --name laptop --config /etc/wormhole/wormholed.toml
```

## Verify listeners and logs

```sh
sudo ss -lntup | grep -E ':(80|443|10000|20000)\\b' && sudo journalctl -u wormholed -n 100 --no-pager
```

## Container

```sh
docker build -f deploy/Dockerfile -t wormholed . && docker run --rm -v "$PWD/wormholed.toml:/etc/wormhole/wormholed.toml:ro" -v wormhole-state:/var/lib/wormhole -p 80:80/tcp -p 443:443/tcp -p 443:443/udp -p 10000-20000:10000-20000/tcp wormholed
```

For local self-signed testing:

```sh
docker compose -f deploy/docker-compose.yml up --build
```

Use `deploy/wormholed.container.toml` only for local testing. Production containers must use the
real domain, production TLS, and the same configured TCP range as the published ports.
