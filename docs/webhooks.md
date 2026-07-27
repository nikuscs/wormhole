# Persistent forwards, webhooks, inspection, and replay

Persistent Wormhole endpoints retain their hostname or TCP port while the client is offline and
are restored by the daemon. HTTP requests to an offline persistent endpoint normally receive
`503 Tunnel Offline`.

## Durable webhook buffering

Buffering is opt-in for persistent HTTP endpoints:

```toml
[[service]]
name = "stripe"
target = 3000

[[service.endpoint]]
driver = "wormhole"
persist = true
buffer = { max_requests = 100, max_body = "1MiB", ttl = "24h" }
retry = { attempts = 5, backoff = "500ms" }
inspect = true
```

An offline request is fully read within 30 seconds and committed durably before the relay returns
`202 Accepted` with `Wormhole-Buffered: true`. Delivery is at least once, strictly ordered per
endpoint, and begins only after the restored client reports its local route ready. The original
caller never receives the local application's later response. Quota exhaustion returns 503 and an
oversized body returns 413; accepted rows are never silently discarded.

Retries of non-idempotent webhooks can duplicate side effects. Enable `5xx` retries only when the
application is idempotent (for example, when it deduplicates Stripe event IDs). Transport failure
before acknowledgement may also redeliver a request.

Failed deliveries are quarantined on the relay. Operators can list, retry, or remove exact failed
rows through `wormholed webhooks failed ...`; failed rows continue to count against byte quotas.

## Inspection and replay

Inspection is memory-only and applies only to `wormhole` driver HTTP endpoints. Tailscale and
Cloudflare send traffic directly to the application and cannot be inspected. The daemon retains
20 eligible exchanges per endpoint within a 32 MiB global budget, ignores static assets by
default, and redacts authorization, cookie, set-cookie, and x-api-key values at capture time.

```sh
wormhole requests --follow --json
wormhole replay 019...
```

Bodies retained completely can be replayed to the endpoint's current local target. Truncated
bodies are visible for debugging but cannot be replayed.

## Edge authentication and share links

```sh
wormhole http 3000 --persist --auth basic:agent:secret
wormhole http 3000 --persist --auth bearer:secret
wormhole http 3000 --persist --auth links --name preview
wormhole share preview --expires 24h --path /
```

Basic, bearer, and signed-link checks happen at the relay before proxying or buffering. Signed
links exchange the expiring token for a Secure, HttpOnly, SameSite=Lax host-wide cookie and
redirect without the token. Webhook providers that cannot authenticate at the HTTP layer should
omit edge auth and continue verifying provider signatures in the application.
