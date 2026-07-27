# Stage 04 — Client core (`wormhole-core`)

**Goal:** the client engine as a library: driver trait + registry (Laravel-style), named remotes
(one client ↔ many wormhole servers), the tunnel manager that binds one local service to N
endpoints across N drivers concurrently, reconnection, interface aliases with auto-discovery,
and port utilities (free-port allocation + child listening-port detection). No CLI, no daemon —
stage 05 wraps this.

**Depends on:** 02. **Parallel with:** 03. **Blocks:** 05, 06.

## Core vocabulary (types used everywhere; put in `model.rs`)

```rust
/// A local thing to expose. Target resolves through interface aliases.
pub struct Service { pub name: String, pub target: Target, pub proto: ServiceProto /* Http|Tcp */ }
pub enum Target { Port(u16), HostPort(String, u16), Iface { alias: String, port: u16 } }

/// One desired public exposure of a service via one driver instance.
pub struct EndpointSpec {
    pub proto: ServiceProto,         // derived from Service; API rejects a mismatched client value
    pub driver: String,              // registry key: "wormhole" | "tailscale" | "cloudflare"
    pub qualifier: Option<String>,   // driver mode, e.g. tailscale:"funnel", cloudflare:"named"
    pub remote: Option<String>,      // wormhole driver: which remote; None = default remote
    pub host: Option<String>,        // subdomain LABEL (never a full domain — server owns domains)
    pub domain: Option<String>,      // pick among the server's offered domains; None = default
    pub public_port: Option<u16>,    // provider public port (not the local target port)
    pub persist: Persistence,        // proto::Persistence
    pub buffer: Option<BufferPolicy>,
    pub auth: Option<EdgeAuth>,      // relay-edge basic/bearer/share-link policy (stage 07)
    pub retry: Option<RetryPolicy>,  // local delivery retries (stage 07 W7; http-only)
    pub inspect: bool,               // capture requests for this endpoint (stage 07)
}

/// A live exposure returned by a driver.
pub struct ActiveEndpoint {
    pub id: Uuid,
    pub service: String,
    pub driver: String,
    pub urls: Vec<String>,
    pub status: EndpointStatus,      // Online | Reconnecting | Offline | Error(String)
    pub since: jiff::Timestamp,
}
```

## Driver architecture (the Laravel-drivers idea, locked)

```rust
#[async_trait::async_trait]
pub trait TunnelDriver: Send + Sync {
    fn name(&self) -> &'static str;
    /// Cheap capability probe used by `doctor` and pre-flight (binary present? logged in?).
    async fn check(&self) -> DriverHealth;
    /// Open one endpoint. Runs until `stop` fires or fatal error. Reports via `events`.
    /// MUST establish the URL and send Ready before accepting traffic.
    async fn run(
        &self,
        spec: EndpointSpec,
        target: ResolvedTarget,                       // SocketAddr after alias resolution
        events: mpsc::Sender<DriverEvent>,            // Ready/StatusChanged/Log/Closed/Captured
        // DriverEvent::Captured(Box<CapturedRequest>) carries stage-07 inspection records
        // across the core→daemon crate boundary; CapturedRequest lives in core::model.
        stop: CancellationToken,                      // tokio_util::sync
    ) -> Result<(), DriverError>;
}

pub struct DriverRegistry { map: HashMap<&'static str, Arc<dyn TunnelDriver>> }
// built once from config: registry.register(WormholeDriver::new(remotes)); ...
```

Rules:
- `DriverEvent::Ready { urls, bind_id, reservation }` carries the wormhole server identifiers;
  provider drivers set the last two fields to `None`. The daemon, not core, persists them.
- `run` owns the endpoint's whole lifecycle **including reconnection** (backoff 250ms → 30s,
  full jitter, forever for `Persistent`, 5 attempts then `Closed` for `Temporary`).
- Drivers never print; they emit `DriverEvent::Log(level, msg)`.
- The tunnel manager treats every driver identically — adding a provider later is one file.

## Module layout

```
crates/wormhole-core/src/
  lib.rs        model.rs      error.rs
  config.rs     # ClientConfig: remotes, aliases, defaults; load/merge global + project
  driver.rs     # trait, registry, DriverEvent, DriverHealth
  manager.rs    # TunnelManager: services -> endpoint tasks, status book-keeping
  remotes.rs    # Remote { name, addr, server_name, trusted_ca? }, identity resolution
  wormhole_driver.rs  # OUR driver: QUIC to a remote, proto handshake, stream accept loop
  ifaces.rs     # alias discovery + resolution
  ports.rs      # free-port alloc, wait_for_listener, child port detection
  keys_store.rs # identity file management on top of proto::keys
```

## Tasks

- [ ] **C1 — Config** (`config.rs`). Global `~/.config/wormhole/config.toml`
  (path via `directories`, overridable `WORMHOLE_CONFIG`):

  ```toml
  default_remote = "myvps"

  [remotes.myvps]
  addr = "tun.example.com:443"           # QUIC/udp
  server_name = "tun.example.com"        # TLS + challenge binding name
  # trusted_ca = "/path/self-signed.pem"   # dev/e2e: trust anchors = exactly this CA/cert
                                           # (it IS a CA trust root, not leaf pinning — named honestly)

  [remotes.work]
  addr = "wh.corp.example:443"
  identity = "~/.config/wormhole/keys/work.key"   # per-remote override

  [aliases]                               # user-defined; merged over auto-discovered
  db-box = "192.168.1.40"

  [defaults]
  drivers = ["wormhole"]                  # used when no endpoint specified
  inspect = true
  ```

  Loader merges: defaults ← global file ← project `wormhole.toml` (stage 05 defines it) ←
  explicit args. Unknown keys warn, don't fail. Validation: unit tests for merge precedence +
  a full-file insta snapshot round-trip.

- [ ] **C2 — Identity store** (`keys_store.rs`). Default identity
  `~/.config/wormhole/keys/identity.key` — auto-generate on first use (log fingerprint once),
  0600 enforced by P3. `resolve_identity(remote) -> Identity` honoring per-remote override.
  Validation: unit test in tempdir HOME.

- [ ] **C3 — Interface aliases** (`ifaces.rs`). Auto-discovery via `netdev`/`if-addrs`, refreshed
  on demand (no background poll):
  - `localhost` → 127.0.0.1 (always)
  - `lan` → IPv4 of the default-route interface (netdev `get_default_interface`)
  - `tailscale` → first interface with an address in `100.64.0.0/10` (CGNAT range tailscale uses)
  - `docker` → interface named `docker0`/`bridge100` when present
  - every real interface by name (`en0`, `utun3`, …)
  API: `discover() -> Vec<IfaceAlias { alias, iface, ip }>`, `resolve(alias_or_host) -> IpAddr`
  (order: user alias → builtin alias → interface name → literal IP/hostname).
  Validation: unit tests with injected fake interface list (make discovery take a
  `fn() -> Vec<Interface>` for testability); `resolve("localhost")` = 127.0.0.1.

- [ ] **C4 — Port utilities** (`ports.rs`).
  - `alloc_port(range: 4000..=4999) -> u16` — bind `127.0.0.1:0`-style probing inside range,
    return first free (bind and drop; races are fine, caller retries once).
  - `wait_for_listener(addr, timeout)` — poll `TcpStream::connect` every 150ms.
  - `detect_child_port(pid, since) -> Option<u16>` — two crates, split responsibilities:
    `sysinfo` builds the descendant pid set (walk the process table's parent-pid links from
    `pid` — `listeners` has no process graph), then `listeners` lists listening sockets and we
    match against that set. Used by `wormhole run` fallback when the tool ignores `PORT`
    (portless technique: inject first, poll as fallback).
  Validation: unit test — spawn a `TcpListener` on an alloc'd port in-process, detect it by pid.

- [ ] **C5 — Wormhole driver** (`wormhole_driver.rs`) — the reference driver, over our protocol:
  - quinn client endpoint: rustls with webpki roots; `trusted_ca` remote option installs a
    single-CA root store instead (never a "skip verify" switch). TLS server name and the
    handshake's expected `server_name` are the same configured value (P4 enforces the match).
  - Connect → handshake → `Bind` → receive `Bound` → install bind→target routing locally →
    send `BindReady` → receive `BindActive` → emit
    `DriverEvent::Ready { urls, bind_id, reservation }`. The CLI daemon persists the
    identifiers keyed by (remote, project id, service, endpoint); reconnects/restarts pass the
    reservation back. Core never writes daemon storage.
  - HTTP stream: read `StreamHeader::Http`, remove hop-by-hop headers, deliver through a Hyper
    client to `ResolvedTarget`, then write `HttpResponseHead` and stream the body back. This
    single HTTP-aware path is also where retry, capture, and buffered-delivery behavior attach
    in stage 07. Preserve upgrades by switching to raw copy after a 101.
  - TCP stream: read `StreamHeader::Tcp`, connect to `ResolvedTarget`, raw
    `copy_bidirectional`. Concurrency-cap both protocols with the negotiated semaphore.
  - Keepalive: `Ping` every 20s; missed 2 pongs → tear down → reconnect path (rebind same spec;
    persistent binds reclaim their hostname per S5).
  - Multi-remote via a shared-connection actor. Spec it precisely (this is the subtlest piece):
    `RemoteConn` = one task owning the QUIC connection + control stream per remote, in a
    `DashMap<RemoteName, Arc<RemoteConn>>`. API: command mpsc (`Bind{spec, reservation, reply}`,
    `Unbind{bind, forget}`, `Shutdown`) + it maintains `binds: HashMap<Uuid, EndpointHandle>`
    (target addr, capture sink, semaphore). Incoming server streams match the header variant,
    extract its bind id, and dispatch through that map; unknown id → reset. Control frames demux by
    request id (`Bound`/`BindError` to the pending reply, `Event` broadcast). Refcount: last
    endpoint's `Unbind` closes the connection after 30s linger; per-endpoint
    `CancellationToken` tears down only that bind's streams.
    Unit-test the actor against the in-process fake QUIC server: two concurrent binds on one
    connection, interleaved streams route to the right targets, one endpoint cancelled leaves
    the other flowing.
  Validation: integration test against a real `wormholed` in self-signed mode (dev-dep on
  nothing: spawn the binary via `assert_cmd`-style path from `CARGO_BIN_EXE_wormholed`? That
  env var only exists in `wormholed`'s own tests — instead this test lives in
  `crates/wormhole-e2e` (stage 08). Here: unit-test the pieces with a fake in-process QUIC
  server built from proto + quinn in `#[cfg(test)]`.)

- [ ] **C6 — Tunnel manager** (`manager.rs`).
  - `TunnelManager::new(registry, config)`; API:
    `expose(service, Vec<EndpointSpec>) -> Vec<EndpointId>` (spawns one driver task per spec —
    this is the multi-URL-at-once feature: specs with different drivers run concurrently;
    manager overwrites/validates each internal `spec.proto` from `service.proto`),
    `close(endpoint_or_service)`, `list() -> Vec<ActiveEndpoint>`, `subscribe() ->
    broadcast::Receiver<StatusChange>`, `shutdown()` (cancel all, 10s drain).
  - Consumes `DriverEvent`s, maintains the `ActiveEndpoint` book, restarts nothing itself
    (drivers own reconnect) but records `Error` terminal states.
  - Capability validation is fail-fast: `buffer`, `auth`, `retry`, and `inspect` are
    wormhole-HTTP-only unless a provider explicitly advertises support; never silently ignore
    an endpoint option.
  Validation: unit tests with a `MockDriver` (registered as `"mock"`): expose with 3 specs →
  3 Ready urls listed; close one endpoint → others unaffected; driver error surfaces in list.

- [ ] **C7 — Doctor data.** `core::doctor() -> Vec<DoctorCheck>`: config parse, identity exists +
  perms, each remote QUIC/TLS connection reachable (3s timeout; application auth not required),
  each registered driver's `check()`. Pure data — CLI renders it in stage 05.
  Validation: unit test with mock driver healths.

## Acceptance gate

```bash
cargo test -p wormhole-core --locked \
&& cargo clippy -p wormhole-core --all-targets --locked -- -D warnings
```

Commit `feat(core): drivers, remotes, tunnel manager`.
