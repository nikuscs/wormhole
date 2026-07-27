# Stage 02 — Protocol (`wormhole-proto`)

**Goal:** the complete wire contract between `wormhole` client and `wormholed`: framed control
messages, Ed25519 identity + signed-nonce handshake, stream headers for data, protocol
versioning. Pure library — no sockets, no QUIC; transport lives in stages 03/04. This makes the
protocol unit-testable and keeps client/server from drifting.

**Depends on:** 01. **Blocks:** 03, 04.

## Design (normative)

- One QUIC connection per (client, remote). ALPN `wormhole/2`. The **first** bidirectional stream
  opened by the client is the **control stream**; it stays open for the connection's life.
- Control stream framing: 4-byte big-endian length prefix + JSON body
  (`LengthDelimitedCodec::builder().max_frame_length(1024 * 1024)`). JSON chosen deliberately:
  control traffic is low-rate and debuggability beats compactness.
- Data streams are opened by the **server**. HTTP binds use one bidi stream **per request**:
  length-prefixed `StreamHeader::Http` (request head), streaming request body to the client,
  length-prefixed `HttpResponseHead` back, then streaming response body. QUIC half-close marks
  each body's end. A `101` response switches that stream to raw bidirectional upgrade bytes.
  TCP binds use one bidi stream per public TCP connection: `StreamHeader::Tcp`, then raw bytes.
  The WebSocket fallback in stage 08 preserves these same logical stream semantics.
- **Auth = handshake only.** Server sends a random 32-byte nonce; client signs a
  domain-separated transcript (below). After `Welcome`, nothing is ever authenticated
  per-request again. Replay-safe (nonce is single-use, per-connection), no secrets on the wire,
  no shared tokens on disk.
- **Server-name binding:** the client MUST refuse to sign if `Challenge.server` differs from its
  configured `server_name` for that remote (prevents a relay from proxying the challenge to
  another relay). Signed transcript is context-tagged with fixed-width little-endian lengths:
  `"wormhole-v1-challenge" || u32_le(nonce.len) || nonce || u32_le(server_utf8.len) ||
  server_utf8 || u16_le(proto_version)`. All protocol base64 is canonical RFC 4648 Standard with
  required `=` padding; decoders reject unpadded and otherwise non-canonical forms.
- Versioning: `PROTO_VERSION: u16 = 2` inside `Hello`; peers require an exact match within ALPN
  `wormhole/2`. A wire-incompatible version gets a new ALPN. Unknown JSON fields are ignored
  (`serde(default)` + no `deny_unknown_fields`) for additive changes within v1.

## Module layout

```
crates/wormhole-proto/src/
  lib.rs        # re-exports, PROTO_VERSION, ALPN const
  frames.rs     # ControlFrame, StreamHeader, all payload structs
  codec.rs      # encode/decode helpers over AsyncRead/AsyncWrite
  keys.rs       # Identity (keypair), PublicKeyRef, fingerprints, file load/store
  handshake.rs  # pure state machines: ClientHandshake, ServerHandshake
  error.rs      # ProtoError (thiserror)
```

## Tasks

- [x] **P1 — Frame types** (`frames.rs`). Serde enums, internally tagged:

  ```rust
  pub const PROTO_VERSION: u16 = 2;
  pub const ALPN: &[u8] = b"wormhole/2";

  #[derive(Debug, Clone, Serialize, Deserialize)]
  #[serde(tag = "t", rename_all = "snake_case")]
  pub enum ControlFrame {
      // handshake (exact order: hello -> challenge -> auth -> welcome | denied)
      Hello { proto: u16, client: String, pubkey: String /* base64 */ },
      Challenge { nonce: String /* base64, 32 bytes */, server: String },
      Auth { signature: String /* base64 over nonce||server||proto (le bytes) */ },
      Welcome { session: Uuid, limits: Limits, motd: Option<String> },
      Denied { reason: DenyReason },
      // binds (client -> server)
      Bind { request: Uuid, spec: BindSpec,
             reservation: Option<Uuid> /* secret reclaim token for a persistent bind */ },
      Unbind { bind: Uuid, forget: bool /* true = also drop server-side reservation */ },
      /// client installed bind→target routing and is ready for public streams
      BindReady { bind: Uuid },
      // server -> client
      Bound { request: Uuid, bind: Uuid /* stable server bind id */, urls: Vec<String>,
              persist: Persistence,
              reservation: Option<Uuid> /* server-issued, persistent binds only */,
              pending_buffered: u32, failed_buffered: u32 },
      BindError { request: Uuid, reason: String },
      /// server atomically marked the bind Online; only now may the driver emit Ready
      BindActive { bind: Uuid },
      Event { kind: EventKind, msg: String },
      /// client -> server: buffered webhook (bind, seq) was fully delivered to the local app
      /// (complete response received). Server deletes the row only on this ack.
      AckBuffered { bind: Uuid, seq: u64 },
      /// Local delivery exhausted its retry policy. Server moves the durable record to the
      /// failed queue and continues draining later sequence numbers.
      NackBuffered { bind: Uuid, seq: u64, reason: String },
      // liveness, both directions
      Ping { seq: u64 },
      Pong { seq: u64 },
  }

  #[derive(Debug, Clone, Serialize, Deserialize)]
  #[serde(tag = "kind", rename_all = "snake_case")]
  pub enum BindSpec {
      Http {
          /// requested subdomain LABEL only ("web-fix-ui"); None = server picks.
          /// Domains are server-decided: clients can never submit a full hostname.
          host: Option<String>,
          /// which server-configured domain; None = server default. Unknown -> BindError.
          domain: Option<String>,
          persist: Persistence,
          /// buffer webhooks while client offline (persist-only), None = disabled
          buffer: Option<BufferPolicy>,
          /// edge-enforced access control for the public URL (stage 07 W8), None = open
          auth: Option<EdgeAuth>,
      },
      Tcp { remote_port: Option<u16>, persist: Persistence },
  }

  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct EdgeAuth {
      pub basic: Option<String>,      // "user:pass" — edge replies 401 + WWW-Authenticate
      pub bearer: Option<String>,     // Authorization: Bearer <secret>
      /// client-generated 32-byte key (base64) for HMAC-signed expiring share links;
      /// client mints links offline, edge verifies. None = share links disabled.
      pub link_key: Option<String>,
  }

  #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
  #[serde(rename_all = "snake_case")]
  pub enum Persistence { Temporary, Persistent }

  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct BufferPolicy { pub max_requests: u32, pub max_body_bytes: u64, pub ttl_secs: u64 }

  #[derive(Debug, Clone, Serialize, Deserialize)]
  #[serde(tag = "kind", rename_all = "snake_case")]
  pub enum StreamHeader {
      Http {
          bind: Uuid,
          peer: SocketAddr,
          request: HttpRequestHead,
          buffered: Option<u64>,
      },
      Tcp { bind: Uuid, peer: SocketAddr },
  }

  /// Header values are base64 so non-UTF-8 values survive JSON exactly.
  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct HeaderField { pub name: String, pub value_b64: String }
  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct HttpRequestHead {
      pub method: String, pub uri: String, pub version: String,
      pub headers: Vec<HeaderField>,
  }
  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct HttpResponseHead {
      pub status: u16, pub version: String, pub headers: Vec<HeaderField>,
  }
  ```

  Plus `Limits { max_binds: u32, max_streams: u32 }`, `DenyReason` enum
  (`UnknownKey`, `BadSignature`, `VersionMismatch { expected: u16 }`, `KeyRevoked`, `Limit`),
  `EventKind` (`Info`, `Warning`, `BufferedDelivery`, `Shutdown`).
  Validation: `cargo test -p wormhole-proto` serde round-trip test for every variant
  (build one value per variant, `serde_json` round-trip, assert eq).

- [x] **P2 — Codec** (`codec.rs`). Thin helpers so client/server never hand-roll framing:

  ```rust
  pub struct ControlChannel<S> { framed: Framed<S, LengthDelimitedCodec>, }
  impl<S: AsyncRead + AsyncWrite + Unpin> ControlChannel<S> {
      pub fn new(io: S) -> Self { /* max_frame_length 1 MiB, 4-byte BE prefix */ }
      pub async fn send(&mut self, f: &ControlFrame) -> Result<(), ProtoError>;
      pub async fn recv(&mut self) -> Result<ControlFrame, ProtoError>;   // Err(Closed) on EOF
  }
  pub async fn write_stream_header<W: AsyncWrite + Unpin>(w: &mut W, h: &StreamHeader) -> ...;
  pub async fn read_stream_header<R: AsyncRead + Unpin>(r: &mut R) -> ...; // hard cap 64 KiB
  pub async fn write_response_head<W: AsyncWrite + Unpin>(
      w: &mut W, h: &HttpResponseHead
  ) -> ...;
  pub async fn read_response_head<R: AsyncRead + Unpin>(r: &mut R) -> ...; // hard cap 64 KiB
  ```

  Validation: unit test over `tokio::io::duplex` — send 100 mixed frames, receive identical;
  oversized frame returns `ProtoError::FrameTooLarge`, not a panic.

- [x] **P3 — Keys** (`keys.rs`). Ed25519 identity handling:

  ```rust
  pub struct Identity { signing: ed25519_dalek::SigningKey }   // wrap, zeroize on drop
  impl Identity {
      pub fn generate() -> Self;                                // rand::rng()
      pub fn load(path: &Utf8Path) -> Result<Self, ProtoError>; // refuse if mode != 0o600
      pub fn save(&self, path: &Utf8Path) -> Result<(), ProtoError>; // create 0o600, dirs 0o700
      pub fn public_base64(&self) -> String;
      pub fn fingerprint(&self) -> String;                      // "WH256:<base64(sha256(pub))>"
      pub fn sign_challenge(&self, nonce: &[u8; 32], server: &str, proto: u16) -> String;
  }
  pub fn verify_challenge(
      pub_b64: &str, nonce: &[u8; 32], server: &str, proto: u16, sig_b64: &str
  ) -> bool;
  ```

  On-disk format: single line `wormhole-ed25519 <base64 seed>` in the key file,
  `<pub base64> <comment>` for public entries (authorized-keys style, one per line).
  `save` writes a 0600 temp file in the owned 0700 parent, fsyncs, and atomically renames;
  it never creates a world-readable file or follows a symlink target.
  Challenge transcript: the domain-separated, length-prefixed encoding from the Design section
  (implement once in `keys.rs`, used by both sign and verify — never concatenate ad hoc).
  Validation: unit tests — sign/verify round-trip; tampered nonce/server/proto each fail;
  `load` rejects 0o644 file with a clear error; fingerprint is stable (insta snapshot).

- [x] **P4 — Handshake state machines** (`handshake.rs`). Pure, sans-IO, so both sides share one
  tested implementation:

  ```rust
  pub struct ClientHandshake { /* holds Identity, server_name, state */ }
  impl ClientHandshake {
      pub fn hello(&self) -> ControlFrame;
      /// feed server frame, get Option<reply>; Done(Welcome) or Failed(DenyReason) terminal
      pub fn step(&mut self, incoming: &ControlFrame) -> Result<HandshakeStep, ProtoError>;
  }
  pub struct ServerHandshake { /* generates nonce via rand, holds verifier callback */ }
  // same shape; caller supplies `is_authorized: impl Fn(&str) -> KeyDecision`
  ```

  Rules: any out-of-order frame → `ProtoError::Protocol`; handshake must finish within the
  first 2 frames each way; server rejects `proto != PROTO_VERSION` with `VersionMismatch`;
  **client refuses to sign when `Challenge.server != expected_server_name`**
  (`ProtoError::ServerNameMismatch`).
  Validation: unit tests — happy path client vs server machines wired directly; wrong key
  denied; out-of-order `Auth` before `Hello` errors; version mismatch carries `expected`;
  mismatched `Challenge.server` aborts without producing a signature.

- [x] **P5 — Property tests.** `proptest`: arbitrary byte-noise into `ControlChannel::recv`
  never panics (errors are fine); arbitrary valid frames always round-trip through codec.
  Validation: `cargo test -p wormhole-proto -- prop` passes.

## Acceptance gate

```bash
cargo test -p wormhole-proto --locked \
&& cargo clippy -p wormhole-proto --all-targets --locked -- -D warnings \
&& cargo fmt --all -- --check
```

Plus: `grep -r "tokio::net\|quinn" crates/wormhole-proto/src` returns nothing (crate stays
transport-free). Commit `feat(proto): wire protocol, keys, handshake`.
