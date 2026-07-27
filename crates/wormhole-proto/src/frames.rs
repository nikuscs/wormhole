//! Serializable control frames and data-stream headers for protocol version 1.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Exact protocol version carried in the handshake.
pub const PROTO_VERSION: u16 = 1;
/// ALPN identifier for the version 1 wire contract.
pub const ALPN: &[u8] = b"wormhole/1";

/// Frames exchanged over the long-lived control stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ControlFrame {
    /// Starts a client handshake.
    Hello { proto: u16, client: String, pubkey: String },
    /// Challenges the client with a single-use nonce.
    Challenge { nonce: String, server: String },
    /// Proves possession of the advertised private key.
    Auth { signature: String },
    /// Completes an authenticated handshake.
    Welcome { session: Uuid, limits: Limits, motd: Option<String> },
    /// Terminates a rejected handshake.
    Denied { reason: DenyReason },
    /// Requests a new public bind.
    Bind { request: Uuid, spec: BindSpec, reservation: Option<Uuid> },
    /// Removes a bind and optionally its persistent reservation.
    Unbind { bind: Uuid, forget: bool },
    /// Confirms that the client installed local routing for a bind.
    BindReady { bind: Uuid },
    /// Reports a successful server-side bind reservation.
    Bound {
        request: Uuid,
        bind: Uuid,
        urls: Vec<String>,
        persist: Persistence,
        reservation: Option<Uuid>,
        pending_buffered: u32,
        failed_buffered: u32,
    },
    /// Reports a failed bind request.
    BindError { request: Uuid, reason: String },
    /// Confirms the bind is online and may receive streams.
    BindActive { bind: Uuid },
    /// Carries an informational session event.
    Event { kind: EventKind, msg: String },
    /// Acknowledges complete delivery of a buffered webhook.
    AckBuffered { bind: Uuid, seq: u64 },
    /// Reports exhausted local delivery retries for a buffered webhook.
    NackBuffered { bind: Uuid, seq: u64, reason: String },
    /// Probes control-stream liveness.
    Ping { seq: u64 },
    /// Answers a liveness probe.
    Pong { seq: u64 },
}

/// Public endpoint requested by a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BindSpec {
    /// HTTP endpoint terminated and routed by the relay.
    Http {
        /// Requested subdomain label, never a complete hostname.
        host: Option<String>,
        /// Selected server-configured domain, or the server default.
        domain: Option<String>,
        /// Whether the relay reserves this bind while the client is offline.
        persist: Persistence,
        /// Optional offline webhook buffering policy.
        buffer: Option<BufferPolicy>,
        /// Optional access control enforced by the relay edge.
        auth: Option<EdgeAuth>,
    },
    /// Raw TCP endpoint.
    Tcp { remote_port: Option<u16>, persist: Persistence },
}

/// Access-control material enforced at a public HTTP edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeAuth {
    /// Basic-auth credential in `user:password` form.
    pub basic: Option<String>,
    /// Bearer token expected in the Authorization header.
    pub bearer: Option<String>,
    /// Base64-encoded HMAC key for expiring share links.
    pub link_key: Option<String>,
}

/// Lifetime of a bind reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Persistence {
    /// Exists only while the client session is connected.
    Temporary,
    /// Remains reserved across disconnects.
    Persistent,
}

/// Limits applied to offline webhook buffering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BufferPolicy {
    /// Maximum buffered request count.
    pub max_requests: u32,
    /// Maximum body bytes retained per request.
    pub max_body_bytes: u64,
    /// Maximum retention time in seconds.
    pub ttl_secs: u64,
}

/// Header sent before each server-opened data stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StreamHeader {
    /// HTTP request metadata followed by streaming request bytes.
    Http { bind: Uuid, peer: SocketAddr, request: HttpRequestHead, buffered: Option<u64> },
    /// TCP connection metadata followed by raw bidirectional bytes.
    Tcp { bind: Uuid, peer: SocketAddr },
}

/// Header name and base64-encoded raw value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderField {
    /// HTTP field name.
    pub name: String,
    /// Base64-encoded field value, preserving non-UTF-8 bytes.
    pub value_b64: String,
}

/// Serializable HTTP request metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequestHead {
    /// HTTP method token.
    pub method: String,
    /// Request target.
    pub uri: String,
    /// HTTP version string.
    pub version: String,
    /// Ordered request fields.
    pub headers: Vec<HeaderField>,
}

/// Serializable HTTP response metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponseHead {
    /// Numeric HTTP status.
    pub status: u16,
    /// HTTP version string.
    pub version: String,
    /// Ordered response fields.
    pub headers: Vec<HeaderField>,
}

/// Session limits advertised by the relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Maximum simultaneous binds.
    pub max_binds: u32,
    /// Maximum simultaneous data streams.
    pub max_streams: u32,
}

/// Stable handshake rejection category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DenyReason {
    /// The presented public key is not authorized.
    UnknownKey,
    /// Signature verification failed.
    BadSignature,
    /// The peer uses an incompatible protocol version.
    VersionMismatch { expected: u16 },
    /// The presented key has been revoked.
    KeyRevoked,
    /// A server policy limit rejected the handshake.
    Limit,
}

/// Session event category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Informational event.
    Info,
    /// Recoverable warning.
    Warning,
    /// Buffered delivery progress.
    BufferedDelivery,
    /// Relay shutdown notification.
    Shutdown,
}

#[cfg(test)]
#[path = "frames_tests.rs"]
mod tests;
