//! Shared client-core service, endpoint, event, and diagnostic models.

use std::net::SocketAddr;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wormhole_proto::frames::{BufferPolicy, EdgeAuth, Persistence};

/// Protocol spoken by a local service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceProto {
    /// HTTP reverse proxying.
    Http,
    /// Raw TCP forwarding.
    Tcp,
}

/// A local thing to expose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    /// Stable local service name.
    pub name: String,
    /// Unresolved local destination.
    pub target: Target,
    /// Local delivery protocol.
    pub proto: ServiceProto,
}

/// Local target before interface-alias resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Target {
    /// Loopback TCP port.
    Port(u16),
    /// Explicit host and port.
    HostPort(String, u16),
    /// Named interface alias and port.
    Iface { alias: String, port: u16 },
}

/// Resolved socket destination supplied to drivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedTarget(pub SocketAddr);

/// Local HTTP delivery retry policy reserved for Stage 07 behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum delivery attempts.
    pub max_attempts: u32,
    /// Initial delay in milliseconds.
    pub initial_delay_ms: u64,
}

/// One desired public exposure through one driver instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointSpec {
    /// Public protocol, overwritten from the service by the manager.
    pub proto: ServiceProto,
    /// Registered driver name.
    pub driver: String,
    /// Optional provider mode.
    pub qualifier: Option<String>,
    /// Optional named Wormhole remote.
    pub remote: Option<String>,
    /// Requested server-owned subdomain label.
    pub host: Option<String>,
    /// Requested offered server domain.
    pub domain: Option<String>,
    /// Provider-side public port.
    pub public_port: Option<u16>,
    /// Endpoint lifetime.
    pub persist: Persistence,
    /// Offline HTTP buffering policy.
    pub buffer: Option<BufferPolicy>,
    /// Relay-edge authentication policy.
    pub auth: Option<EdgeAuth>,
    /// Local delivery retries.
    pub retry: Option<RetryPolicy>,
    /// Capture requests for inspection.
    pub inspect: bool,
    /// Reservation used to reclaim a persistent Wormhole bind.
    #[serde(default)]
    pub reservation: Option<Uuid>,
}

/// Current endpoint lifecycle status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointStatus {
    /// Public routing is ready.
    Online,
    /// Driver is reconnecting.
    Reconnecting,
    /// Endpoint is intentionally stopped.
    Offline,
    /// Driver terminated with an error.
    Error(String),
}

/// A live or recently stopped exposure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveEndpoint {
    /// Manager-local endpoint identifier.
    pub id: Uuid,
    /// Owning service name.
    pub service: String,
    /// Driver registry name.
    pub driver: String,
    /// Public URLs currently assigned.
    pub urls: Vec<String>,
    /// Current lifecycle status.
    pub status: EndpointStatus,
    /// Time this status record was created.
    pub since: Timestamp,
}

/// Captured HTTP request metadata reserved for Stage 07 inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedRequest {
    /// Endpoint bind identifier.
    pub bind_id: Uuid,
    /// Request method.
    pub method: String,
    /// Request target.
    pub uri: String,
    /// Capture timestamp.
    pub captured_at: Timestamp,
}

/// One manager status transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusChange {
    /// Endpoint that changed.
    pub endpoint: Uuid,
    /// New status.
    pub status: EndpointStatus,
}

/// Structured diagnostic result rendered by Stage 05.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    /// Check name.
    pub name: String,
    /// Whether it succeeded.
    pub healthy: bool,
    /// Human-readable detail without secrets.
    pub detail: String,
}
