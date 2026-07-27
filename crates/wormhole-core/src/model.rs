//! Shared client-core service, endpoint, event, and diagnostic models.

use std::net::SocketAddr;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use wormhole_proto::frames::{BufferPolicy, EdgeAuth, Persistence};

/// Protocol spoken by a local service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceProto {
    /// HTTP reverse proxying.
    Http,
    /// Raw TCP forwarding.
    Tcp,
}

/// A local thing to expose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Service {
    /// Stable local service name.
    pub name: String,
    /// Unresolved local destination.
    #[schema(value_type = TargetSchema)]
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

/// Schema-only representation of the tagged target wire contract.
#[doc(hidden)]
#[derive(ToSchema)]
#[serde(untagged)]
pub enum TargetSchema {
    Port(PortTargetSchema),
    HostPort(HostPortTargetSchema),
    Iface(IfaceTargetSchema),
}

#[doc(hidden)]
#[derive(ToSchema)]
pub struct PortTargetSchema {
    pub kind: PortTargetKind,
    pub value: u16,
}

#[doc(hidden)]
#[derive(ToSchema)]
pub struct HostPortTargetSchema {
    pub kind: HostPortTargetKind,
    pub value: HostPortValueSchema,
}

#[doc(hidden)]
#[derive(ToSchema)]
pub struct HostPortValueSchema(pub String, pub u16);

#[doc(hidden)]
#[derive(ToSchema)]
pub struct IfaceTargetSchema {
    pub kind: IfaceTargetKind,
    pub value: IfaceTargetValueSchema,
}

#[doc(hidden)]
#[derive(ToSchema)]
pub struct IfaceTargetValueSchema {
    pub alias: String,
    pub port: u16,
}

#[doc(hidden)]
#[derive(ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PortTargetKind {
    Port,
}

#[doc(hidden)]
#[derive(ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostPortTargetKind {
    HostPort,
}

#[doc(hidden)]
#[derive(ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IfaceTargetKind {
    Iface,
}

/// Resolved socket destination supplied to drivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedTarget(pub SocketAddr);

/// Local HTTP delivery retry policy reserved for Stage 07 behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    #[serde(default = "default_retry_max_delay")]
    pub max_delay_ms: u64,
    #[serde(default = "default_retry_connect")]
    pub retry_connect: bool,
    #[serde(default)]
    pub retry_5xx: bool,
    #[serde(default = "default_retry_body")]
    pub max_body_bytes: u64,
    #[serde(default = "default_retry_deadline")]
    pub total_deadline_ms: u64,
}

const fn default_retry_max_delay() -> u64 {
    30_000
}

const fn default_retry_connect() -> bool {
    true
}

const fn default_retry_body() -> u64 {
    1024 * 1024
}

const fn default_retry_deadline() -> u64 {
    60_000
}

/// One desired public exposure through one driver instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
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
    /// Include static asset requests in inspection capture.
    #[serde(default)]
    pub inspect_assets: bool,
    /// Maximum complete request body retained for inspection.
    #[serde(default = "default_capture_body_max")]
    pub capture_body_max: u64,
    /// Reservation used to reclaim a persistent Wormhole bind.
    #[serde(default)]
    pub reservation: Option<Uuid>,
}

const fn default_capture_body_max() -> u64 {
    1024 * 1024
}

/// Current endpoint lifecycle status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
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
    /// Number of buffered webhooks delivered in this daemon lifetime.
    #[serde(default)]
    pub buffered_delivered: u64,
    /// Number waiting at the relay when last reported.
    #[serde(default)]
    pub buffered_pending: u32,
    /// Number quarantined at the relay when last reported.
    #[serde(default)]
    pub buffered_failed: u32,
    /// Time this status record was created.
    #[schema(value_type = String, format = DateTime)]
    pub since: Timestamp,
}

/// One redacted captured HTTP header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CapturedHeader {
    pub name: String,
    pub value_b64: String,
}

/// Memory-only captured HTTP exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CapturedRequest {
    pub id: Uuid,
    pub endpoint_id: Option<Uuid>,
    pub bind_id: Uuid,
    pub method: String,
    pub uri: String,
    pub headers: Vec<CapturedHeader>,
    #[serde(with = "base64_bytes")]
    #[schema(value_type = String)]
    pub body: Vec<u8>,
    pub body_truncated: bool,
    pub response_status: Option<u16>,
    pub response_headers: Vec<CapturedHeader>,
    #[serde(with = "base64_bytes")]
    #[schema(value_type = String)]
    pub response_body_prefix: Vec<u8>,
    pub response_body_truncated: bool,
    pub duration_ms: u64,
    pub delivery: String,
    #[schema(value_type = String, format = DateTime)]
    pub captured_at: Timestamp,
}

mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        STANDARD.decode(value).map_err(serde::de::Error::custom)
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DoctorCheck {
    /// Check name.
    pub name: String,
    /// Whether it succeeded.
    pub healthy: bool,
    /// Human-readable detail without secrets.
    pub detail: String,
}
