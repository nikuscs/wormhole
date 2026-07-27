//! Public routing records, allocation requests, and registry errors.

use parking_lot::RwLock;
use tokio::sync::mpsc;
use uuid::Uuid;
use wormhole_proto::frames::{BindSpec, BufferPolicy, EdgeAuth, Persistence};

use crate::db::{PersistedBindSpec, PersistedEndpoint};

/// Lookup key used by HTTP and TCP edges.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HostKey {
    /// Fully qualified lower-case HTTP hostname.
    Hostname(String),
    /// Public TCP listener port.
    TcpPort(u16),
}

/// Public-routing readiness of a bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindState {
    /// Reserved but the client has not installed local routing.
    Pending,
    /// Ready to receive public streams.
    Online,
    /// Persistent reservation whose client is disconnected.
    Offline,
}

/// Commands sent from an edge to the owning session actor.
#[derive(Debug)]
pub enum SessionCommand {
    /// Relay shutdown notification; stream variants are added by S4/S7.
    Shutdown,
}

/// Shared routing record for one public endpoint.
pub struct BindHandle {
    /// Stable server bind identifier.
    pub bind_id: Uuid,
    /// Owning key fingerprint.
    pub key_fpr: String,
    /// Bind lifetime.
    pub persist: Persistence,
    /// Optional offline buffer policy.
    pub buffer_policy: Option<BufferPolicy>,
    /// Raw in-memory edge policy; never persisted or serialized by this type.
    pub auth: Option<EdgeAuth>,
    /// Sanitized requested bind specification.
    pub spec: PersistedBindSpec,
    /// Allocated public endpoint.
    pub endpoint: PersistedEndpoint,
    pub(crate) state: RwLock<BindState>,
    pub(crate) session_tx: RwLock<Option<mpsc::Sender<SessionCommand>>>,
    pub(crate) reservation: Option<Uuid>,
}

impl BindHandle {
    /// Returns the current routing state.
    pub fn state(&self) -> BindState {
        *self.state.read()
    }

    /// Returns a clone of the active session channel, if connected.
    pub fn session(&self) -> Option<mpsc::Sender<SessionCommand>> {
        self.session_tx.read().clone()
    }
}

/// Inputs required to allocate or reclaim a bind.
pub struct AllocationRequest {
    /// Authenticated owner fingerprint.
    pub key_fpr: String,
    /// Requested HTTP or TCP endpoint.
    pub spec: BindSpec,
    /// Optional secret reservation token.
    pub reservation: Option<Uuid>,
    /// Owning session actor channel.
    pub session_tx: mpsc::Sender<SessionCommand>,
}

/// Successful allocation returned to the session actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    /// Stable server bind identifier.
    pub bind: Uuid,
    /// Public URL list.
    pub urls: Vec<String>,
    /// Persistent reclaim token.
    pub reservation: Option<Uuid>,
    /// Bind lifetime.
    pub persist: Persistence,
}

/// Endpoint allocation or state-transition failure.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// Durable database access failed.
    #[error(transparent)]
    Database(#[from] crate::db::DbError),
    /// Requested server domain is not configured.
    #[error("unknown server domain: {0}")]
    UnknownDomain(String),
    /// Requested hostname label is invalid.
    #[error("invalid hostname label: {0}")]
    InvalidHostname(String),
    /// Hostname or TCP port is already reserved.
    #[error("public endpoint is already reserved: {0:?}")]
    Conflict(HostKey),
    /// Requested TCP port is outside the configured range.
    #[error("TCP port is outside the configured range: {0}")]
    PortOutsideRange(u16),
    /// No TCP port remains available.
    #[error("TCP port range is exhausted")]
    PortRangeExhausted,
    /// Random hostname attempts were exhausted.
    #[error("hostname allocation attempts exhausted")]
    AllocationExhausted,
    /// Reservation token does not exist.
    #[error("unknown reservation")]
    UnknownReservation,
    /// Reservation belongs to another key.
    #[error("reservation belongs to another key")]
    ReservationOwnerMismatch,
    /// Reservation protocol differs from the reclaim request.
    #[error("reservation protocol does not match request")]
    ReservationKindMismatch,
    /// Online reservations cannot be taken over.
    #[error("bind is already online: {0}")]
    AlreadyOnline(Uuid),
    /// Bind identifier is unknown.
    #[error("unknown bind: {0}")]
    UnknownBind(Uuid),
    /// State transition is invalid.
    #[error("bind {bind} has invalid state {state:?}")]
    InvalidState { bind: Uuid, state: BindState },
}

pub fn clone_request(request: &AllocationRequest) -> AllocationRequest {
    AllocationRequest {
        key_fpr: request.key_fpr.clone(),
        spec: request.spec.clone(),
        reservation: request.reservation,
        session_tx: request.session_tx.clone(),
    }
}
