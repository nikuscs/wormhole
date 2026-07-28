//! Public routing records, allocation requests, and registry errors.

use bytes::Bytes;
use parking_lot::RwLock;
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot},
};
use uuid::Uuid;
use wormhole_proto::frames::{
    BindSpec, BufferPolicy, EdgeAuth, HttpResponseHead, Persistence, StreamHeader,
};

use crate::db::{AuthVerifier, PersistedBindSpec, PersistedEndpoint};

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
    /// Opens one logical HTTP request stream to the client.
    OpenHttp {
        /// Typed request metadata.
        header: StreamHeader,
        /// Bounded streaming request-body channel.
        body: mpsc::Receiver<Result<Bytes, String>>,
        /// Whether a 101 response should retain the stream bidirectionally.
        upgrade: bool,
        /// Response head and bounded body channel.
        reply: oneshot::Sender<Result<HttpTunnelResponse, String>>,
    },
    /// Opens one raw TCP stream to the client.
    OpenTcp {
        /// Typed TCP connection metadata.
        header: StreamHeader,
        /// Accepted public TCP connection.
        stream: TcpStream,
    },
    /// Sends updated buffered queue counts to the owning client.
    BufferedStatus { bind: Uuid, pending: u32, failed: u32 },
    /// Removes a bind deleted through the administration API from session ownership.
    RemoveBind {
        /// Stable bind identifier.
        bind: Uuid,
    },
    /// Relay shutdown notification.
    Shutdown,
}

/// Response returned from a client-opened HTTP target.
pub struct HttpTunnelResponse {
    /// Typed response metadata.
    pub head: HttpResponseHead,
    /// Bounded streaming response-body channel.
    pub body: mpsc::Receiver<Result<Bytes, String>>,
    /// Raw tunnel stream retained after a 101 response.
    pub upgrade: Option<UpgradeTunnel>,
}

impl std::fmt::Debug for HttpTunnelResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpTunnelResponse")
            .field("head", &self.head)
            .field("upgrade", &self.upgrade.is_some())
            .finish_non_exhaustive()
    }
}

pub type TunnelRead = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
pub type TunnelWrite = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

/// Raw bidirectional tunnel stream retained for an HTTP upgrade.
pub struct UpgradeTunnel {
    /// Notifies the session actor when the upgraded stream is released.
    pub(crate) release: tokio::sync::oneshot::Sender<()>,
    /// Bytes from the local target to the public client.
    pub recv: TunnelRead,
    /// Bytes from the public client to the local target.
    pub send: TunnelWrite,
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
    /// Persistable verification material used after relay restarts.
    pub(crate) auth_verifier: RwLock<Option<AuthVerifier>>,
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

    /// Returns persisted edge-auth verification material, if configured.
    pub(crate) fn auth_verifier(&self) -> Option<AuthVerifier> {
        self.auth_verifier.read().clone()
    }

    /// Replaces persisted edge-auth verification material.
    pub(crate) fn set_auth_verifier(&self, verifier: Option<AuthVerifier>) {
        *self.auth_verifier.write() = verifier;
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
    /// Offline buffering requires a persistent HTTP reservation.
    #[error("buffer policy requires a persistent HTTP bind")]
    TemporaryBufferPolicy,
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
    /// Bind transition came from a session that does not own the route.
    #[error("bind is owned by another session: {0}")]
    SessionOwnerMismatch(Uuid),
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
