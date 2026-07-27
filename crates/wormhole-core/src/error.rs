//! Client-core error types.

use camino::Utf8PathBuf;

/// Configuration loading or validation failure.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Configuration file I/O failed.
    #[error("configuration I/O failed for {path}: {source}")]
    Io { path: Utf8PathBuf, source: std::io::Error },
    /// TOML decoding failed.
    #[error("invalid configuration {path}: {source}")]
    Toml { path: Utf8PathBuf, source: toml::de::Error },
    /// Configuration values conflict or are incomplete.
    #[error("invalid client configuration: {0}")]
    Invalid(String),
}

/// Driver registration or execution failure.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DriverError {
    /// No driver is registered under this name.
    #[error("unknown tunnel driver: {0}")]
    Unknown(String),
    /// Driver preflight failed.
    #[error("tunnel driver unavailable: {0}")]
    Unavailable(String),
    /// The endpoint requests unsupported options.
    #[error("driver capability mismatch: {0}")]
    Capability(String),
    /// Remote or local transport failed.
    #[error("driver transport failed: {0}")]
    Transport(String),
    /// Protocol sequencing failed.
    #[error("driver protocol failed: {0}")]
    Protocol(String),
    /// Endpoint was cancelled.
    #[error("driver endpoint cancelled")]
    Cancelled,
}

/// Identity path or key persistence failure.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// Identity path cannot be represented safely.
    #[error("invalid identity path: {0}")]
    Path(String),
    /// Protocol key operation failed.
    #[error(transparent)]
    Protocol(#[from] wormhole_proto::ProtoError),
}

/// Interface alias resolution failure.
#[derive(Debug, thiserror::Error)]
pub enum IfaceError {
    /// Alias or hostname could not be resolved.
    #[error("cannot resolve interface alias or host: {0}")]
    Unresolved(String),
    /// Host lookup failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Port utility failure.
#[derive(Debug, thiserror::Error)]
pub enum PortError {
    /// No port in the requested range was available.
    #[error("no free port in requested range")]
    Exhausted,
    /// Listener did not become reachable before the deadline.
    #[error("listener did not become reachable before timeout")]
    Timeout,
    /// Socket or process inspection failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Tunnel-manager operation failure.
#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    /// Driver validation or execution setup failed.
    #[error(transparent)]
    Driver(#[from] DriverError),
    /// Local target resolution failed.
    #[error(transparent)]
    Interface(#[from] IfaceError),
    /// Endpoint identifier is unknown.
    #[error("unknown endpoint: {0}")]
    UnknownEndpoint(uuid::Uuid),
    /// Endpoint cleanup could not be confirmed.
    #[error("endpoint cleanup failed: {0}")]
    Cleanup(String),
}
