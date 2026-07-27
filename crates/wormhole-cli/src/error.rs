//! CLI-facing failures and stable exit-code mapping.

use thiserror::Error;

/// One command failure.
#[derive(Debug, Error)]
pub enum CliError {
    /// Daemon lifecycle failed.
    #[error(transparent)]
    Daemon(#[from] crate::daemon::DaemonError),
    /// Local daemon API is unreachable or failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// Runtime directory setup failed.
    #[error(transparent)]
    Runtime(#[from] crate::runtime::RuntimeError),
    /// Command-line value is invalid.
    #[error("{0}")]
    Invalid(String),
    /// Relay authentication or authorization was denied.
    #[error("access denied: {0}")]
    Denied(String),
    /// Endpoint setup failed before any endpoint became ready.
    #[error("no endpoint became ready")]
    EndpointFailed,
    /// Only some requested endpoints became ready.
    #[error("only some endpoints became ready")]
    Partial,
    /// Wrapped child exited with a non-zero code already visible on inherited stderr.
    #[error("child exited with status {0}")]
    ChildExit(u8),
    /// Core manager operation failed.
    #[error(transparent)]
    Manager(#[from] wormhole_core::ManagerError),
    /// Client configuration is invalid.
    #[error(transparent)]
    Config(#[from] wormhole_core::ConfigError),
    /// Driver probe failed.
    #[error(transparent)]
    Driver(#[from] wormhole_core::DriverError),
    /// Local port allocation or detection failed.
    #[error(transparent)]
    Port(#[from] wormhole_core::PortError),
    /// Identity-store setup failed.
    #[error(transparent)]
    Identity(#[from] wormhole_core::IdentityError),
    /// Local command I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl CliError {
    /// Stable process exit code.
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Invalid(_) => 2,
            Self::Denied(_) => 4,
            Self::Client(crate::client::ClientError::Api { status, .. })
                if matches!(status.as_u16(), 401 | 403) =>
            {
                4
            }
            Self::Client(crate::client::ClientError::Api { status, .. })
                if status.as_u16() == 502 =>
            {
                5
            }
            Self::EndpointFailed => 5,
            Self::Partial => 6,
            Self::ChildExit(code) => *code,
            Self::Client(crate::client::ClientError::Api { .. })
            | Self::Daemon(_)
            | Self::Runtime(_)
            | Self::Manager(_)
            | Self::Config(_)
            | Self::Driver(_)
            | Self::Port(_)
            | Self::Identity(_)
            | Self::Io(_) => 1,
            Self::Client(_) => 3,
        }
    }

    /// Whether the CLI should add its own stderr diagnostic.
    pub const fn should_render(&self) -> bool {
        !matches!(self, Self::ChildExit(_))
    }

    /// Optional concise recovery guidance.
    pub const fn hint(&self) -> Option<&str> {
        match self {
            Self::Client(crate::client::ClientError::Api { .. }) => None,
            Self::Client(_) => Some("run `wormhole daemon logs` to inspect daemon startup"),
            Self::Driver(wormhole_core::DriverError::Unknown(_)) => {
                Some("install or configure the requested tunnel provider")
            }
            Self::EndpointFailed | Self::Partial => Some("run `wormhole doctor` for diagnostics"),
            _ => None,
        }
    }
}
