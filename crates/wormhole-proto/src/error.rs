//! Errors produced while encoding, decoding, and authenticating protocol data.

use std::io;

/// Error type shared by all protocol primitives.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// The peer closed a framed channel before another frame arrived.
    #[error("protocol channel closed")]
    Closed,
    /// An encoded or declared frame exceeded its fixed protocol limit.
    #[error("frame exceeds the {limit}-byte limit")]
    FrameTooLarge { limit: usize },
    /// JSON serialization or decoding failed.
    #[error("invalid protocol JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Underlying asynchronous I/O failed.
    #[error("protocol I/O failed: {0}")]
    Io(#[from] io::Error),
    /// A handshake frame arrived in an invalid state.
    #[error("protocol violation: {0}")]
    Protocol(String),
    /// A challenge named a relay other than the configured remote.
    #[error("challenge server name mismatch: expected {expected}, got {actual}")]
    ServerNameMismatch { expected: String, actual: String },
    /// Identity material was malformed.
    #[error("invalid identity: {0}")]
    InvalidIdentity(String),
    /// Identity file permissions were not private.
    #[error("identity file {path} must have mode 0600, got {mode:04o}")]
    KeyPermissions { path: String, mode: u32 },
    /// Refused to read or replace a symbolic-link identity path.
    #[error("identity path is a symbolic link: {0}")]
    KeySymlink(String),
}
