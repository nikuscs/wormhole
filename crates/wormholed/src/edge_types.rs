//! Errors shared by public edge listeners.

pub fn forwarded_node(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("\"[{ip}]\""),
    }
}

/// Public HTTP edge failure.
#[derive(Debug, thiserror::Error)]
pub enum EdgeError {
    /// Listener or socket I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Response construction failed.
    #[error(transparent)]
    Http(#[from] http::Error),
    /// Response header name was invalid.
    #[error(transparent)]
    HeaderName(#[from] http::header::InvalidHeaderName),
    /// Response header value was invalid.
    #[error(transparent)]
    HeaderValue(#[from] http::header::InvalidHeaderValue),
    /// Base64 header decoding failed.
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    /// The owning client disconnected.
    #[error("tunnel is offline")]
    Offline,
    /// Client response head exceeded the timeout.
    #[error("tunnel response header timed out")]
    HeaderTimeout,
    /// Client tunnel returned an error.
    #[error("tunnel failed: {0}")]
    Tunnel(String),
    /// A 101 response lacked either side of its raw upgrade stream.
    #[error("HTTP upgrade stream is missing")]
    MissingUpgrade,
}
