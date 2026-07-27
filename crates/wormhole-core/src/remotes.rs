//! Named Wormhole relay remotes and address resolution.

use std::net::SocketAddr;

use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// One named Wormhole relay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Remote {
    /// UDP authority of the relay.
    pub addr: String,
    /// TLS and handshake-bound server name.
    pub server_name: String,
    /// Optional exclusive development CA root.
    pub trusted_ca: Option<Utf8PathBuf>,
    /// Optional per-remote identity override.
    pub identity: Option<Utf8PathBuf>,
    /// Unknown forward-compatible settings.
    #[serde(default, flatten)]
    pub(crate) extra: std::collections::BTreeMap<String, toml::Value>,
}

impl Remote {
    /// Resolves the configured UDP authority.
    pub async fn resolve_addr(&self) -> Result<SocketAddr, ConfigError> {
        tokio::net::lookup_host(&self.addr)
            .await
            .map_err(|error| {
                ConfigError::Invalid(format!("cannot resolve {}: {error}", self.addr))
            })?
            .next()
            .ok_or_else(|| ConfigError::Invalid(format!("remote has no address: {}", self.addr)))
    }
}
