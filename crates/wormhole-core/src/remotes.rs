//! Named Wormhole relay remotes and address resolution.

use std::net::SocketAddr;

use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::ConfigError;

/// One named Wormhole relay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Remote {
    /// Preferred control transport.
    #[serde(default)]
    pub transport: Transport,
    /// UDP authority of the relay.
    pub addr: String,
    /// TLS and handshake-bound server name.
    pub server_name: String,
    /// Optional HTTPS authority for WebSocket fallback; defaults to `server_name:443`.
    pub https_addr: Option<String>,
    /// Optional exclusive development CA root.
    #[schema(value_type = Option<String>)]
    pub trusted_ca: Option<Utf8PathBuf>,
    /// Optional per-remote identity override.
    #[schema(value_type = Option<String>)]
    pub identity: Option<Utf8PathBuf>,
    /// Unknown forward-compatible settings.
    #[serde(default, flatten)]
    #[schema(ignore)]
    pub(crate) extra: std::collections::BTreeMap<String, toml::Value>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    #[default]
    Auto,
    Quic,
    Ws,
}

#[cfg(test)]
#[path = "remotes_tests.rs"]
mod tests;

impl Remote {
    /// Creates a named-remote value for configuration editors.
    pub const fn new(addr: String, server_name: String, identity: Option<Utf8PathBuf>) -> Self {
        Self {
            transport: Transport::Auto,
            addr,
            server_name,
            https_addr: None,
            trusted_ca: None,
            identity,
            extra: std::collections::BTreeMap::new(),
        }
    }

    /// Resolves every address for the configured UDP authority.
    pub async fn resolve_addrs(&self) -> Result<Vec<SocketAddr>, ConfigError> {
        resolve_authority(&self.addr).await
    }

    /// Resolves every address for the configured HTTPS authority or standard relay port.
    pub async fn resolve_https_addrs(&self) -> Result<Vec<SocketAddr>, ConfigError> {
        let authority =
            self.https_addr.clone().unwrap_or_else(|| format!("{}:443", self.server_name));
        resolve_authority(&authority).await
    }
}

async fn resolve_authority(authority: &str) -> Result<Vec<SocketAddr>, ConfigError> {
    let addresses = tokio::net::lookup_host(authority)
        .await
        .map_err(|error| ConfigError::Invalid(format!("cannot resolve {authority}: {error}")))?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        Err(ConfigError::Invalid(format!("remote has no address: {authority}")))
    } else {
        Ok(addresses)
    }
}
