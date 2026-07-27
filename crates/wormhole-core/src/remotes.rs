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

impl Remote {
    /// Creates a named-remote value for configuration editors.
    pub const fn new(addr: String, server_name: String, identity: Option<Utf8PathBuf>) -> Self {
        Self {
            transport: Transport::Auto,
            addr,
            server_name,
            trusted_ca: None,
            identity,
            extra: std::collections::BTreeMap::new(),
        }
    }

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
