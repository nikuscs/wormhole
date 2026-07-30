//! Tunnel driver contract, capability metadata, and registry.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    error::DriverError,
    model::{CapturedRequest, EndpointSpec, ResolvedTarget},
};

/// Cheap pre-flight result for one driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverHealth {
    /// Driver is ready.
    Healthy,
    /// Driver is installed but needs configuration or authorization.
    Degraded(String),
    /// Driver cannot currently run.
    Unavailable(String),
}

/// Optional endpoint feature advertised by a driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// HTTP buffering policy.
    Buffer,
    /// Relay-edge authentication.
    Auth,
    /// Local delivery retries.
    Retry,
    /// HTTP request inspection.
    Inspect,
}

/// Compact set of options a driver explicitly supports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DriverCapabilities(u8);

impl DriverCapabilities {
    const BUFFER: u8 = 1;
    const AUTH: u8 = 1 << 1;
    const RETRY: u8 = 1 << 2;
    const INSPECT: u8 = 1 << 3;

    /// Capabilities implemented by the Stage 04 Wormhole HTTP path.
    pub const fn wormhole_http() -> Self {
        Self(Self::BUFFER | Self::AUTH | Self::RETRY | Self::INSPECT)
    }

    /// All optional capabilities, useful for provider implementations and tests.
    pub const fn all() -> Self {
        Self(Self::BUFFER | Self::AUTH | Self::RETRY | Self::INSPECT)
    }

    /// Returns whether a capability is advertised.
    pub const fn supports(self, capability: Capability) -> bool {
        let flag = match capability {
            Capability::Buffer => Self::BUFFER,
            Capability::Auth => Self::AUTH,
            Capability::Retry => Self::RETRY,
            Capability::Inspect => Self::INSPECT,
        };
        self.0 & flag != 0
    }
}

#[cfg(test)]
#[path = "driver_tests.rs"]
mod tests;

/// Lifecycle event emitted by a running driver.
#[derive(Debug, Clone)]
pub enum DriverEvent {
    /// Internal delivery barrier used to acknowledge reliable daemon handoff.
    #[doc(hidden)]
    Handoff(Arc<tokio::sync::Notify>),
    /// Public endpoint is installed and ready for traffic.
    Ready {
        /// Public URLs.
        urls: Vec<String>,
        /// Wormhole server bind identifier.
        bind_id: Option<Uuid>,
        /// Persistent reservation token.
        reservation: Option<Uuid>,
    },
    /// Driver changed its lifecycle status.
    StatusChanged(crate::model::EndpointStatus),
    /// Structured driver log record.
    Log(tracing::Level, String),
    /// Driver stopped intentionally or exhausted retries.
    Closed,
    /// Captured HTTP request record.
    Captured(Box<CapturedRequest>),
    /// Buffered webhook replay progress.
    BufferedDelivery { pending: u32, failed: u32, delivered_delta: u64 },
}

/// Driver event tagged with its manager-local endpoint id.
#[derive(Debug, Clone)]
pub struct EndpointEvent {
    /// Manager-local endpoint identifier.
    pub endpoint: Uuid,
    /// Original driver event, including bind and reservation identifiers.
    pub event: DriverEvent,
}

/// One pluggable tunnel provider implementation.
#[async_trait]
pub trait TunnelDriver: Send + Sync {
    /// Stable registry key.
    fn name(&self) -> &'static str;

    /// Explicitly supported endpoint options.
    fn capabilities(&self) -> DriverCapabilities {
        DriverCapabilities::default()
    }

    /// Validates driver-specific endpoint fields before spawning work.
    fn validate(&self, _spec: &EndpointSpec) -> Result<(), DriverError> {
        Ok(())
    }

    /// Cheap health probe.
    async fn check(&self) -> DriverHealth;

    /// Detailed provider checks used by `wormhole doctor`.
    async fn diagnostics(&self) -> Vec<(String, DriverHealth)> {
        vec![(self.name().to_owned(), self.check().await)]
    }

    /// Owns one endpoint lifecycle, including reconnect behavior.
    async fn run(
        &self,
        spec: EndpointSpec,
        target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
    ) -> Result<(), DriverError>;

    /// Runs with a manager-owned flag that requests reservation deletion on close.
    async fn run_controlled(
        &self,
        spec: EndpointSpec,
        target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
        _forget: watch::Receiver<bool>,
        _preserve: watch::Receiver<bool>,
    ) -> Result<(), DriverError> {
        self.run(spec, target, events, stop).await
    }
}

/// Registry built once from configured driver instances.
#[derive(Default)]
pub struct DriverRegistry {
    map: parking_lot::RwLock<HashMap<&'static str, Arc<dyn TunnelDriver>>>,
}

impl DriverRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers or replaces a driver by its stable name.
    pub fn register(&self, driver: Arc<dyn TunnelDriver>) {
        self.map.write().insert(driver.name(), driver);
    }

    /// Looks up a driver.
    pub fn get(&self, name: &str) -> Option<Arc<dyn TunnelDriver>> {
        self.map.read().get(name).cloned()
    }

    /// Returns all drivers in stable name order.
    pub fn all(&self) -> Vec<Arc<dyn TunnelDriver>> {
        let mut drivers = self.map.read().values().cloned().collect::<Vec<_>>();
        drivers.sort_by_key(|driver| driver.name());
        drivers
    }
}
