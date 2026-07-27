//! Endpoint status mutation helpers.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    driver::{Capability, DriverCapabilities, DriverEvent, DriverHealth, TunnelDriver},
    error::{DriverError, ManagerError},
    model::{ActiveEndpoint, EndpointSpec, ResolvedTarget, ServiceProto},
};

pub async fn preflight_driver(
    driver: Arc<dyn TunnelDriver>,
    allow_partial: bool,
) -> Result<Arc<dyn TunnelDriver>, ManagerError> {
    match driver.check().await {
        DriverHealth::Healthy => Ok(driver),
        DriverHealth::Degraded(message) | DriverHealth::Unavailable(message) if allow_partial => {
            Ok(Arc::new(UnavailableDriver(message)))
        }
        DriverHealth::Degraded(message) | DriverHealth::Unavailable(message) => {
            Err(DriverError::Unavailable(message).into())
        }
    }
}

struct UnavailableDriver(String);

#[async_trait]
impl TunnelDriver for UnavailableDriver {
    fn name(&self) -> &'static str {
        "unavailable"
    }

    async fn check(&self) -> DriverHealth {
        DriverHealth::Healthy
    }

    async fn run(
        &self,
        _spec: EndpointSpec,
        _target: ResolvedTarget,
        _events: mpsc::Sender<DriverEvent>,
        _stop: CancellationToken,
    ) -> Result<(), DriverError> {
        Err(DriverError::Unavailable(self.0.clone()))
    }
}

pub fn validate_capabilities(
    spec: &EndpointSpec,
    capabilities: DriverCapabilities,
) -> Result<(), DriverError> {
    let http = spec.proto == ServiceProto::Http;
    if spec.buffer.is_some() && spec.persist == wormhole_proto::frames::Persistence::Temporary {
        return Err(DriverError::Capability(
            "buffer policy requires a persistent endpoint".to_owned(),
        ));
    }
    let options = [
        (spec.buffer.is_some(), Capability::Buffer, "buffer"),
        (spec.auth.is_some(), Capability::Auth, "auth"),
        (spec.retry.is_some(), Capability::Retry, "retry"),
        (spec.inspect, Capability::Inspect, "inspect"),
    ];
    if let Some(option) = options.into_iter().find_map(|(requested, capability, name)| {
        (requested && (!http || !capabilities.supports(capability))).then_some(name)
    }) {
        return Err(DriverError::Capability(format!(
            "driver {} does not support {option} for {:?}",
            spec.driver, spec.proto
        )));
    }
    Ok(())
}

pub fn apply_ready_urls(
    endpoints: &RwLock<HashMap<Uuid, ActiveEndpoint>>,
    id: Uuid,
    event: &DriverEvent,
) {
    if let DriverEvent::Ready { urls, .. } = event
        && let Some(endpoint) = endpoints.write().get_mut(&id)
    {
        endpoint.urls.clone_from(urls);
    }
}
