//! Portless local-hostname driver backed by the shared Host router.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wormhole_proto::frames::Persistence;

use crate::{
    driver::{DriverCapabilities, DriverEvent, DriverHealth, TunnelDriver},
    error::DriverError,
    local_router::{LocalRouter, shared},
    model::{EndpointSpec, ResolvedTarget, ServiceProto},
};

/// Local HTTP Host-routing driver.
pub struct LocalDriver {
    router: Arc<LocalRouter>,
    http_port: u16,
}

impl LocalDriver {
    /// Creates the production driver using the process-wide router.
    pub fn new(http_port: u16) -> Self {
        Self { router: shared(), http_port }
    }

    #[cfg(test)]
    pub(super) fn isolated(http_port: u16) -> Self {
        Self { router: Arc::new(LocalRouter::new()), http_port }
    }
}

#[async_trait]
impl TunnelDriver for LocalDriver {
    fn name(&self) -> &'static str {
        "local"
    }

    fn capabilities(&self) -> DriverCapabilities {
        DriverCapabilities::default()
    }

    fn validate(&self, spec: &EndpointSpec) -> Result<(), DriverError> {
        if spec.proto != ServiceProto::Http {
            return Err(DriverError::Capability("local driver is HTTP-only".to_owned()));
        }
        if spec.qualifier.is_some() || spec.remote.is_some() || spec.domain.is_some() {
            return Err(DriverError::Capability(
                "local endpoints do not accept qualifiers, remotes, or domains".to_owned(),
            ));
        }
        if spec.public_port.is_some() {
            return Err(DriverError::Capability(
                "local endpoints use defaults.local_http_port, not public_port".to_owned(),
            ));
        }
        if spec.persist == Persistence::Persistent {
            return Err(DriverError::Capability("local endpoints cannot be persistent".to_owned()));
        }
        if !spec.host.as_deref().is_some_and(valid_hostname) {
            return Err(DriverError::Capability(
                "local endpoints require a valid lowercase hostname".to_owned(),
            ));
        }
        Ok(())
    }

    async fn check(&self) -> DriverHealth {
        DriverHealth::Healthy
    }

    async fn run(
        &self,
        spec: EndpointSpec,
        target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
    ) -> Result<(), DriverError> {
        self.validate(&spec)?;
        let hostname = spec.host.as_deref().expect("validated local hostname");
        let registration = self.router.register(self.http_port, hostname, target.0).await?;
        let listener_port = registration
            .listener_address()
            .await
            .ok_or_else(|| DriverError::Transport("local listener disappeared".to_owned()))?
            .port();
        let url = local_url(hostname, listener_port);
        if events
            .send(DriverEvent::Ready { urls: vec![url], bind_id: None, reservation: None })
            .await
            .is_err()
        {
            registration.close().await;
            return Err(DriverError::Cancelled);
        }
        stop.cancelled().await;
        registration.close().await;
        Ok(())
    }
}

fn local_url(hostname: &str, port: u16) -> String {
    if port == 80 { format!("http://{hostname}") } else { format!("http://{hostname}:{port}") }
}

fn valid_hostname(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
                })
        })
}

#[cfg(test)]
#[path = "local_tests.rs"]
mod tests;
