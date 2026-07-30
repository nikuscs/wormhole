//! Debug-build-only deterministic driver used by CLI integration tests.

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wormhole_core::{
    DriverError, DriverEvent, DriverHealth, TunnelDriver,
    driver::DriverCapabilities,
    model::{EndpointSpec, ResolvedTarget},
};

pub struct MockDriver;

#[async_trait]
impl TunnelDriver for MockDriver {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn capabilities(&self) -> DriverCapabilities {
        DriverCapabilities::all()
    }

    async fn check(&self) -> DriverHealth {
        DriverHealth::Healthy
    }

    async fn run(
        &self,
        spec: EndpointSpec,
        _target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
    ) -> Result<(), DriverError> {
        let label = spec.host.unwrap_or_else(|| "endpoint".to_owned());
        let reservation = (spec.persist == wormhole_proto::frames::Persistence::Persistent)
            .then(uuid::Uuid::now_v7);
        events
            .send(DriverEvent::Ready {
                urls: vec![format!("https://{label}.mock.invalid")],
                bind_id: None,
                reservation,
            })
            .await
            .map_err(|_| DriverError::Cancelled)?;
        if reservation.is_some() {
            let barrier = std::sync::Arc::new(tokio::sync::Notify::new());
            events
                .send(DriverEvent::Handoff(std::sync::Arc::clone(&barrier)))
                .await
                .map_err(|_| DriverError::Cancelled)?;
            barrier.notified().await;
        }
        stop.cancelled().await;
        let _closed = events.send(DriverEvent::Closed).await;
        Ok(())
    }
}
