use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wormhole_proto::frames::{BufferPolicy, Persistence};

use super::TunnelManager;
use crate::{
    config::ClientConfig,
    driver::{DriverCapabilities, DriverEvent, DriverHealth, DriverRegistry, TunnelDriver},
    error::DriverError,
    model::{EndpointSpec, EndpointStatus, ResolvedTarget, Service, ServiceProto, Target},
};

struct MockDriver;

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
        if spec.qualifier.as_deref() == Some("error") {
            return Err(DriverError::Transport("mock failure".to_owned()));
        }
        events
            .send(DriverEvent::Ready {
                urls: vec![format!("https://{}.example", spec.host.as_deref().unwrap_or("random"))],
                bind_id: None,
                reservation: None,
            })
            .await
            .map_err(|_| DriverError::Cancelled)?;
        stop.cancelled().await;
        Ok(())
    }
}

fn spec(host: &str) -> EndpointSpec {
    EndpointSpec {
        proto: ServiceProto::Http,
        driver: "mock".to_owned(),
        qualifier: None,
        remote: None,
        host: Some(host.to_owned()),
        domain: None,
        public_port: None,
        persist: Persistence::Temporary,
        buffer: None,
        auth: None,
        retry: None,
        inspect: false,
        reservation: None,
    }
}

fn manager() -> TunnelManager {
    let registry = DriverRegistry::new();
    registry.register(Arc::new(MockDriver));
    TunnelManager::new(Arc::new(registry), ClientConfig::default())
}

#[tokio::test]
async fn sibling_endpoints_are_independent_and_errors_surface() {
    let manager = manager();
    let mut driver_events = manager.take_driver_events().await.expect("driver events");
    let service =
        Service { name: "app".to_owned(), target: Target::Port(4321), proto: ServiceProto::Http };
    let ids = manager
        .expose(service.clone(), vec![spec("one"), spec("two"), spec("three")])
        .await
        .expect("expose endpoints");
    wait_for_status(&manager, EndpointStatus::Online, 3).await;
    let event = driver_events.recv().await.expect("driver event");
    assert!(matches!(event.event, DriverEvent::Ready { .. }));
    assert_eq!(manager.list().iter().filter(|endpoint| endpoint.urls.len() == 1).count(), 3);

    manager.close(ids[0]).await.expect("close one");
    assert_eq!(
        manager.list().iter().filter(|endpoint| endpoint.status == EndpointStatus::Online).count(),
        2
    );

    let mut failing = spec("failure");
    failing.qualifier = Some("error".to_owned());
    let error_id = manager.expose(service, vec![failing]).await.expect("spawn failing")[0];
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(matches!(
        manager
            .list()
            .into_iter()
            .find(|endpoint| endpoint.id == error_id)
            .map(|endpoint| endpoint.status),
        Some(EndpointStatus::Error(_))
    ));
    manager.shutdown().await;
}

#[tokio::test]
async fn mismatched_endpoint_protocol_is_rejected() {
    let manager = manager();
    let service =
        Service { name: "app".to_owned(), target: Target::Port(3000), proto: ServiceProto::Http };
    let mut endpoint = spec("app");
    endpoint.proto = ServiceProto::Tcp;

    let error = manager.expose(service, vec![endpoint]).await.expect_err("mismatch rejected");

    assert!(error.to_string().contains("does not match"));
}

#[tokio::test]
async fn tcp_service_rejects_http_only_options_even_when_driver_supports_them() {
    let manager = manager();
    let service = Service {
        name: "database".to_owned(),
        target: Target::Port(5432),
        proto: ServiceProto::Tcp,
    };
    let mut endpoint = spec("database");
    endpoint.proto = ServiceProto::Tcp;
    endpoint.buffer = Some(BufferPolicy { max_requests: 1, max_body_bytes: 1024, ttl_secs: 60 });

    let error = manager.expose(service, vec![endpoint]).await.expect_err("TCP buffer rejected");

    assert!(error.to_string().contains("buffer"));
}

async fn wait_for_status(manager: &TunnelManager, status: EndpointStatus, count: usize) {
    for _ in 0..50 {
        if manager.list().iter().filter(|endpoint| endpoint.status == status).count() == count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("status did not converge");
}
