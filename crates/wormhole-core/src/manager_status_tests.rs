use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use wormhole_proto::frames::{BufferPolicy, Persistence};

use super::{apply_ready_urls, preflight_driver, validate_capabilities};
use crate::{
    driver::{DriverCapabilities, DriverEvent, DriverHealth, TunnelDriver},
    error::DriverError,
    model::{ActiveEndpoint, EndpointSpec, EndpointStatus, ResolvedTarget, ServiceProto},
};

struct Unhealthy;

#[async_trait]
impl TunnelDriver for Unhealthy {
    fn name(&self) -> &'static str {
        "unhealthy"
    }
    async fn check(&self) -> DriverHealth {
        DriverHealth::Unavailable("offline".to_owned())
    }
    async fn run(
        &self,
        _spec: EndpointSpec,
        _target: ResolvedTarget,
        _events: mpsc::Sender<DriverEvent>,
        _stop: CancellationToken,
    ) -> Result<(), DriverError> {
        Ok(())
    }
}

#[tokio::test]
async fn partial_preflight_wraps_unavailable_driver() {
    assert!(preflight_driver(Arc::new(Unhealthy), false).await.is_err());
    let driver = preflight_driver(Arc::new(Unhealthy), true).await.expect("partial");
    assert_eq!(driver.name(), "unavailable");
    assert_eq!(driver.check().await, DriverHealth::Healthy);
    let (events, _) = mpsc::channel(1);
    let error = driver
        .run(
            spec(),
            ResolvedTarget("127.0.0.1:1".parse().expect("target")),
            events,
            CancellationToken::new(),
        )
        .await
        .expect_err("unavailable");
    assert!(matches!(error, DriverError::Unavailable(_)));
}

#[test]
fn capability_validation_and_ready_url_application_cover_edge_cases() {
    let mut endpoint = spec();
    endpoint.buffer = Some(BufferPolicy { max_requests: 1, max_body_bytes: 1, ttl_secs: 1 });
    assert!(validate_capabilities(&endpoint, DriverCapabilities::all()).is_err());
    endpoint.persist = Persistence::Persistent;
    endpoint.proto = ServiceProto::Tcp;
    assert!(validate_capabilities(&endpoint, DriverCapabilities::all()).is_err());

    let id = Uuid::now_v7();
    let endpoints = RwLock::new(HashMap::from([(
        id,
        ActiveEndpoint {
            id,
            service: "app".to_owned(),
            driver: "mock".to_owned(),
            urls: Vec::new(),
            status: EndpointStatus::Online,
            buffered_delivered: 0,
            buffered_pending: 0,
            buffered_failed: 0,
            since: jiff::Timestamp::now(),
        },
    )]));
    apply_ready_urls(
        &endpoints,
        id,
        &DriverEvent::Ready {
            urls: vec!["https://ready".to_owned()],
            bind_id: None,
            reservation: None,
        },
    );
    assert_eq!(endpoints.read()[&id].urls, ["https://ready"]);
}

fn spec() -> EndpointSpec {
    EndpointSpec {
        proto: ServiceProto::Http,
        driver: "mock".to_owned(),
        qualifier: None,
        remote: None,
        host: None,
        auto_host: false,
        domain: None,
        public_port: None,
        persist: Persistence::Temporary,
        buffer: None,
        auth: None,
        retry: None,
        inspect: false,
        inspect_assets: false,
        capture_body_max: 1024,
        reservation: None,
    }
}
