use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wormhole_proto::frames::Persistence;

use super::LocalDriver;
use crate::{
    driver::{DriverEvent, TunnelDriver},
    model::{EndpointSpec, ResolvedTarget, ServiceProto},
};

#[tokio::test]
async fn local_driver_registers_ready_url_and_cleans_up() {
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("target");
    let target = ResolvedTarget(target.local_addr().expect("target address"));
    let driver = Arc::new(LocalDriver::isolated(0));
    let (events, mut receiver) = mpsc::channel(4);
    let stop = CancellationToken::new();
    let task = tokio::spawn({
        let driver = Arc::clone(&driver);
        let stop = stop.clone();
        async move { driver.run(spec(), target, events, stop).await }
    });

    let event = receiver.recv().await.expect("ready event");
    let DriverEvent::Ready { urls, .. } = event else { panic!("expected ready event") };
    assert!(urls[0].starts_with("http://app.localhost:"));
    stop.cancel();
    task.await.expect("driver task").expect("driver cleanup");
}

#[test]
fn local_driver_rejects_tcp_missing_hosts_and_persistence() {
    let driver = LocalDriver::isolated(0);
    let mut endpoint = spec();
    endpoint.proto = ServiceProto::Tcp;
    assert!(driver.validate(&endpoint).is_err());

    endpoint = spec();
    endpoint.host = None;
    assert!(driver.validate(&endpoint).is_err());

    endpoint = spec();
    endpoint.persist = Persistence::Persistent;
    assert!(driver.validate(&endpoint).is_err());
}

fn spec() -> EndpointSpec {
    EndpointSpec {
        proto: ServiceProto::Http,
        driver: "local".to_owned(),
        qualifier: None,
        remote: None,
        host: Some("app.localhost".to_owned()),
        auto_host: true,
        domain: None,
        public_port: None,
        persist: Persistence::Temporary,
        buffer: None,
        auth: None,
        retry: None,
        inspect: false,
        inspect_assets: false,
        capture_body_max: 1024 * 1024,
        reservation: None,
    }
}
