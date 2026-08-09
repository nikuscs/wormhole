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
    let urls = run_driver(false).await;
    assert!(urls[0].starts_with("https://app.localhost:"));
    assert!(urls[1].starts_with("http://app.localhost:"));
}

#[tokio::test]
async fn elevation_marker_advertises_portless_urls() {
    let urls = run_driver(true).await;
    assert_eq!(urls, ["https://app.localhost", "http://app.localhost"]);
}

async fn run_driver(portless: bool) -> Vec<String> {
    let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("target");
    let target = ResolvedTarget(target_listener.local_addr().expect("target address"));
    let directory = tempfile::tempdir().expect("CA directory");
    let ca_directory = camino::Utf8PathBuf::from_path_buf(directory.path().to_owned())
        .expect("UTF-8 CA directory");
    if portless {
        crate::local_system::write_elevation_marker(&ca_directory).expect("elevation marker");
    }
    let driver = Arc::new(LocalDriver::isolated(0, 0, ca_directory));
    let (events, mut receiver) = mpsc::channel(4);
    let stop = CancellationToken::new();
    let task = tokio::spawn({
        let driver = Arc::clone(&driver);
        let stop = stop.clone();
        async move { driver.run(spec(), target, events, stop).await }
    });
    let event = receiver.recv().await.expect("ready event");
    let DriverEvent::Ready { urls, .. } = event else { panic!("expected ready event") };
    stop.cancel();
    task.await.expect("driver task").expect("driver cleanup");
    drop(target_listener);
    urls
}

#[test]
fn local_driver_rejects_tcp_missing_hosts_and_persistence() {
    let driver = LocalDriver::isolated(0, 0, camino::Utf8PathBuf::from("."));
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
