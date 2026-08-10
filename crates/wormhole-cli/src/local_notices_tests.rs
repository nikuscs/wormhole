use wormhole_core::{ActiveEndpoint, ClientConfig, EndpointSpec, model::ServiceProto};
use wormhole_proto::frames::Persistence;

use super::{annotate_active, apply, detect};

#[test]
fn custom_tld_notices_are_structured_and_managed_hosts_suppress_hints() {
    let mut config = ClientConfig::default();
    config.defaults.local_tld = "test".to_owned();
    let specs = vec![local_spec("app.test")];
    let notices = detect(&specs, None, &config, &[]);
    assert_eq!(notices.hints, ["wormhole local hosts sync app.test"]);
    let mut endpoints = vec![local_endpoint()];
    apply(&mut endpoints, &notices);
    assert_eq!(endpoints[0].hints, ["wormhole local hosts sync app.test"]);
    assert!(serde_json::to_string(&endpoints).expect("JSON").contains("hosts sync app.test"));
    assert!(crate::output::HumanRender::render(&endpoints).contains("hint: wormhole local"));

    let managed = detect(&specs, None, &config, &["app.test".to_owned()]);
    assert!(managed.hints.is_empty());
    let localhost = detect(&specs, Some("localhost"), &config, &[]);
    assert!(localhost.hints.is_empty());
    config.defaults.local_tld = "local".to_owned();
    let warning = detect(&specs, None, &config, &[]);
    assert!(warning.warnings[0].contains("mDNS/Bonjour"));
}

#[test]
fn listing_recomputes_hints_from_live_endpoint_urls() {
    let mut endpoints = vec![local_endpoint()];
    annotate_active(&mut endpoints, &[]);
    assert_eq!(endpoints[0].hints, ["wormhole local hosts sync app.test"]);
    assert!(serde_json::to_string(&endpoints).expect("JSON").contains("hosts sync app.test"));

    annotate_active(&mut endpoints, &["app.test".to_owned()]);
    assert!(endpoints[0].hints.is_empty(), "a synced host needs no hint");

    let mut localhost = vec![local_endpoint()];
    localhost[0].urls = vec!["http://app.localhost:20080".to_owned()];
    annotate_active(&mut localhost, &[]);
    assert!(localhost[0].hints.is_empty(), ".localhost never needs a hosts entry");

    let mut mdns = vec![local_endpoint()];
    mdns[0].urls = vec!["https://app.local:20443".to_owned()];
    annotate_active(&mut mdns, &[]);
    assert!(mdns[0].warnings[0].contains("mDNS/Bonjour"));

    let mut other = vec![local_endpoint()];
    other[0].driver = "wormhole".to_owned();
    annotate_active(&mut other, &[]);
    assert!(other[0].hints.is_empty(), "only local endpoints are annotated");
}

fn local_spec(hostname: &str) -> EndpointSpec {
    EndpointSpec {
        proto: ServiceProto::Http,
        driver: "local".to_owned(),
        qualifier: None,
        remote: None,
        host: Some(hostname.to_owned()),
        auto_host: true,
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

fn local_endpoint() -> ActiveEndpoint {
    ActiveEndpoint {
        id: uuid::Uuid::now_v7(),
        service: "web".to_owned(),
        driver: "local".to_owned(),
        urls: vec!["https://app.test".to_owned()],
        hints: Vec::new(),
        warnings: Vec::new(),
        status: wormhole_core::model::EndpointStatus::Online,
        buffered_delivered: 0,
        buffered_pending: 0,
        buffered_failed: 0,
        since: jiff::Timestamp::now(),
    }
}
