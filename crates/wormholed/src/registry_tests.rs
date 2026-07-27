use tokio::sync::mpsc;
use wormhole_proto::frames::{BindSpec, Persistence};

use super::{AllocationRequest, BindState, HostKey, Registry, RegistryError};
use crate::config::PortRange;

fn registry() -> Registry {
    Registry::new(
        vec!["tun.example.com".to_owned(), "work.example.com".to_owned()],
        None,
        8443,
        PortRange { start: 10_000, end: 10_001 },
    )
}

fn http_request(owner: &str, host: Option<&str>, domain: Option<&str>) -> AllocationRequest {
    let (session_tx, _session_rx) = mpsc::channel(4);
    AllocationRequest {
        key_fpr: owner.to_owned(),
        spec: BindSpec::Http {
            host: host.map(str::to_owned),
            domain: domain.map(str::to_owned),
            persist: Persistence::Persistent,
            buffer: None,
            auth: None,
        },
        reservation: None,
        session_tx,
    }
}

fn tcp_request(owner: &str, port: Option<u16>) -> AllocationRequest {
    let (session_tx, _session_rx) = mpsc::channel(4);
    AllocationRequest {
        key_fpr: owner.to_owned(),
        spec: BindSpec::Tcp { remote_port: port, persist: Persistence::Temporary },
        reservation: None,
        session_tx,
    }
}

fn reclaim_request(owner: &str, reservation: uuid::Uuid) -> AllocationRequest {
    let mut request = http_request(owner, Some("ignored"), None);
    request.reservation = Some(reservation);
    request
}

#[test]
fn requested_hostname_conflicts_and_cannot_reclaim_by_name() {
    let registry = registry();
    let allocation = registry
        .allocate(http_request("owner", Some("demo"), None))
        .expect("first hostname must allocate");
    registry.disconnect(allocation.bind).expect("persistent bind must disconnect");

    let error = registry
        .allocate(http_request("owner", Some("demo"), None))
        .expect_err("hostname alone must not reclaim");

    assert!(matches!(error, RegistryError::Conflict(HostKey::Hostname(_))));
}

#[test]
fn reservation_reclaims_same_offline_endpoint_for_owner() {
    let registry = registry();
    let original = registry
        .allocate(http_request("owner", None, None))
        .expect("random hostname must allocate");
    let reservation = original.reservation.expect("persistent bind has reservation");
    registry.disconnect(original.bind).expect("persistent bind must disconnect");

    let reclaimed =
        registry.allocate(reclaim_request("owner", reservation)).expect("owner must reclaim");

    assert_eq!(reclaimed.bind, original.bind);
    assert_eq!(reclaimed.urls, original.urls);
    let hostname = original.urls[0]
        .strip_prefix("https://")
        .and_then(|value| value.strip_suffix(":8443"))
        .expect("generated URL authority");
    let handle = registry.get(&HostKey::Hostname(hostname.to_owned())).expect("route must remain");
    assert_eq!(handle.state(), BindState::Pending);
}

#[test]
fn reservation_rejects_other_key_and_online_duplicate() {
    let registry = registry();
    let allocation = registry
        .allocate(http_request("owner", Some("demo"), None))
        .expect("hostname must allocate");
    let reservation = allocation.reservation.expect("persistent bind has reservation");

    assert!(matches!(
        registry.allocate(reclaim_request("attacker", reservation)),
        Err(RegistryError::ReservationOwnerMismatch)
    ));
    registry.activate(allocation.bind).expect("pending bind must activate");
    assert!(matches!(
        registry.allocate(reclaim_request("owner", reservation)),
        Err(RegistryError::AlreadyOnline(bind)) if bind == allocation.bind
    ));
}

#[test]
fn unknown_domain_is_rejected() {
    let registry = registry();

    let error = registry
        .allocate(http_request("owner", Some("demo"), Some("evil.example")))
        .expect_err("unknown domain must fail");

    assert!(matches!(error, RegistryError::UnknownDomain(domain) if domain == "evil.example"));
}

#[test]
fn tcp_range_allocates_lowest_free_then_exhausts() {
    let registry = registry();

    let first = registry.allocate(tcp_request("one", None)).expect("first port must allocate");
    let second = registry.allocate(tcp_request("two", None)).expect("second port must allocate");
    let exhausted = registry.allocate(tcp_request("three", None)).expect_err("range must exhaust");

    assert_eq!(first.urls, vec!["tcp://tun.example.com:10000"]);
    assert_eq!(second.urls, vec!["tcp://tun.example.com:10001"]);
    assert!(matches!(exhausted, RegistryError::PortRangeExhausted));
}

#[test]
fn generated_http_url_uses_actual_nonstandard_listener_port() {
    let registry = registry();

    let allocation = registry
        .allocate(http_request("owner", Some("demo"), Some("work.example.com")))
        .expect("hostname must allocate");

    assert_eq!(allocation.urls, vec!["https://demo.work.example.com:8443"]);
}
