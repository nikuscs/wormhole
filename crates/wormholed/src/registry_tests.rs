use std::sync::Arc;

use jiff::Timestamp;
use tempfile::tempdir;
use tokio::sync::mpsc;
use wormhole_proto::frames::{BindSpec, BufferPolicy, Persistence};

use super::{AllocationRequest, BindState, HostKey, Registry, RegistryError, SessionCommand};
use crate::{
    config::PortRange,
    db::{PersistedBind, PersistedBindSpec, PersistedEndpoint, RelayDb},
};

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
            auto_host: false,
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
    assert!(matches!(
        registry.allocate(reclaim_request("owner", reservation)),
        Err(RegistryError::InvalidState { state: BindState::Pending, .. })
    ));
    let (other, _receiver) = mpsc::channel(1);
    assert!(matches!(
        registry.activate(allocation.bind, &other),
        Err(RegistryError::SessionOwnerMismatch(bind)) if bind == allocation.bind
    ));
    let session = registry.get_bind(allocation.bind).expect("bind").session().expect("session");
    registry.activate(allocation.bind, &session).expect("pending bind must activate");
    assert!(matches!(
        registry.allocate(reclaim_request("owner", reservation)),
        Err(RegistryError::AlreadyOnline(bind)) if bind == allocation.bind
    ));
}

#[test]
fn temporary_http_bind_rejects_buffer_policy() {
    let registry = registry();
    let mut request = http_request("owner", Some("demo"), None);
    request.spec = BindSpec::Http {
        host: Some("demo".to_owned()),
        auto_host: false,
        domain: None,
        persist: Persistence::Temporary,
        buffer: Some(BufferPolicy { max_requests: 1, max_body_bytes: 1024, ttl_secs: 60 }),
        auth: None,
    };
    assert!(matches!(registry.allocate(request), Err(RegistryError::TemporaryBufferPolicy)));
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

#[test]
fn invalid_http_labels_and_tcp_ports_are_rejected() {
    let registry = registry();
    for label in ["", "UPPER", "-leading", "trailing-", "has.dot"] {
        assert!(matches!(
            registry.allocate(http_request("owner", Some(label), None)),
            Err(RegistryError::InvalidHostname(_))
        ));
    }
    assert!(matches!(
        registry.allocate(tcp_request("owner", Some(9_999))),
        Err(RegistryError::PortOutsideRange(9_999))
    ));

    let first = registry.allocate(tcp_request("owner", Some(10_000))).expect("port");
    assert!(matches!(
        registry.allocate(tcp_request("other", Some(10_000))),
        Err(RegistryError::Conflict(HostKey::TcpPort(10_000)))
    ));
    assert_eq!(registry.tcp_routes()[0].0, 10_000);
    assert!(registry.remove(first.bind, false).is_ok());
    assert!(matches!(registry.remove(first.bind, false), Err(RegistryError::UnknownBind(_))));
}

#[tokio::test]
async fn shutdown_notifies_each_session_once_and_queries_are_stable() {
    let registry = registry();
    let (session_tx, mut session_rx) = mpsc::channel(4);
    let request = |host: &str| AllocationRequest {
        key_fpr: "owner".to_owned(),
        spec: BindSpec::Http {
            host: Some(host.to_owned()),
            auto_host: false,
            domain: None,
            persist: Persistence::Persistent,
            buffer: None,
            auth: None,
        },
        reservation: None,
        session_tx: session_tx.clone(),
    };
    registry.allocate(request("one")).expect("one");
    registry.allocate(request("two")).expect("two");

    assert_eq!(registry.len(), 2);
    assert!(!registry.is_empty());
    assert!(registry.is_domain("tun.example.com"));
    assert!(!registry.is_domain("other.example.com"));
    assert_eq!(registry.routes().len(), 2);
    registry.shutdown_sessions();
    assert!(matches!(session_rx.recv().await, Some(SessionCommand::Shutdown)));
    assert!(session_rx.try_recv().is_err());
}

#[test]
fn preload_restores_offline_routes_and_reservations() {
    let directory = tempdir().expect("temporary directory");
    let path = camino::Utf8Path::from_path(directory.path()).expect("UTF-8");
    let database = RelayDb::open(path).expect("database");
    let now = Timestamp::now();
    let bind = uuid::Uuid::now_v7();
    let reservation = uuid::Uuid::now_v7();
    database
        .put_bind(
            bind,
            &PersistedBind {
                reservation,
                spec: PersistedBindSpec::Tcp {
                    remote_port: Some(10_001),
                    persist: Persistence::Persistent,
                },
                auth_verifier: None,
                endpoint: PersistedEndpoint::TcpPort(10_001),
                key_fpr: "owner".to_owned(),
                created: now,
                last_seen: now,
            },
        )
        .expect("persist bind");
    let registry = registry();

    assert_eq!(registry.preload(&database).expect("preload"), 1);
    let handle = registry.get_bind(bind).expect("restored bind");
    assert_eq!(handle.state(), BindState::Offline);
    assert_eq!(registry.bind_for_reservation(reservation), Some(bind));
    assert_eq!(registry.tcp_routes()[0].0, 10_001);

    let mut wrong_kind = http_request("owner", Some("demo"), None);
    wrong_kind.reservation = Some(reservation);
    assert!(matches!(registry.allocate(wrong_kind), Err(RegistryError::ReservationKindMismatch)));
    registry.remove(bind, false).expect("remove route only");
    assert_eq!(registry.bind_for_reservation(reservation), Some(bind));
}

#[test]
fn persistent_disconnects_but_temporary_disconnect_removes() {
    let registry = Arc::new(registry());
    let persistent =
        registry.allocate(http_request("owner", Some("persistent"), None)).expect("persistent");
    registry.disconnect(persistent.bind).expect("disconnect persistent");
    assert_eq!(registry.get_bind(persistent.bind).expect("retained").state(), BindState::Offline);

    let temporary = registry.allocate(tcp_request("owner", None)).expect("temporary");
    registry.disconnect(temporary.bind).expect("disconnect temporary");
    assert!(registry.get_bind(temporary.bind).is_none());
}
