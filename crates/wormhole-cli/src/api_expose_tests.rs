use wormhole_core::{
    ActiveEndpoint, EndpointSpec,
    model::{EndpointStatus, ServiceProto},
};
use wormhole_proto::frames::{EdgeAuth, Persistence};

use super::{failure_message, restore_reservations};

#[test]
fn failure_message_preserves_provider_diagnostics_or_supplies_timeout_context() {
    let failures = vec![
        active(EndpointStatus::Error("cloudflare unavailable".to_owned())),
        active(EndpointStatus::Offline),
        active(EndpointStatus::Error("relay denied".to_owned())),
    ];
    assert_eq!(failure_message(&failures), "cloudflare unavailable; relay denied");
    assert!(failure_message(&[active(EndpointStatus::Offline)]).contains("startup timeout"));
}

#[test]
fn reservation_restore_matches_equivalent_specs_without_reusing_candidates() {
    let first_reservation = uuid::Uuid::now_v7();
    let second_reservation = uuid::Uuid::now_v7();
    let mut first = spec("one");
    first.auth = Some(EdgeAuth {
        basic: None,
        bearer: None,
        link_key: Some("new-generated-key".to_owned()),
    });
    let second = spec("two");
    let mut cached_first = first.clone();
    cached_first.reservation = Some(first_reservation);
    cached_first.auth.as_mut().expect("auth").link_key = Some("cached-link-key".to_owned());
    let mut cached_second = second.clone();
    cached_second.reservation = Some(second_reservation);
    let mut requested = vec![second, first];

    assert!(restore_reservations(&mut requested, &[cached_first, cached_second]).is_empty());
    assert_eq!(requested[0].reservation, Some(second_reservation));
    assert_eq!(requested[1].reservation, Some(first_reservation));
    assert_eq!(
        requested[1].auth.as_ref().and_then(|auth| auth.link_key.as_deref()),
        Some("cached-link-key")
    );
}

#[test]
fn reservation_restore_reports_unmatched_cached_persistence() {
    let reservation = uuid::Uuid::now_v7();
    let mut cached = spec("old");
    cached.reservation = Some(reservation);
    let mut requested = vec![spec("new")];

    let orphans = restore_reservations(&mut requested, &[cached]);

    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].reservation, Some(reservation));
    assert_eq!(requested[0].reservation, None);
}

fn spec(host: &str) -> EndpointSpec {
    EndpointSpec {
        proto: ServiceProto::Http,
        driver: "mock".to_owned(),
        qualifier: None,
        remote: None,
        host: Some(host.to_owned()),
        auto_host: false,
        domain: None,
        public_port: None,
        persist: Persistence::Persistent,
        buffer: None,
        auth: None,
        retry: None,
        inspect: true,
        inspect_assets: false,
        capture_body_max: 1024,
        reservation: None,
    }
}

fn active(status: EndpointStatus) -> ActiveEndpoint {
    ActiveEndpoint {
        id: uuid::Uuid::now_v7(),
        service: "web".to_owned(),
        driver: "mock".to_owned(),
        urls: Vec::new(),
        status,
        buffered_delivered: 0,
        buffered_pending: 0,
        buffered_failed: 0,
        since: "2026-01-01T00:00:00Z".parse().expect("timestamp"),
    }
}
