use super::{adoptable, cutoff_from_ttl};
use crate::storage::BindRow;

fn bind(state: &str, connection: Option<&str>) -> BindRow {
    BindRow {
        bind_id: "bind".to_owned(),
        reservation: Some("reservation".to_owned()),
        fingerprint: "owner".to_owned(),
        hostname: "app.example.com".to_owned(),
        persistent: 1,
        connection_id: connection.map(str::to_owned),
        state: state.to_owned(),
        basic_hmac: None,
        bearer_hmac: None,
        link_hmac_key: None,
    }
}

#[test]
fn a_dormant_hostname_returns_to_its_owner() {
    assert!(adoptable(&bind("offline", None), "owner", |_| false));
    assert!(adoptable(&bind("pending", Some("gone")), "owner", |_| false));
}

#[test]
fn a_hostname_still_being_served_is_not_taken() {
    assert!(!adoptable(&bind("online", Some("live")), "owner", |connection| connection == "live"));
}

#[test]
fn a_hostname_left_online_by_a_vanished_connection_is_reclaimed() {
    // Without this an evicted object or killed process owns the label forever: the row claims to be
    // online, so nothing may take it, and no live connection remains to release it.
    assert!(adoptable(&bind("online", Some("vanished")), "owner", |connection| connection
        == "someone-else"));
    assert!(adoptable(&bind("online", None), "owner", |_| true));
}

#[test]
fn another_client_never_loses_its_hostname() {
    assert!(!adoptable(&bind("offline", None), "stranger", |_| false));
    assert!(!adoptable(&bind("online", Some("vanished")), "stranger", |_| false));
}

#[test]
fn an_unused_reservation_ages_out_after_the_configured_window() {
    const DAY: i64 = 24 * 60 * 60;
    let now = 1_000_000;

    assert_eq!(cutoff_from_ttl(DAY, now), Some(now - DAY));
    assert_eq!(cutoff_from_ttl(60, now), Some(now - 60));
}

#[test]
fn a_non_positive_window_keeps_reservations_forever() {
    // Operators who never want a URL to expire set 0; the sweep must then not run at all rather
    // than compute a cutoff of "now" and delete every offline bind.
    assert_eq!(cutoff_from_ttl(0, 1_000_000), None);
    assert_eq!(cutoff_from_ttl(-1, 1_000_000), None);
}
