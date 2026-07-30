use super::{MAX_BIND_CACHE, Runtime};
use crate::storage::BindRow;

fn bind(index: usize) -> BindRow {
    BindRow {
        bind_id: format!("bind-{index}"),
        reservation: Some(format!("reservation-{index}")),
        fingerprint: format!("fingerprint-{}", index % 2),
        hostname: format!("host-{index}.example.com"),
        persistent: 1,
        connection_id: Some(format!("connection-{}", index % 3)),
        state: "online".to_owned(),
        basic_hmac: None,
        bearer_hmac: None,
        link_hmac_key: None,
    }
}

#[test]
fn bind_cache_is_bounded() {
    let mut runtime = Runtime::default();
    for index in 0..=MAX_BIND_CACHE {
        runtime.cache_bind(&bind(index));
    }
    assert_eq!(runtime.binds.len(), 1);
    assert!(runtime.binds.contains_key(&format!("host-{MAX_BIND_CACHE}.example.com")));
}

#[test]
fn bind_cache_invalidates_all_lifecycle_keys() {
    let mut runtime = Runtime::default();
    for index in 0..6 {
        runtime.cache_bind(&bind(index));
    }

    runtime.invalidate_bind("bind-0");
    runtime.invalidate_reservation("reservation-1");
    runtime.invalidate_connection("connection-2");
    runtime.invalidate_fingerprint("fingerprint-1");

    assert!(runtime.binds.values().all(|row| {
        row.bind_id != "bind-0"
            && row.reservation.as_deref() != Some("reservation-1")
            && row.connection_id.as_deref() != Some("connection-2")
            && row.fingerprint != "fingerprint-1"
    }));
}
