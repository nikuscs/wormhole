use uuid::Uuid;
use wormhole_core::{CapturedRequest, model::CapturedHeader};

use super::{CaptureStore, ENDPOINT_LIMIT, GLOBAL_BYTES};

#[test]
fn insert_bounds_each_endpoint_and_lists_newest_first() {
    let first_endpoint = Uuid::now_v7();
    let second_endpoint = Uuid::now_v7();
    let mut store = CaptureStore::default();
    for index in 0..=ENDPOINT_LIMIT {
        store.insert(first_endpoint, capture(index, first_endpoint, 1));
    }
    store.insert(second_endpoint, capture(100, second_endpoint, 1));

    let first = store.list(Some(first_endpoint), None, usize::MAX);
    assert_eq!(first.len(), ENDPOINT_LIMIT);
    assert_eq!(first.first().expect("newest").uri, format!("/{ENDPOINT_LIMIT}"));
    assert_eq!(first.last().expect("oldest retained").uri, "/1");
    assert_eq!(store.list(None, None, 3).len(), 3);
    assert_eq!(store.get(first[4].id).expect("stored capture"), first[4]);
}

#[test]
fn filters_by_time_and_clear_resets_accounting() {
    let endpoint = Uuid::now_v7();
    let mut store = CaptureStore::default();
    store.insert(endpoint, capture(1, endpoint, 8));
    store.insert(endpoint, capture(2, endpoint, 8));
    let threshold = timestamp(1);

    let recent = store.list(None, Some(threshold), 10);
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].uri, "/2");

    store.clear();
    assert!(store.list(None, None, 10).is_empty());
    assert_eq!(store.bytes, 0);
}

#[test]
fn global_budget_evicts_oldest_and_rejects_oversized_capture() {
    let endpoint = Uuid::now_v7();
    let mut store = CaptureStore::default();
    let body_size = GLOBAL_BYTES / 2;
    let first = capture(1, endpoint, body_size);
    let first_id = first.id;
    store.insert(endpoint, first);
    store.insert(endpoint, capture(2, endpoint, body_size));

    assert!(store.get(first_id).is_none(), "oldest capture should be evicted");
    assert_eq!(store.list(None, None, 10).len(), 1);

    store.insert(endpoint, capture(3, endpoint, GLOBAL_BYTES));
    assert!(store.list(None, None, 10).is_empty(), "oversized capture is not retained");
}

fn capture(index: usize, endpoint: Uuid, body_size: usize) -> CapturedRequest {
    CapturedRequest {
        id: Uuid::now_v7(),
        endpoint_id: Some(endpoint),
        bind_id: Uuid::nil(),
        method: "POST".to_owned(),
        uri: format!("/{index}"),
        headers: vec![CapturedHeader {
            name: "content-type".to_owned(),
            value_b64: "dGV4dA==".to_owned(),
        }],
        body: vec![0; body_size],
        body_truncated: false,
        response_status: Some(200),
        response_headers: Vec::new(),
        response_body_prefix: Vec::new(),
        response_body_truncated: false,
        duration_ms: 1,
        delivery: "live".to_owned(),
        captured_at: timestamp(index),
    }
}

fn timestamp(offset: usize) -> jiff::Timestamp {
    let minute = offset / 60;
    let second = offset % 60;
    format!("2026-01-01T00:{minute:02}:{second:02}Z").parse().expect("timestamp")
}
