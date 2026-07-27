use jiff::Timestamp;
use uuid::Uuid;
use wormhole_proto::frames::{BufferPolicy, Persistence};

use crate::{
    buffer::BufferedRequest,
    db::{BufferQuotas, PersistedBind, PersistedBindSpec, PersistedEndpoint, RelayDb},
};

fn request(body: &[u8]) -> BufferedRequest {
    BufferedRequest {
        v: 1,
        method: "POST".to_owned(),
        uri: "/hook".to_owned(),
        http_version: "HTTP/1.1".to_owned(),
        headers: Vec::new(),
        body: body.to_vec(),
        seq: 0,
        received_at: Timestamp::now(),
    }
}

const fn quotas(max_requests: u32, ttl_secs: u64, bytes: u64) -> BufferQuotas {
    BufferQuotas { max_requests, ttl_secs, key_bytes: bytes, total_bytes: bytes }
}

fn database() -> (tempfile::TempDir, RelayDb, Uuid) {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = camino::Utf8Path::from_path(directory.path()).expect("utf8");
    let database = RelayDb::open(path).expect("database");
    let bind = Uuid::now_v7();
    let now = Timestamp::now();
    database
        .put_bind(
            bind,
            &PersistedBind {
                reservation: Uuid::now_v7(),
                spec: PersistedBindSpec::Http {
                    host: Some("hook".to_owned()),
                    domain: Some("example.com".to_owned()),
                    persist: Persistence::Persistent,
                    buffer: Some(BufferPolicy {
                        max_requests: 2,
                        max_body_bytes: 1024,
                        ttl_secs: 60,
                    }),
                },
                auth_verifier: None,
                endpoint: PersistedEndpoint::Hostname("hook.example.com".to_owned()),
                key_fpr: "WH256:test".to_owned(),
                created: now,
                last_seen: now,
            },
        )
        .expect("bind");
    (directory, database, bind)
}

#[test]
fn durable_queue_orders_rejects_and_quarantines() {
    let (_directory, database, bind) = database();
    let first = database
        .enqueue_buffered(bind, "WH256:test", request(b"one"), quotas(2, 60, 16_384))
        .expect("first");
    let second = database
        .enqueue_buffered(bind, "WH256:test", request(b"two"), quotas(2, 60, 16_384))
        .expect("second");
    assert_eq!((first, second), (1, 2));
    assert!(
        database
            .enqueue_buffered(bind, "WH256:test", request(b"three"), quotas(2, 60, 16_384))
            .is_err()
    );
    assert_eq!(database.first_buffered(bind).expect("first read").expect("row").body, b"one");
    database.fail_buffered(bind, first, &"😀".repeat(1024)).expect("quarantine");
    assert_eq!(database.list_failed().expect("failed")[0].2.reason.chars().count(), 512);
    assert_eq!(database.buffered_counts(bind).expect("counts"), (1, 1));
    assert_eq!(database.first_buffered(bind).expect("second read").expect("row").seq, second);
    database.delete_buffered(bind, second).expect("ack second");
    let third = database
        .enqueue_buffered(bind, "WH256:test", request(b"three"), quotas(2, 60, 16_384))
        .expect("third after drain");
    assert_eq!(third, 3);
    database.retry_failed(bind, first).expect("retry first");
    assert_eq!(database.buffered_counts(bind).expect("counts"), (2, 0));
    assert_eq!(database.first_buffered(bind).expect("first").expect("retried").seq, first);
    database.delete_buffered(bind, first).expect("ack retried");
    assert_eq!(database.first_buffered(bind).expect("third").expect("new").seq, third);
}

#[test]
fn expired_rows_are_pruned_before_quota_checks() {
    let (_directory, database, bind) = database();
    let mut expired = request(b"old");
    expired.received_at =
        Timestamp::from_second(Timestamp::now().as_second() - 2).expect("old timestamp");
    database
        .enqueue_buffered(bind, "WH256:test", expired, quotas(1, 1, 16_384))
        .expect("expired row");
    database
        .enqueue_buffered(bind, "WH256:test", request(b"new"), quotas(1, 1, 16_384))
        .expect("replacement");
    assert_eq!(database.buffered_counts(bind).expect("counts"), (1, 0));
}

#[test]
fn byte_quota_is_checked_before_commit() {
    let (_directory, database, bind) = database();
    assert!(
        database
            .enqueue_buffered(bind, "WH256:test", request(&[1; 512]), quotas(10, 60, 8))
            .is_err()
    );
    assert_eq!(database.buffered_counts(bind).expect("counts"), (0, 0));
}
