use base64::Engine as _;
use jiff::Timestamp;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;
use uuid::Uuid;
use wormhole_proto::frames::{BindSpec, BufferPolicy, EdgeAuth, Persistence};

use super::{deliver, drain, durable_headers, sanitized_cookie, sanitized_uri};
use crate::{
    authz::{AuthStore, KeyLimits},
    buffer::BufferedRequest,
    config::{LimitsConfig, PortRange},
    db::{BufferQuotas, PersistedBind, PersistedBindSpec, PersistedEndpoint, RelayDb},
    edge_tcp::TcpEdgeManager,
    registry::{AllocationRequest, BindHandle, HttpTunnelResponse, Registry, SessionCommand},
    state::AppState,
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
fn durable_request_strips_relay_credentials() {
    let registry = Registry::new(
        vec!["example.com".to_owned()],
        None,
        443,
        PortRange { start: 10_000, end: 10_001 },
    );
    let (session_tx, _session_rx) = mpsc::channel(1);
    let allocation = registry
        .allocate(AllocationRequest {
            key_fpr: "WH256:test".to_owned(),
            spec: BindSpec::Http {
                host: Some("hook".to_owned()),
                auto_host: false,
                domain: None,
                persist: Persistence::Persistent,
                buffer: Some(BufferPolicy { max_requests: 1, max_body_bytes: 1024, ttl_secs: 60 }),
                auth: Some(EdgeAuth {
                    basic: None,
                    bearer: Some("secret".to_owned()),
                    link_key: None,
                }),
            },
            reservation: None,
            session_tx,
        })
        .expect("allocation");
    let handle = registry.get_bind(allocation.bind).expect("handle");
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::AUTHORIZATION, "Bearer secret".parse().expect("auth"));
    headers
        .insert(http::header::COOKIE, "theme=dark; wormhole_auth=token".parse().expect("cookie"));

    let durable = durable_headers(&headers, &handle);

    assert_eq!(durable.len(), 1);
    assert_eq!(durable[0].name, "cookie");
    assert_eq!(
        base64::engine::general_purpose::STANDARD.decode(&durable[0].value_b64).expect("cookie"),
        b"theme=dark"
    );
    assert_eq!(
        sanitized_uri(&"/hook?wh_token=secret&event=push".parse().expect("URI")),
        "/hook?event=push"
    );
    assert!(sanitized_cookie(&"wormhole_auth=secret".parse().expect("cookie")).is_none());
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

fn delivery_handle() -> (Arc<BindHandle>, mpsc::Receiver<SessionCommand>) {
    let registry = Registry::new(
        vec!["example.com".to_owned()],
        None,
        443,
        PortRange { start: 10_000, end: 10_001 },
    );
    let (session_tx, session_rx) = mpsc::channel(2);
    let allocation = registry
        .allocate(AllocationRequest {
            key_fpr: "WH256:test".to_owned(),
            spec: BindSpec::Http {
                host: Some("hook".to_owned()),
                auto_host: false,
                domain: None,
                persist: Persistence::Persistent,
                buffer: Some(BufferPolicy { max_requests: 2, max_body_bytes: 1024, ttl_secs: 60 }),
                auth: None,
            },
            reservation: None,
            session_tx: session_tx.clone(),
        })
        .expect("allocation");
    registry.activate(allocation.bind, &session_tx).expect("activate");
    (registry.get_bind(allocation.bind).expect("handle"), session_rx)
}

#[tokio::test]
async fn durable_delivery_preserves_request_and_waits_for_response_body() {
    let (handle, mut session_rx) = delivery_handle();
    let mut buffered = request(b"event payload");
    buffered.seq = 42;
    buffered.uri = "/hook?event=push".to_owned();
    let delivery = tokio::spawn({
        let handle = Arc::clone(&handle);
        async move { deliver(&handle, &buffered).await }
    });
    let SessionCommand::OpenHttp { header, mut body, reply, .. } =
        session_rx.recv().await.expect("delivery command")
    else {
        panic!("expected HTTP delivery");
    };
    let wormhole_proto::frames::StreamHeader::Http { buffered, request, .. } = header else {
        panic!("expected HTTP header");
    };
    assert_eq!(buffered, Some(42));
    assert_eq!(request.uri, "/hook?event=push");
    assert_eq!(body.recv().await.expect("body").expect("body chunk"), b"event payload"[..]);
    assert!(body.recv().await.is_none());
    let (response_tx, response_rx) = mpsc::channel(1);
    response_tx.send(Ok(Bytes::from_static(b"accepted"))).await.expect("response body");
    drop(response_tx);
    reply
        .send(Ok(HttpTunnelResponse {
            head: wormhole_proto::frames::HttpResponseHead {
                status: 202,
                version: "HTTP/1.1".to_owned(),
                headers: Vec::new(),
            },
            body: response_rx,
            upgrade: None,
        }))
        .expect("delivery reply");
    delivery.await.expect("delivery task").expect("delivery success");
}

#[tokio::test]
async fn durable_delivery_reports_closed_session_and_body_failure() {
    let (handle, session_rx) = delivery_handle();
    drop(session_rx);
    assert!(matches!(
        deliver(&handle, &request(b"event")).await,
        Err(super::BufferError::Unavailable)
    ));

    let (handle, mut session_rx) = delivery_handle();
    let delivery = tokio::spawn({
        let handle = Arc::clone(&handle);
        async move { deliver(&handle, &request(b"event")).await }
    });
    let SessionCommand::OpenHttp { reply, .. } = session_rx.recv().await.expect("command") else {
        panic!("expected HTTP delivery");
    };
    let (response_tx, response_rx) = mpsc::channel(1);
    response_tx.send(Err("target reset".to_owned())).await.expect("response error");
    drop(response_tx);
    reply
        .send(Ok(HttpTunnelResponse {
            head: wormhole_proto::frames::HttpResponseHead {
                status: 500,
                version: "HTTP/1.1".to_owned(),
                headers: Vec::new(),
            },
            body: response_rx,
            upgrade: None,
        }))
        .expect("delivery reply");
    assert!(matches!(
        delivery.await.expect("delivery task"),
        Err(super::BufferError::Body(message)) if message == "target reset"
    ));
}

#[test]
fn failed_rows_retry_delete_and_missing_transitions_are_atomic() {
    let (_directory, database, bind) = database();
    let seq = database
        .enqueue_buffered(bind, "WH256:test", request(b"payload"), quotas(4, 60, 16_384))
        .expect("enqueue");
    assert!(database.fail_buffered(bind, 999, "missing").is_err());
    database.fail_buffered(bind, seq, "target failed").expect("fail");

    let failed = database.list_failed().expect("failed rows");
    assert_eq!((failed[0].0, failed[0].1), (bind, seq));
    assert!(!database.retry_failed(bind, 999).expect("missing retry"));
    assert!(database.retry_failed(bind, seq).expect("retry"));
    assert!(database.list_failed().expect("failed rows").is_empty());
    database.fail_buffered(bind, seq, "again").expect("fail again");
    assert!(!database.delete_failed(bind, 999).expect("missing delete"));
    assert!(database.delete_failed(bind, seq).expect("delete"));
    assert!(database.list_failed().expect("failed rows").is_empty());
}

#[test]
fn deleting_bind_data_removes_active_failed_sequence_and_bind() {
    let (_directory, database, bind) = database();
    let first = database
        .enqueue_buffered(bind, "WH256:test", request(b"one"), quotas(4, 60, 16_384))
        .expect("first");
    let second = database
        .enqueue_buffered(bind, "WH256:test", request(b"two"), quotas(4, 60, 16_384))
        .expect("second");
    database.fail_buffered(bind, first, "failed").expect("fail first");

    database.delete_bind_data(bind).expect("delete bind data");

    assert!(database.get_bind(bind).expect("get bind").is_none());
    assert_eq!(database.buffered_counts(bind).expect("counts"), (0, 0));
    assert!(database.list_failed().expect("failed").is_empty());
    assert!(!database.delete_buffered(bind, second).expect("missing active row"));
}

#[test]
fn prune_all_expired_covers_active_failed_and_unbuffered_binds() {
    let (_directory, database, bind) = database();
    let mut old = request(b"old");
    old.received_at =
        Timestamp::from_second(Timestamp::now().as_second() - 10).expect("old timestamp");
    let active = database
        .enqueue_buffered(bind, "WH256:test", old.clone(), quotas(4, 60, 16_384))
        .expect("active");
    let failed =
        database.enqueue_buffered(bind, "WH256:test", old, quotas(4, 60, 16_384)).expect("failed");
    database.fail_buffered(bind, failed, "failed").expect("quarantine");
    assert_eq!(database.buffered_counts(bind).expect("before"), (1, 1));

    database.prune_expired(bind, 1).expect("prune bind");
    assert_eq!(database.buffered_counts(bind).expect("after"), (0, 0));
    assert!(!database.delete_buffered(bind, active).expect("expired active row"));
    database.prune_all_expired().expect("prune all");
}

#[test]
fn durable_header_sanitization_preserves_safe_values() {
    let registry = Registry::new(
        vec!["example.com".to_owned()],
        None,
        443,
        PortRange { start: 10_000, end: 10_001 },
    );
    let (session_tx, _session_rx) = mpsc::channel(1);
    let allocation = registry
        .allocate(AllocationRequest {
            key_fpr: "WH256:test".to_owned(),
            spec: BindSpec::Http {
                host: Some("hook".to_owned()),
                auto_host: false,
                domain: None,
                persist: Persistence::Persistent,
                buffer: None,
                auth: None,
            },
            reservation: None,
            session_tx,
        })
        .expect("allocation");
    let handle = registry.get_bind(allocation.bind).expect("handle");
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::AUTHORIZATION, "Bearer client".parse().expect("authorization"));
    headers.insert(http::header::COOKIE, "theme=dark".parse().expect("cookie"));
    headers.insert("x-event", "push".parse().expect("event"));

    let durable = durable_headers(&headers, &handle);
    assert_eq!(durable.len(), 3);
    assert_eq!(sanitized_uri(&"/hook?wh_token=only".parse().expect("URI")), "/hook");
    assert_eq!(sanitized_uri(&"/hook".parse().expect("URI")), "/hook");
    assert!(sanitized_cookie(&http::HeaderValue::from_bytes(b"\xff").expect("opaque")).is_none());
}

fn drain_fixture() -> (
    tempfile::TempDir,
    Arc<AppState>,
    Arc<BindHandle>,
    mpsc::Sender<SessionCommand>,
    mpsc::Receiver<SessionCommand>,
) {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = camino::Utf8Path::from_path(directory.path()).expect("UTF-8");
    let database = Arc::new(RelayDb::open(path).expect("database"));
    let limits = LimitsConfig::default();
    let auth = Arc::new(AuthStore::new(Arc::clone(&database), KeyLimits::from(&limits)));
    let registry = Arc::new(Registry::new(
        vec!["example.com".to_owned()],
        None,
        443,
        PortRange { start: 10_000, end: 10_001 },
    ));
    let (session_tx, session_rx) = mpsc::channel(2);
    let allocation = registry
        .allocate(AllocationRequest {
            key_fpr: "WH256:test".to_owned(),
            spec: BindSpec::Http {
                host: Some("hook".to_owned()),
                auto_host: false,
                domain: None,
                persist: Persistence::Persistent,
                buffer: Some(BufferPolicy { max_requests: 4, max_body_bytes: 1024, ttl_secs: 60 }),
                auth: None,
            },
            reservation: None,
            session_tx: session_tx.clone(),
        })
        .expect("allocation");
    let handle = registry.get_bind(allocation.bind).expect("handle");
    let now = Timestamp::now();
    database
        .put_bind(
            allocation.bind,
            &PersistedBind {
                reservation: allocation.reservation.expect("reservation"),
                spec: handle.spec.clone(),
                auth_verifier: None,
                endpoint: handle.endpoint.clone(),
                key_fpr: handle.key_fpr.clone(),
                created: now,
                last_seen: now,
            },
        )
        .expect("persist bind");
    let state = Arc::new(
        AppState::new(
            registry,
            database,
            Arc::new(TcpEdgeManager::new("127.0.0.1".parse().expect("IP"))),
            auth,
            limits,
        )
        .expect("state"),
    );
    (directory, state, handle, session_tx, session_rx)
}

#[tokio::test]
async fn drain_respects_state_claims_and_delivers_one_request() {
    let (_directory, state, handle, session_tx, mut session_rx) = drain_fixture();
    drain(&state, &handle).await.expect("offline drain");
    state.registry.activate(handle.bind_id, &session_tx).expect("activate");
    drain(&state, &handle).await.expect("empty drain");

    let seq = state
        .database
        .enqueue_buffered(handle.bind_id, &handle.key_fpr, request(b"payload"), quotas(4, 60, 4096))
        .expect("enqueue");
    assert!(state.claim_buffered(handle.bind_id, seq));
    drain(&state, &handle).await.expect("already claimed");
    assert!(session_rx.try_recv().is_err());
    state.release_buffered_bind(handle.bind_id);

    let delivery = tokio::spawn({
        let state = Arc::clone(&state);
        let handle = Arc::clone(&handle);
        async move { drain(&state, &handle).await }
    });
    let SessionCommand::OpenHttp { reply, .. } = session_rx.recv().await.expect("delivery") else {
        panic!("expected HTTP delivery");
    };
    let (response_tx, response_rx) = mpsc::channel(1);
    drop(response_tx);
    reply
        .send(Ok(HttpTunnelResponse {
            head: wormhole_proto::frames::HttpResponseHead {
                status: 204,
                version: "HTTP/1.1".to_owned(),
                headers: Vec::new(),
            },
            body: response_rx,
            upgrade: None,
        }))
        .expect("response");
    delivery.await.expect("delivery task").expect("drain");
    assert!(!state.claim_buffered(handle.bind_id, seq));
}
