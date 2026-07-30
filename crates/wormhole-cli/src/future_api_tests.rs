use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use axum::{
    extract::{Path, Query, State},
    response::IntoResponse as _,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use wormhole_core::{
    CapturedRequest, ClientConfig, EndpointSpec, Service, Target, TunnelManager,
    driver::DriverRegistry,
    keys_store::IdentityStore,
    model::{CapturedHeader, ServiceProto},
};

use super::{
    RequestQuery, clear_requests, is_redacted, replay, replay_to, request, requests, target_address,
};
use crate::{
    api_types::ApiState,
    capture_store::CaptureStore,
    mock_driver::MockDriver,
    state_db::{DesiredKey, DesiredService, StateDb},
};

#[tokio::test]
async fn request_routes_filter_lookup_validate_and_clear() {
    let state = test_state();
    let endpoint = Uuid::now_v7();
    let first = capture(endpoint, "/first");
    let second = capture(endpoint, "/second");
    state.captures.write().await.insert(endpoint, first.clone());
    state.captures.write().await.insert(endpoint, second.clone());

    let listed = requests(
        State(state.clone()),
        Query(RequestQuery { endpoint: Some(endpoint), limit: Some(1), since: None }),
    )
    .await
    .expect("list captures");
    assert_eq!(listed.0, vec![second.clone()]);
    let found = request(State(state.clone()), Path(first.id)).await.expect("capture");
    assert_eq!(found.0, first);

    let invalid = requests(
        State(state.clone()),
        Query(RequestQuery { endpoint: None, limit: None, since: Some("not-a-time".to_owned()) }),
    )
    .await
    .expect_err("invalid timestamp");
    assert_eq!(invalid.into_response().status(), axum::http::StatusCode::BAD_REQUEST);
    let missing =
        request(State(state.clone()), Path(Uuid::now_v7())).await.expect_err("missing capture");
    assert_eq!(missing.into_response().status(), axum::http::StatusCode::NOT_FOUND);

    assert!(clear_requests(State(state.clone())).await.0.closed);
    assert!(state.captures.read().await.list(None, None, 10).is_empty());
    state.manager.shutdown().await;
}

#[tokio::test]
async fn replay_rejects_unusable_capture_and_stale_lifecycle_state() {
    let state = test_state();
    let endpoint = Uuid::now_v7();

    let missing =
        replay(State(state.clone()), Path(Uuid::now_v7())).await.expect_err("missing capture");
    assert_eq!(missing.into_response().status(), axum::http::StatusCode::NOT_FOUND);

    let mut truncated = capture(endpoint, "/truncated");
    truncated.body_truncated = true;
    state.captures.write().await.insert(endpoint, truncated.clone());
    let rejected =
        replay(State(state.clone()), Path(truncated.id)).await.expect_err("truncated capture");
    assert_eq!(rejected.into_response().status(), axum::http::StatusCode::BAD_REQUEST);

    let inactive_capture = capture(endpoint, "/stale");
    state.captures.write().await.insert(endpoint, inactive_capture.clone());
    let inactive = replay(State(state.clone()), Path(inactive_capture.id))
        .await
        .expect_err("inactive endpoint");
    assert_eq!(inactive.into_response().status(), axum::http::StatusCode::NOT_FOUND);

    let key = DesiredKey::new("project".to_owned(), "web".to_owned()).expect("key");
    state.bindings.write().await.insert(endpoint, (key, 0));
    let absent =
        replay(State(state.clone()), Path(inactive_capture.id)).await.expect_err("absent service");
    assert_eq!(absent.into_response().status(), axum::http::StatusCode::NOT_FOUND);
    state.manager.shutdown().await;
}

#[tokio::test]
async fn replay_forwards_safe_headers_and_body_to_active_target() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let port = listener.local_addr().expect("address").port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut bytes = vec![0; 4096];
        let read = stream.read(&mut bytes).await.expect("request");
        bytes.truncate(read);
        stream
            .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .expect("response");
        bytes
    });

    let state = test_state();
    let endpoint = Uuid::now_v7();
    let key = DesiredKey::new("project".to_owned(), "web".to_owned()).expect("key");
    let desired = desired_service(port);
    state.desired.write().await.insert(key.clone(), desired);
    state.bindings.write().await.insert(endpoint, (key, 0));
    let mut captured = capture(endpoint, "/replay?source=test");
    captured.body = b"payload".to_vec();
    captured.headers = vec![
        header("x-safe", b"visible"),
        header("authorization", b"secret"),
        CapturedHeader { name: "bad header".to_owned(), value_b64: STANDARD.encode(b"ignored") },
        CapturedHeader { name: "x-bad-base64".to_owned(), value_b64: "%%%".to_owned() },
    ];
    state.captures.write().await.insert(endpoint, captured.clone());

    let response = replay(State(state.clone()), Path(captured.id)).await.expect("replay");
    assert_eq!(response.0.status, 201);
    let request = String::from_utf8_lossy(&server.await.expect("server task")).to_ascii_lowercase();
    assert!(request.contains("post /replay?source=test"));
    assert!(request.contains("x-safe: visible"));
    assert!(request.contains("payload"));
    assert!(!request.contains("authorization"));
    assert!(!request.contains("secret"));
    state.manager.shutdown().await;
}

#[tokio::test]
async fn replay_rejects_invalid_captured_http_method() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let address = listener.local_addr().expect("address");
    let accepted = tokio::spawn(async move { listener.accept().await.expect("accept") });
    let mut captured = capture(Uuid::now_v7(), "/invalid");
    captured.method = "bad method".to_owned();
    let error = replay_to(address, &captured).await.expect_err("invalid method");
    assert_eq!(error.into_response().status(), axum::http::StatusCode::BAD_REQUEST);
    drop(accepted.await.expect("accept task"));
}

#[tokio::test]
async fn target_resolution_covers_port_host_and_configured_interface_aliases() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let port = listener.local_addr().expect("address").port();
    assert_eq!(
        target_address(&Target::Port(port), BTreeMap::new()).await.expect("port").port(),
        port
    );
    assert_eq!(
        target_address(&Target::HostPort("localhost".to_owned(), port), BTreeMap::new())
            .await
            .expect("host")
            .port(),
        port
    );
    let aliases = BTreeMap::from([("local-test".to_owned(), "127.0.0.1".to_owned())]);
    assert_eq!(
        target_address(&Target::Iface { alias: "local-test".to_owned(), port }, aliases)
            .await
            .expect("interface"),
        listener.local_addr().expect("address")
    );
    assert!(
        target_address(&Target::HostPort("invalid host".to_owned(), port), BTreeMap::new())
            .await
            .is_err()
    );
    for name in ["authorization", "Cookie", "SET-COOKIE", "X-Api-Key"] {
        assert!(is_redacted(name));
    }
    assert!(!is_redacted("content-type"));
}

fn test_state() -> ApiState {
    let directory = tempfile::tempdir().expect("tempdir").keep();
    let path = camino::Utf8PathBuf::from_path_buf(directory).expect("utf8");
    let registry = DriverRegistry::new();
    registry.register(Arc::new(MockDriver));
    let config = ClientConfig::default();
    ApiState {
        manager: Arc::new(TunnelManager::new(Arc::new(registry), config.clone())),
        config: Arc::new(RwLock::new(config)),
        config_path: None,
        identities: Arc::new(IdentityStore::with_home(path.clone())),
        database: Arc::new(StateDb::open(&path).expect("database")),
        desired: Arc::new(RwLock::new(BTreeMap::new())),
        bindings: Arc::new(RwLock::new(HashMap::new())),
        persistence_lock: Arc::new(Mutex::new(())),
        mutation_lock: Arc::new(Mutex::new(())),
        expose_lock: Arc::new(Mutex::new(())),
        captures: Arc::new(RwLock::new(CaptureStore::default())),
        started: jiff::Timestamp::now(),
        shutdown: CancellationToken::new(),
        token: Arc::from("test"),
    }
}

fn desired_service(port: u16) -> DesiredService {
    DesiredService {
        active: true,
        project_id: "project".to_owned(),
        remotes: None,
        default_remote: None,
        service: Service {
            name: "web".to_owned(),
            target: Target::Port(port),
            proto: ServiceProto::Http,
        },
        endpoints: Vec::<EndpointSpec>::new(),
        disabled_endpoints: Vec::new(),
    }
}

fn capture(endpoint: Uuid, uri: &str) -> CapturedRequest {
    CapturedRequest {
        id: Uuid::now_v7(),
        endpoint_id: Some(endpoint),
        bind_id: Uuid::nil(),
        method: "POST".to_owned(),
        uri: uri.to_owned(),
        headers: Vec::new(),
        body: Vec::new(),
        body_truncated: false,
        response_status: Some(200),
        response_headers: Vec::new(),
        response_body_prefix: Vec::new(),
        response_body_truncated: false,
        duration_ms: 1,
        delivery: "live".to_owned(),
        captured_at: "2026-01-01T00:00:00Z".parse().expect("timestamp"),
    }
}

fn header(name: &str, value: &[u8]) -> CapturedHeader {
    CapturedHeader { name: name.to_owned(), value_b64: STANDARD.encode(value) }
}
