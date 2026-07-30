use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener as StdUnixListener},
    path::PathBuf,
    sync::Arc,
};

use axum::{
    Json,
    extract::{Path as AxumPath, State},
};
use bytes::Bytes;
use jiff::Timestamp;
use tempfile::tempdir;
use tokio::sync::mpsc;
use utoipa::OpenApi;
use uuid::Uuid;
use wormhole_proto::{
    Identity,
    frames::{BindSpec, BufferPolicy, Persistence},
};

use super::{
    AdminApi, AdminError, AdminServer, AdminState, AuthorizeKeyRequest, authorize_key, list_keys,
    remove_stale_socket, revoke_key,
};
use crate::{
    buffer::BufferedRequest,
    db::{BufferQuotas, PersistedBind, PersistedBindSpec},
    registry::{AllocationRequest, SessionCommand},
};

#[test]
fn stale_socket_cleanup_refuses_regular_files() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("admin.sock");
    fs::write(&path, b"do not remove").expect("regular file");
    assert!(matches!(remove_stale_socket(&path), Err(AdminError::UnsafeSocket(_))));
    assert_eq!(fs::read(path).expect("preserved file"), b"do not remove");
}

#[test]
fn stale_unix_socket_is_removed() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("admin.sock");
    let listener = StdUnixListener::bind(&path).expect("socket");
    drop(listener);
    remove_stale_socket(&path).expect("stale socket removed");
    assert!(!path.exists());
}

#[test]
fn openapi_never_exposes_secret_verifier_fields() {
    let json = serde_json::to_string_pretty(&AdminApi::openapi()).expect("openapi JSON");
    for forbidden in ["reservation", "basic_argon2", "bearer_sha256", "link_hmac_key"] {
        assert!(!json.contains(forbidden), "OpenAPI exposed {forbidden}");
    }
    assert!(json.contains("/v1/status"));
    assert!(json.contains("/v1/binds/{id}"));
}

#[test]
fn admin_client_rejects_unsuccessful_mutations() {
    let response = crate::admin_client::AdminResponse {
        status: http::StatusCode::NOT_FOUND,
        body: Bytes::from_static(b"missing"),
    };
    let error = response.require_success().expect_err("404 must fail");
    assert!(error.to_string().contains("404 Not Found"));
}

#[test]
fn committed_openapi_is_current() {
    let json =
        format!("{}\n", serde_json::to_string_pretty(&AdminApi::openapi()).expect("OpenAPI JSON"));
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/admin-api.openapi.json");
    if std::env::var_os("UPDATE_OPENAPI").is_some() {
        fs::write(&path, &json).expect("write OpenAPI snapshot");
    }
    assert_eq!(fs::read_to_string(path).expect("committed OpenAPI"), json);
}

async fn admin_state_fixture() -> (
    tempfile::TempDir,
    crate::config::WormholedConfig,
    Arc<crate::state::AppState>,
    Arc<crate::certs::CertManager>,
) {
    let directory = tempdir().expect("temporary directory");
    let root = camino::Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let config_path = root.join("wormholed.toml");
    crate::config::WormholedConfig::initialize(&config_path).expect("initialize config");
    let config = crate::config::WormholedConfig::load(&config_path).expect("load config");
    let database = Arc::new(crate::db::RelayDb::open(&config.server.data_dir).expect("database"));
    let auth = Arc::new(crate::authz::AuthStore::new(
        Arc::clone(&database),
        crate::authz::KeyLimits::from(&config.limits),
    ));
    let registry = Arc::new(crate::registry::Registry::new(
        config.server.domains.clone(),
        config.server.public_https_port,
        443,
        config.tcp.port_range,
    ));
    let tcp = Arc::new(crate::edge_tcp::TcpEdgeManager::new(config.server.https_addr.ip()));
    let state = Arc::new(
        crate::state::AppState::new(registry, database, tcp, auth, config.limits.clone())
            .expect("state"),
    );
    let certificates = Arc::new(crate::certs::CertManager::ready(&config).await.expect("certs"));
    (directory, config, state, certificates)
}

#[tokio::test]
async fn key_mutations_validate_persist_list_and_revoke() {
    let (_directory, _config, state, certificates) = admin_state_fixture().await;
    let admin = AdminState { state, certificates };
    let public = wormhole_proto::Identity::generate().public_base64();
    let (status, Json(created)) = authorize_key(
        State(admin.clone()),
        Json(AuthorizeKeyRequest { public_key: public, name: "relay agent".to_owned() }),
    )
    .await
    .expect("authorize");
    assert_eq!(status, http::StatusCode::CREATED);
    let Json(keys) = list_keys(State(admin.clone())).await.expect("list keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].fingerprint, created.fingerprint);
    assert_eq!(keys[0].name, "relay agent");
    assert!(!keys[0].revoked);

    assert_eq!(
        revoke_key(State(admin.clone()), AxumPath(created.fingerprint.clone()))
            .await
            .expect("revoke"),
        http::StatusCode::NO_CONTENT
    );
    let Json(keys) = list_keys(State(admin)).await.expect("list revoked keys");
    assert!(keys[0].revoked);
}

#[tokio::test]
async fn invalid_key_mutation_is_a_bad_request() {
    let (_directory, _config, state, certificates) = admin_state_fixture().await;
    let error = authorize_key(
        State(AdminState { state, certificates }),
        Json(AuthorizeKeyRequest {
            public_key: "not-a-public-key".to_owned(),
            name: "invalid".to_owned(),
        }),
    )
    .await
    .expect_err("invalid key");
    assert_eq!(error.0, http::StatusCode::BAD_REQUEST);
    assert!(!error.1.0.error.is_empty());
}

#[tokio::test]
async fn unix_socket_is_private_and_serves_status() {
    let (_directory, config, state, certificates) = admin_state_fixture().await;
    assert!(state.try_open_session("WH256:test", 1));
    let _stream = state.track_stream();
    let server = AdminServer::bind(&config.server.data_dir, Arc::clone(&state), certificates)
        .expect("admin");
    let socket = config.server.data_dir.join("admin.sock");
    assert_eq!(fs::metadata(&socket).expect("socket metadata").permissions().mode() & 0o777, 0o600);
    let task = tokio::spawn(server.run());
    let response = crate::admin_client::request::<serde_json::Value>(
        socket.as_std_path(),
        http::Method::GET,
        "/v1/status",
        None,
    )
    .await
    .expect("status request");
    assert_eq!(response.status, http::StatusCode::OK);
    let status: super::StatusResponse =
        serde_json::from_slice(&response.body).expect("status response");
    assert_eq!(status.sessions, 1);
    assert_eq!(status.streams, 1);
    assert_eq!(status.binds, 0);
    let mut shutdown = state.subscribe_shutdown();
    state.begin_shutdown();
    shutdown.changed().await.expect("shutdown notification");
    assert!(*shutdown.borrow());
    task.abort();
    let _cancelled = task.await;
}

async fn running_admin_fixture() -> (
    tempfile::TempDir,
    camino::Utf8PathBuf,
    Arc<crate::state::AppState>,
    tokio::task::JoinHandle<Result<(), AdminError>>,
) {
    let directory = tempdir().expect("temporary directory");
    let root = camino::Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let config_path = root.join("wormholed.toml");
    crate::config::WormholedConfig::initialize(&config_path).expect("initialize config");
    let config = crate::config::WormholedConfig::load(&config_path).expect("load config");
    let database = Arc::new(crate::db::RelayDb::open(&config.server.data_dir).expect("database"));
    let auth = Arc::new(crate::authz::AuthStore::new(
        Arc::clone(&database),
        crate::authz::KeyLimits::from(&config.limits),
    ));
    let registry = Arc::new(crate::registry::Registry::new(
        config.server.domains.clone(),
        config.server.public_https_port,
        443,
        config.tcp.port_range,
    ));
    let tcp = Arc::new(crate::edge_tcp::TcpEdgeManager::new(config.server.https_addr.ip()));
    let state = Arc::new(
        crate::state::AppState::new(registry, database, tcp, auth, config.limits.clone())
            .expect("state"),
    );
    let certificates = Arc::new(crate::certs::CertManager::ready(&config).await.expect("certs"));
    let server = AdminServer::bind(&config.server.data_dir, Arc::clone(&state), certificates)
        .expect("admin");
    let socket = config.server.data_dir.join("admin.sock");
    let task = tokio::spawn(server.run());
    (directory, socket, state, task)
}

async fn request(
    socket: &camino::Utf8Path,
    method: http::Method,
    path: &str,
) -> crate::admin_client::AdminResponse {
    crate::admin_client::request::<serde_json::Value>(socket.as_std_path(), method, path, None)
        .await
        .expect("admin request")
}

fn buffered_request() -> BufferedRequest {
    BufferedRequest {
        v: 1,
        method: "POST".to_owned(),
        uri: "/hook".to_owned(),
        http_version: "HTTP/1.1".to_owned(),
        headers: Vec::new(),
        body: b"payload".to_vec(),
        seq: 0,
        received_at: Timestamp::now(),
    }
}

#[tokio::test]
async fn admin_key_and_bind_endpoints_cover_success_validation_and_acknowledgement() {
    let (_directory, socket, state, task) = running_admin_fixture().await;
    let identity = Identity::generate();
    let authorize = super::AuthorizeKeyRequest {
        public_key: identity.public_base64(),
        name: "agent".to_owned(),
    };
    let response = crate::admin_client::request(
        socket.as_std_path(),
        http::Method::POST,
        "/v1/keys",
        Some(&authorize),
    )
    .await
    .expect("authorize");
    assert_eq!(response.status, http::StatusCode::CREATED);
    let fingerprint: super::KeyFingerprint =
        serde_json::from_slice(&response.body).expect("fingerprint");
    let keys = request(&socket, http::Method::GET, "/v1/keys").await;
    assert_eq!(keys.status, http::StatusCode::OK);
    assert!(String::from_utf8_lossy(&keys.body).contains("agent"));
    let invalid = crate::admin_client::request(
        socket.as_std_path(),
        http::Method::POST,
        "/v1/keys",
        Some(&super::AuthorizeKeyRequest {
            public_key: "invalid".to_owned(),
            name: "bad".to_owned(),
        }),
    )
    .await
    .expect("invalid key");
    assert_eq!(invalid.status, http::StatusCode::BAD_REQUEST);

    let (session_tx, mut session_rx) = mpsc::channel(4);
    let allocation = state
        .registry
        .allocate(AllocationRequest {
            key_fpr: fingerprint.fingerprint.clone(),
            spec: BindSpec::Http {
                host: Some("admin".to_owned()),
                auto_host: false,
                domain: None,
                persist: Persistence::Persistent,
                buffer: None,
                auth: None,
            },
            reservation: None,
            session_tx,
        })
        .expect("bind");
    assert!(state.try_add_bind(&fingerprint.fingerprint, 2));
    let binds = request(&socket, http::Method::GET, "/v1/binds").await;
    assert_eq!(binds.status, http::StatusCode::OK);
    assert!(String::from_utf8_lossy(&binds.body).contains("pending"));

    let delete_socket = socket.clone();
    let delete = tokio::spawn(async move {
        request(&delete_socket, http::Method::DELETE, &format!("/v1/binds/{}", allocation.bind))
            .await
    });
    let Some(SessionCommand::RemoveBind { bind, acknowledged }) = session_rx.recv().await else {
        panic!("remove command");
    };
    assert_eq!(bind, allocation.bind);
    acknowledged.send(false).expect("negative acknowledgement");
    assert_eq!(delete.await.expect("delete task").status, http::StatusCode::NO_CONTENT);
    assert!(state.registry.get_bind(allocation.bind).is_none());
    assert_eq!(state.counts(&fingerprint.fingerprint).1, 0);

    let missing =
        request(&socket, http::Method::DELETE, &format!("/v1/binds/{}", Uuid::now_v7())).await;
    assert_eq!(missing.status, http::StatusCode::NOT_FOUND);
    let revoke = request(
        &socket,
        http::Method::DELETE,
        &format!("/v1/keys/{}", crate::admin_client::encoded_path(&fingerprint.fingerprint)),
    )
    .await;
    assert_eq!(revoke.status, http::StatusCode::NO_CONTENT);
    task.abort();
    let _cancelled = task.await;
}

#[tokio::test]
async fn invite_endpoints_create_list_without_secret_and_revoke() {
    let (_directory, socket, _state, task) = running_admin_fixture().await;
    let created = crate::admin_client::request(
        socket.as_std_path(),
        http::Method::POST,
        "/v1/invites",
        Some(&super::CreateInviteRequest {
            name: "personal devices".to_owned(),
            ttl_secs: None,
            max_uses: None,
        }),
    )
    .await
    .expect("create invite");
    assert_eq!(created.status, http::StatusCode::CREATED);
    let created: super::CreatedInviteResponse =
        serde_json::from_slice(&created.body).expect("created response");
    assert!(created.token.starts_with("whi_"));

    let listed = request(&socket, http::Method::GET, "/v1/invites").await;
    assert_eq!(listed.status, http::StatusCode::OK);
    let body = String::from_utf8_lossy(&listed.body);
    assert!(body.contains("personal devices"));
    assert!(!body.contains(&created.token));
    assert!(!body.contains("secret_sha256"));

    let revoked = request(
        &socket,
        http::Method::DELETE,
        &format!("/v1/invites/{}", crate::admin_client::encoded_path(&created.id)),
    )
    .await;
    assert_eq!(revoked.status, http::StatusCode::NO_CONTENT);
    let listed = request(&socket, http::Method::GET, "/v1/invites").await;
    let invites: Vec<super::InviteResponse> =
        serde_json::from_slice(&listed.body).expect("invite list");
    assert!(invites[0].revoked);

    task.abort();
    let _cancelled = task.await;
}

fn failed_webhook_fixture(
    state: &Arc<crate::state::AppState>,
) -> (Uuid, u64, mpsc::Receiver<SessionCommand>) {
    let (session_tx, session_rx) = mpsc::channel(8);
    let allocation = state
        .registry
        .allocate(AllocationRequest {
            key_fpr: "owner".to_owned(),
            spec: BindSpec::Http {
                host: Some("hook".to_owned()),
                auto_host: false,
                domain: None,
                persist: Persistence::Persistent,
                buffer: Some(BufferPolicy { max_requests: 4, max_body_bytes: 1024, ttl_secs: 60 }),
                auth: None,
            },
            reservation: None,
            session_tx,
        })
        .expect("bind");
    let handle = state.registry.get_bind(allocation.bind).expect("handle");
    let now = Timestamp::now();
    state
        .database
        .put_bind(
            allocation.bind,
            &PersistedBind {
                reservation: allocation.reservation.expect("reservation"),
                spec: PersistedBindSpec::Http {
                    host: Some("hook".to_owned()),
                    domain: Some("localtest.wormhole".to_owned()),
                    persist: Persistence::Persistent,
                    buffer: handle.buffer_policy.clone(),
                },
                auth_verifier: None,
                endpoint: handle.endpoint.clone(),
                key_fpr: "owner".to_owned(),
                created: now,
                last_seen: now,
            },
        )
        .expect("persist bind");
    let seq = state
        .database
        .enqueue_buffered(
            allocation.bind,
            "owner",
            buffered_request(),
            BufferQuotas { max_requests: 4, ttl_secs: 60, key_bytes: 4096, total_bytes: 4096 },
        )
        .expect("enqueue");
    state.database.fail_buffered(allocation.bind, seq, "delivery failed").expect("fail");
    (allocation.bind, seq, session_rx)
}

#[tokio::test]
async fn failed_webhook_endpoints_retry_delete_notify_and_report_missing_rows() {
    let (_directory, socket, state, task) = running_admin_fixture().await;
    let (bind_id, seq, mut session_rx) = failed_webhook_fixture(&state);
    let listed = request(&socket, http::Method::GET, "/v1/webhooks/failed").await;
    assert_eq!(listed.status, http::StatusCode::OK);
    assert!(String::from_utf8_lossy(&listed.body).contains("delivery failed"));

    let retry_socket = socket.clone();
    let retry = tokio::spawn(async move {
        request(
            &retry_socket,
            http::Method::POST,
            &format!("/v1/webhooks/failed/{bind_id}/{seq}/retry"),
        )
        .await
    });
    let Some(SessionCommand::BufferedStatus { bind, pending, failed }) = session_rx.recv().await
    else {
        panic!("buffer status");
    };
    assert_eq!((bind, pending, failed), (bind_id, 1, 0));
    assert_eq!(retry.await.expect("retry task").status, http::StatusCode::NO_CONTENT);

    state.database.fail_buffered(bind_id, seq, "again").expect("fail again");
    let delete_socket = socket.clone();
    let delete = tokio::spawn(async move {
        request(
            &delete_socket,
            http::Method::DELETE,
            &format!("/v1/webhooks/failed/{bind_id}/{seq}"),
        )
        .await
    });
    assert!(matches!(
        session_rx.recv().await,
        Some(SessionCommand::BufferedStatus { pending: 0, failed: 0, .. })
    ));
    assert_eq!(delete.await.expect("delete task").status, http::StatusCode::NO_CONTENT);

    let missing =
        request(&socket, http::Method::POST, &format!("/v1/webhooks/failed/{bind_id}/999/retry"))
            .await;
    assert_eq!(missing.status, http::StatusCode::NOT_FOUND);
    task.abort();
    let _cancelled = task.await;
}
