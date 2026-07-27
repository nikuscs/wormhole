use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener as StdUnixListener},
    path::PathBuf,
    sync::Arc,
};

use tempfile::tempdir;
use utoipa::OpenApi;

use super::{AdminApi, AdminError, AdminServer, remove_stale_socket};

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
fn committed_openapi_is_current() {
    let json =
        format!("{}\n", serde_json::to_string_pretty(&AdminApi::openapi()).expect("OpenAPI JSON"));
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/admin-api.openapi.json");
    if std::env::var_os("UPDATE_OPENAPI").is_some() {
        fs::write(&path, &json).expect("write OpenAPI snapshot");
    }
    assert_eq!(fs::read_to_string(path).expect("committed OpenAPI"), json);
}

#[tokio::test]
async fn unix_socket_is_private_and_serves_status() {
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
    assert!(state.try_open_session("WH256:test", 1));
    let _stream = state.track_stream();
    let certificates = Arc::new(crate::certs::CertManager::ready(&config).await.expect("certs"));
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
